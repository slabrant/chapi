// Command chapi is the ultralight chat server: one binary, the client assets
// embedded in it, and everything else in environment variables.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/slabrant/chapi/internal/auth"
	"github.com/slabrant/chapi/internal/config"
	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/httpapi"
	"github.com/slabrant/chapi/internal/hub"
	"github.com/slabrant/chapi/internal/store"
	"github.com/slabrant/chapi/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "chapi:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.LoadSecrets(); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	if cfg.GeneratedSigningKey {
		log.Warn("generated a signing key",
			"path", cfg.DataDir+"/signing.key",
			"note", "archived messages verify against this key; keep it with the archive")
	}
	if cfg.GeneratedTokenSecret {
		log.Warn("generated a token secret", "path", cfg.DataDir+"/token.key")
	}

	authenticator, err := auth.New(cfg.Password, cfg.TokenSecret, cfg.TokenEpoch, cfg.TokenTTL)
	if err != nil {
		return err
	}

	priv := ed25519.NewKeyFromSeed(cfg.SigningSeed)
	signer := envelope.NewSigner(cfg.KeyID, priv)
	keys := envelope.SingleKey(cfg.KeyID, signer.Public())

	registry := hub.NewRegistry(hub.Config{
		DataDir: cfg.DataDir,
		Store: store.Config{
			MaxText:       cfg.RingText,
			MaxImageBytes: cfg.RingImageBytes,
			MaxBackfill:   cfg.MaxBackfill,
		},
		ImageMaxBytes:   cfg.ImageMaxBytes,
		MaxTextBytes:    cfg.TextMaxBytes,
		OutboundBuffer:  cfg.OutboundBuffer,
		RoomIdleTimeout: cfg.RoomIdleTimeout,
		SweepInterval:   cfg.SweepInterval,
	}, signer, keys, log)

	hubCtx, stopHub := context.WithCancel(context.Background())
	defer stopHub()
	go registry.Run(hubCtx)

	api := httpapi.New(httpapi.Config{
		AllowedOrigins:   cfg.AllowedOrigins,
		TrustProxyHeader: cfg.TrustProxyHeader,
		PingInterval:     cfg.PingInterval,
		WriteTimeout:     cfg.WriteTimeout,
		LoginBurst:       cfg.LoginBurst,
		LoginWindow:      cfg.LoginWindow,
	}, authenticator, registry, signer, web.FS(), log)

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: api.Handler(),
		// ReadTimeout and WriteTimeout are deliberately unset: they apply to
		// the whole connection, and a websocket is meant to stay open. The
		// per-frame deadlines in the write pump cover what they would have.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr, "data", cfg.DataDir, "keyid", cfg.KeyID)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case sig := <-signals:
		log.Info("shutting down", "signal", sig.String())
	}

	// Stop the hub first: it closes every live connection, which is what lets
	// the hijacked websocket handlers return instead of hanging the shutdown.
	stopHub()
	registry.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return <-serveErr
}

func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
