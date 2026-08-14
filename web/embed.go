// Package web carries the client assets the binary serves.
//
// The client is a separate project. What lives here is a placeholder: enough
// of a page to exercise the embed path, the response headers and a same-origin
// wss: connection by hand. When the real client exists, its build output
// replaces dist/ and nothing in the server changes.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var files embed.FS

// FS returns the embedded client assets rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		// dist is embedded at compile time; it cannot be missing at runtime.
		panic("web: embedded assets missing: " + err.Error())
	}
	return sub
}
