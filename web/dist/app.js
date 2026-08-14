// Placeholder client for chapi.
//
// It implements the client contract from DESIGN.md and nothing beyond it:
// verify every message, verify before parsing, never re-serialize a header,
// treat an absent payload on a verifying header as authentic, track the newest
// sequence per room and send it on rejoin.
//
// There is no local store here. The real client's job is to keep far more
// history than the server does; that design belongs to the client project.

const state = {
  token: null,
  keyId: null,
  verifyKey: null,
  imageMaxBytes: 0,
  socket: null,
  room: null,
  nick: "anon",
  // Newest known sequence per room, which is what a rejoin resumes from.
  newestSeq: new Map(),
};

const el = (id) => document.getElementById(id);
const encoder = new TextEncoder();

function status(text) {
  el("status").textContent = text;
}

function line(className, text) {
  const li = document.createElement("li");
  li.className = className;
  li.textContent = text;
  el("log").append(li);
  li.scrollIntoView({ block: "nearest" });
  return li;
}

function hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Ed25519 in WebCrypto is recent. Without it this page cannot verify anything,
// and it says so rather than rendering unverified content as if it were real.
async function importVerifyKey(base64Key) {
  try {
    return await crypto.subtle.importKey(
      "raw",
      base64ToBytes(base64Key),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
}

// verifyMessage checks the signature over the raw header bytes, then the
// payload hash. The header is only parsed after its signature holds, which is
// what makes JSON's lack of a canonical form a non-problem.
async function verifyMessage(envelope) {
  if (!state.verifyKey) return { ok: false, reason: "no verifying key" };

  const signature = base64ToBytes(envelope.sig);
  const signed = encoder.encode(envelope.h);
  const ok = await crypto.subtle.verify("Ed25519", state.verifyKey, signature, signed);
  if (!ok) return { ok: false, reason: "bad signature" };

  const header = JSON.parse(envelope.h);
  if (header.keyid !== state.keyId) {
    return { ok: false, reason: `unknown keyid ${header.keyid}` };
  }

  // An image whose payload is gone is an archived record, not a forgery.
  const stripped = header.kind === "image" && envelope.p === "";
  if (!stripped) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(envelope.p));
    if (hex(digest) !== header.hash) return { ok: false, reason: "payload hash mismatch" };
  }
  return { ok: true, header, stripped };
}

function render(header, payload, stripped) {
  const li = document.createElement("li");

  const seq = document.createElement("span");
  seq.className = "seq";
  seq.textContent = `#${header.seq}`;
  li.append(seq);

  const nick = document.createElement("span");
  nick.className = "nick";
  nick.textContent = header.nick;
  li.append(nick);

  if (header.kind === "text") {
    li.append(document.createTextNode(payload));
  } else if (header.kind === "shush") {
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `shushed #${JSON.parse(payload).seq}`;
    li.append(meta);
  } else if (header.kind === "image") {
    if (stripped) {
      const meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = `image no longer held by the server (${header.w}x${header.h})`;
      li.append(meta);
    } else {
      const img = document.createElement("img");
      img.src = `data:${header.mime};base64,${payload}`;
      if (header.w) img.width = header.w;
      if (header.h) img.height = header.h;
      li.append(img);
    }
  }

  el("log").append(li);
  li.scrollIntoView({ block: "nearest" });
}

function noteSeq(room, seq) {
  const current = state.newestSeq.get(room) ?? 0;
  if (seq > current) state.newestSeq.set(room, seq);
}

async function onFrame(raw) {
  let frame;
  try {
    frame = JSON.parse(raw);
  } catch {
    line("unverified", "server sent a frame that is not JSON");
    return;
  }

  // A signed message carries "h"; a control frame carries "t".
  if (frame.h === undefined) {
    switch (frame.t) {
      case "joined":
        status(`in ${frame.room}, newest sequence ${frame.seq}`);
        break;
      case "activity":
        line("meta", `activity in ${frame.room} (sequence ${frame.seq})`);
        break;
      case "gap":
        // Surfaced, never hidden: this is history the server could not serve.
        line("unverified", `gap in ${frame.room}: ${frame.from}-${frame.to}`);
        break;
      case "rooms":
        line("meta", `rooms: ${frame.rooms.join(", ")}`);
        break;
      case "error":
        line("unverified", `server: ${frame.msg}`);
        break;
      default:
        line("meta", `unhandled frame ${frame.t}`);
    }
    return;
  }

  const result = await verifyMessage(frame);
  if (!result.ok) {
    line("unverified", `rejected a message: ${result.reason}`);
    return;
  }
  noteSeq(result.header.room, result.header.seq);
  render(result.header, frame.p, result.stripped);
}

function send(frame) {
  if (state.socket?.readyState !== WebSocket.OPEN) {
    status("not connected");
    return;
  }
  state.socket.send(JSON.stringify(frame));
}

function join(room) {
  state.room = room;
  el("log").replaceChildren();
  send({ t: "join", room, since: state.newestSeq.get(room) ?? 0 });
}

function connect() {
  const url = new URL("/ws", location.href);
  url.protocol = location.protocol === "https:" ? "wss:" : "ws:";

  // The token rides as a second offered subprotocol so it stays out of the URL
  // and out of access logs. The server selects and echoes "chapi.v1".
  const socket = new WebSocket(url, ["chapi.v1", state.token]);
  state.socket = socket;

  socket.addEventListener("open", () => {
    status("connected");
    join(el("room").value.trim() || "general");
  });
  socket.addEventListener("message", (event) => onFrame(event.data));
  socket.addEventListener("close", (event) => {
    // 4001 means this client fell behind. Reconnecting and resuming from the
    // newest known sequence is the intended response, not an error.
    const slow = event.code === 4001;
    status(`disconnected (${event.code}${slow ? ", fell behind" : ""}) ${event.reason}`);
  });
}

el("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.nick = el("nick").value.trim() || "anon";

  const response = await fetch("/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: el("password").value }),
  });
  if (!response.ok) {
    status(`login failed (${response.status})`);
    return;
  }

  const body = await response.json();
  state.token = body.token;
  state.keyId = body.keyid;
  state.imageMaxBytes = body.image_max_bytes;
  state.verifyKey = await importVerifyKey(body.pubkey);

  el("login").hidden = true;
  el("chat").hidden = false;
  if (!state.verifyKey) {
    line("unverified", "this browser cannot verify Ed25519; nothing will be displayed");
  }
  connect();
});

el("room-form").addEventListener("submit", (event) => {
  event.preventDefault();
  join(el("room").value.trim() || "general");
});

el("send-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const body = el("body").value;
  if (!body) return;
  send({ t: "send", nick: state.nick, kind: "text", p: body });
  el("body").value = "";
});
