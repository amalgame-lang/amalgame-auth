# amalgame-auth

HTTP authentication primitives for the Amalgame / Mosaic stack — usable
**outside** the web framework. A lean L7 server (e.g. WebDAV) can require
auth without pulling all of `amalgame-web`.

```amalgame
import Amalgame.Auth

let creds = new Credentials()
    .AddPassword("alice", "…")     // hashed with scrypt (amalgame-crypto)
    .Add("bob", bobScryptHash)      // or a precomputed hash (config / KeePass)

let auth = BasicAuth.ForCredentials("Family NAS", creds)

// middleware mode — null = ok, else a ready 401:
let denied = auth.Reject(req)
if (denied != null) { return denied }

// identity mode — who is it? ("" if not authenticated):
let user = auth.Authenticate(req)
```

## What's here

- **`BasicAuth`** — RFC 7617 HTTP Basic as a pure `HttpRequest ->
  HttpResponse` middleware:
  - `Reject(req)` → `null` if authenticated, else a `401` carrying
    `WWW-Authenticate: Basic realm="…"` (so browsers/clients prompt).
  - `Authenticate(req)` → the verified username, or `""`.
  - `User(req)` → the username carried by the request (parse only).
  - `Challenge()` → a bare `401`.
  - `.WithAllowPrivate()` → loopback / RFC1918 / ULA source addresses
    pass **without** credentials (trusted-LAN convenience); off by
    default. `BasicAuth.IsPrivateAddr(addr)` is the classifier.
- **`Credentials`** — a multi-user store: `Add(name, scryptHash)`,
  `AddPassword(name, plaintext)` (hashes for you), `Verify(name, pwd)`
  (constant-time scrypt via `amalgame-crypto`).
- **`BasicAuth.EncodeBase64Std` / `DecodeBase64Std`** — standard base64
  for building / parsing `Authorization` headers.

## Security

- **Deploy behind TLS.** Basic sends the password base64-encoded, *not*
  encrypted — terminate HTTPS at the host. base64 is reversible.
- Passwords are stored only as **scrypt** hashes; `Verify` is
  constant-time (amalgame-crypto's `Password`).
- Fail-closed: no credential store, no/invalid credentials → rejected.
- The realm string is sanitized (no quote/CTL injection into the header).

## Dependencies

- `amalgame-net-http` — `HttpRequest` / `HttpResponse`
- `amalgame-crypto`   — scrypt `Password` + `Bytes` base64

## Build & test

```bash
./tests/run_tests.sh        # 15 checks: credentials, Basic, LAN bypass, base64
```

Resolves sibling checkouts of `amalgame-net-http`, `amalgame-tls`,
`amalgame-async`, `amalgame-datetime`, `amalgame-crypto` (or `$AMALGAME_*`
overrides). Tests run against synthetic requests — no socket.

## License

Apache-2.0.
