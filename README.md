### `Overview`

- Run it, scan the QR code from a phone or point a browser at the printed URL, enter the PIN, and you have two-way file transfer between every device on that WiFi.

  <img width="777" height="542" alt="Lumenfrontend01" src="https://github.com/user-attachments/assets/95a82c57-7597-47b2-8432-eae60fd8a3f4" />


### `run`

        pip install -r requirements.txt
        python -m lumendrop                      
        python -m lumendrop ~/Shared --no-gui 

        | Option | Default | Purpose |
        |---|---|---|
        | `folder` | `~/LumenDrop` | Folder to share (system/home/hidden config locations are refused) |
        | `--port` | `8420` | 1024–65535 |
        | `--host` | `0.0.0.0` | Bind address (`::` for IPv6) |
        | `--advertise IP` | auto | Address shown in URL/QR (e.g. the hotspot interface) |
        | `--hostname NAME` | – | Extra Host header to accept (repeatable), e.g. a local DNS name |
        | `--pin-length N` | `8` | 6–12 digits |
        | `--no-https` | off | Plain HTTP (not recommended) |
        | `--data-dir DIR` | perOS app dir | Private state: DB, TLS key, logs, thumbnails |
        | `--allow-root` | off | Permit running elevated |

- Tests: `pip install pytest httpx && pytest`.

### `Offline operation`

- Network discovery enumerates interfaces directly (psutil + routing probes that send no packets), so it works on a hotspot, ad-hoc Wi-Fi or a direct cable with link-local `169.254.x.x` addresses. Virtual adapters (Docker, VirtualBox, WSL…) are ranked last.

- All assets are served locally; no CDN, fonts or external calls.

- Single shared folder, single server process. This isn't built for scale. It's built for a room full of devices on the same WiFi.
  
- The browser client pauses uploads when the link drops, probes the server with backoff, and resumes from the last confirmed chunk.
  
- Interrupted uploads also survive page reloads and server restarts (24 h).

### `Security model`

- Self-signed ECDSA P-256 certificate covering every local address; TLS ≥ 1.2 with AEAD ciphers only. Verify the fingerprint shown in the panel on first connect.
  
- 8-digit PIN (≈26.6 bits) with per client lockout (5/15 min, persisted), HMAC-signed login nonce, and a global failure budget: distributed guessing (many IPs / IPv6 /64 rotation) auto rotates the PIN and pauses unknown clients.
  
- Server-side, revocable, 256-bit tokens (stored hashed), idle + absolute expiry, bound to the User Agent, `HttpOnly` + `SameSite=Strict` + `__Host-` prefix over HTTPS.
  
- Synchronizer token on every state change, strict `Origin`/`Referer` matching, and a Fetch Metadata resource isolation policy.
  
- Host header allow-list of local addresses and names.
  
- No HTML built from user data without escaping; client renders with `textContent` only; per response CSP nonce, `require trusted types-for 'script'`; shared files are served as sandboxed attachments with `nosniff`, raster images inline only after magic-byte verification.
  
- Unicode-safe name sanitisation (reserved Windows names, bidi overrides, traversal), atomic exclusive create (no overwrite/symlink following), staged uploads with exact chunk-size enforcement, optional per chunk SHA-256, whole-file SHA-256, free space reservation, per-session/global upload quotas.
  
- Context-aware signals (raw-path traversal and encoding evasion, scanner paths only on 404, injection grammars only on non free text parameters, scanner user agents, JNDI lookups, cross site writes) are combined as log likelihood evidence with exponential decay (half-life 180 s). 

- A client is blocked when the posterior probability of hostility exceeds 0.985; signed in and reputable clients (Beta-posterior reputation) get a lower prior, which keeps false positives down. Blocks escalate 30 min → 2 h → 24 h and are forgiven after 7 days.

- Token-bucket rate limits (separate anonymous/signed in buckets), header (16 KB), URL, and per-route body limits enforced while streaming.

- Clients only ever see generic localized messages plus a short reference ID; logs redact the PIN and tokens, neutralise CR/LF and control characters, and live in a `0700` directory.

- Warns/refuses when elevated; refuses to share filesystem roots, the home folder or its ancestors, system directories, hidden config folders, and LumenDrop's own data directory.
