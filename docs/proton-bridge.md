# Proton Mail via a managed Bridge

An alternative to the direct Proton API integration (see `proton.md`). Instead
of talking to Proton's servers ourselves — which requires impersonating a Proton
app, because Proton grants no app identifier to third-party mail clients and its
anti-abuse system locks accounts that sign in under a borrowed identity — Flectar
bundles Proton's own Bridge core and manages it internally. The person installs
only Flectar; Flectar starts Bridge headless, signs the account in through it,
and connects to the local IMAP/SMTP servers Bridge exposes. The sign-in is
genuinely Proton's Bridge authenticating, so no identity is faked.

Trade-offs: Bridge is a paid-plan feature, so free accounts are rejected
(`Error::FreeAccount`). Proton's labels arrive as IMAP folders rather than native
labels. The bundled core is a separate Go process (a few hundred MB of RAM).

## How Flectar drives Bridge

Flectar plays the exact role Bridge's own GUI plays, over Bridge's frontend gRPC
contract (vendored from upstream as `crates/flectar-proton-bridge/proto/bridge.proto`).

- **Spawn.** `bridge(.exe) --grpc --no-window --parent-pid <flectar_pid>
  --log-level <level> --launcher <bundled-core>`, with `APPDATA` /
  `XDG_CONFIG_HOME` pointed at a Flectar-owned directory so the core's whole
  state (vault, handshake) is contained and findable. The core self-terminates
  when `--parent-pid` dies, so no orphan survives Flectar.
- **Handshake.** The core writes `grpcServerConfig.json` under its settings
  directory (`<config-home>/protonmail/bridge-v3/` by default) with the gRPC
  TCP port (Windows), a self-signed TLS certificate (CN/SAN `127.0.0.1`) and a
  server token. Flectar finds the file by name, connects over TLS trusting that
  certificate, and sends the token as `server-token` metadata on every call.
- **Sign-in.** `RunEventStream` → `GuiReady` → `Login`, then the `LoginEvent`
  stream is driven: `tfaRequested` → `Login2FA`, `twoPasswordRequested` →
  `Login2Passwords`, `hvRequested` → open the URL (Bridge captures the solved
  token itself) then `Login` again with `useHvDetails=true`, `error` with
  `FREE_USER` → a clear paid-plan message, `finished` → done. Security-key 2FA
  is reported as unsupported.
- **Readout.** `GetUser` → the per-account Bridge password and addresses;
  `MailServerSettings` → IMAP/SMTP ports and TLS flags; `ExportTLSCertificates`
  → the certificate Flectar imports for the local account.

## Build plan

1. **`crates/flectar-proton-bridge`** — the process manager, gRPC client and
   sign-in driver, tested end to end against a mock Bridge over TLS. (done)
2. Wire the managed-Bridge path into account setup and the sign-in UI, then
   create a local IMAP/SMTP account at `127.0.0.1` with the exported certificate
   trusted and the Bridge password in the credential store.
3. Bundle Proton's Bridge core binary (Windows x64, arm64 via emulation) in the
   `Native platform artifacts` workflow; Flectar launches it from its install dir.

The vendored `bridge.proto` is GPL-3.0-or-later (Proton Mail Bridge); it is
compatible with Flectar's AGPL-3.0. Re-vendor it whenever the bundled Bridge is
updated.
