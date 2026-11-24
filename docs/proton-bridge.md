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
2. **`crates/flectar-mail-core/src/proton/bridge.rs`** — the managed-Bridge path
   behind the existing `Core::proton_sign_in*` methods (the UI is unchanged; the
   direct-API sign-in is preserved as `proton_direct_*`). A background task runs
   the callback-based Bridge sign-in and exchanges prompts/answers with the
   step-by-step UI over channels; on success it creates an ordinary local
   IMAP/SMTP account via `add_account_password` and records the account so the
   core is restarted at the next launch (`start_accounts_now` → `proton_bridge_boot`).
   (done)
3. **CI bundling** — the `Native platform artifacts` Windows job downloads Proton
   Mail Bridge (pinned **v3.27.2**, checksum-verified), installs it silently, and
   copies it into `proton-bridge/` beside `flectar-mail.exe`. Flectar launches
   `proton-bridge/proton-bridge.exe`. (done; needs a CI run to confirm the
   installed layout on the runner)

The vendored `bridge.proto` is GPL-3.0-or-later (Proton Mail Bridge); its content
is identical on `main` and the pinned **v3.27.2** release, so the client matches
the bundled core. Re-vendor and re-pin together whenever the bundled Bridge is
updated. Bundling Proton's GPL-3.0 Bridge is compatible with Flectar's AGPL-3.0;
the copied folder carries Bridge's own licence.

## Not yet verified end to end

Signing in requires a paid Proton account, the bundled core, and Windows, none of
which can run in the build environment. The orchestration is unit-tested and the
whole workspace compiles; the acceptance test is a Windows build where a paid
account signs in and syncs.
