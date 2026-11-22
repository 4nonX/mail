# Proton Mail accounts

Status: in progress on `feat/proton`.

Proton keeps mail end-to-end encrypted and offers no IMAP; its own apps talk
to Proton's REST API and decrypt on the device. Flectar Mail does the same,
with Proton's MIT-licensed `proton-crypto` crates on their pure-Rust
OpenPGP backend (no Go toolchain).

## Done

`crates/flectar-mail-core/src/proton/`:

- `api.rs` – the session: app identity header, tokens, one refresh on 401,
  Proton's `Code`/`Error`/`Details` error shape, human-verification details.
- `auth.rs` – unauthenticated session, SRP (`/auth/v4/info`, `/auth/v4`)
  with server-proof check, TOTP (`/auth/v4/2fa`), two-password accounts, the
  key passphrase derived from the (mailbox) password and checked against the
  user keys. The password itself is never stored.
- `hv.rs` – Proton's CAPTCHA solved in the user's browser: a loopback server
  frames `/core/v4/captcha` from its own origin, passes Proton's requests
  through without the framing headers, and takes the `pm_captcha` token. It
  only answers its own `Host`, only takes the token from its own `Origin`,
  and stops after one token or ten minutes.
- `keys.rs` – user, salts and addresses; user keys unlocked with the
  passphrase, address keys through the user keys; message and attachment
  decryption behind a `Decrypter` trait object.
- `mail.rs` – labels and folders, metadata pages, full messages, attachments,
  read/unread/delete, label/unlabel, the event stream, and rebuilding the
  RFC 5322 message (plain, with attachments as `mixed`/`related`, and
  PGP/MIME) so the existing ingest stores it like any other mail.

## Next

1. `MailProtocol::Proton` and a migration adding `'proton'` to the
   `accounts.mail_protocol` check (as 023 did for `'local'`), plus
   `proton_id` columns for messages and folders.
2. Credentials: tokens and key passphrase in the credential store.
3. Account setup: username, password, CAPTCHA in the browser, TOTP, mailbox
   password.
4. Sync actor (modelled on `jmap/sync.rs`): labels to folders, metadata
   backfill per label, bodies on demand through `fetch_rfc822`, events for
   changes.
5. Actions: read/unread, star (label 10), move, archive, trash, labels.
6. Sending: drafts and `/mail/v4/messages/{id}` send packages.
