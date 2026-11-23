# Proton Mail accounts

Status: on `feat/proton`, not yet run against Proton's servers.

Proton keeps mail end-to-end encrypted and offers no IMAP; its own apps talk
to Proton's REST API and decrypt on the device. Flectar Mail does the same,
with Proton's MIT-licensed `proton-crypto` crates on their pure-Rust
OpenPGP backend (no Go toolchain).

## What an account does

A Proton account is `MailProtocol::Proton`, stored as `'proton'`
(migration 069). It is `generic` / `password`: it signs in with the
password, which is never kept.

- **Signing in** (`proton/setup.rs`, `src/proton_sign_in.rs`): address and
  password in the account form, then whatever Proton asks for: its CAPTCHA
  in the browser, the code from an authenticator app, the mailbox password
  of an account with two. An account that only offers a security key is
  told so. Signing in to an address that is here already signs that account
  in again.
- **What is stored** (`proton/stored.rs`): the session tokens and the key
  passphrase, as one value in the credential store. Every refreshed token
  pair is saved before the request that needed it goes on, as Proton's
  refresh tokens work once. For the same reason an account has one session,
  which its workers and everything else share (`sync::Link`).
- **Folders and labels**: Proton's system folders and the account's own
  folders are folders here, with paths made of their names (`" / "`
  between levels, as for JMAP). A message is in exactly one of them, so
  Proton is a single-folder protocol. Proton's labels are account labels
  here, known by their Proton id in `labels.keyword`; a label made here is
  made on Proton when it is first used. The star is Proton's label 10.
- **Mail** (`proton/sync.rs`): the first sync lists all mail within the
  account's history setting, newest first, as metadata. Afterwards the
  account follows `/core/v4/events`, every thirty seconds while it follows
  mail as it arrives. Each changed message is read as it is now instead of
  from the event. Proton's conversations are the threads
  (`threads.proton_id`). A message's body is fetched, decrypted and stored
  as the RFC 5322 message it was when it is opened, and ahead of time as
  the download setting says: messages without attachments, or everything.
- **Actions** (`proton/actions.rs`): read and unread, star, move, archive,
  trash, spam, labels, deleting for good, emptying the Trash, marking a
  folder read, and read receipts, which Proton sends itself.
- **Folders** (`proton/folders.rs`): made, renamed and deleted on Proton.
  Proton keeps a deleted folder's mail, without a folder; it shows with the
  archive.
- **Drafts and sending** (`proton/send.rs`): a draft is saved to Proton with
  its body and attachments encrypted to the sending address's key. Sending
  hands each recipient the session keys: Proton users get them encrypted to
  their key; someone elsewhere who publishes a key gets a PGP/MIME message;
  anyone else gets the keys through Proton in the clear, so their mail
  server can read the message. The account's own mail security (GnuPG,
  S/MIME) can't be combined with this and is refused when sending.
- **Importing and moving mail between accounts**: a whole message goes to
  Proton through its import, with its headers as they are and its content
  as one PGP/MIME part encrypted to the account's key.
- **Searching the server**: Proton finds what it lists about a message
  (sender, recipient, subject, folder, time, unread, starred, attachments)
  and can't look inside one; text inside messages is found in the mail kept
  here.

Proton accounts stay on the device they signed in on: they get no
`sync_id`, so Flectar Mail Sync neither shares them nor takes one from
another device.

## What Proton has no way to do

These are refused in words, as for other accounts whose servers lack them:
automatic replies and server-side rules from Flectar Mail, folder
subscriptions, a second copy of a message in another folder, and asking for
a read receipt, as Proton writes a sent message's headers itself. For the
same reason a sender identity's reply-to address reaches only recipients
who get the message as PGP/MIME.

## The protocol layer

`crates/flectar-mail-core/src/proton/`:

- `api.rs` – the session: app identity header, tokens, one refresh at a
  time on 401, Proton's `Code`/`Error`/`Details` error shape, rate limits,
  forms with file parts.
- `auth.rs` – unauthenticated session, SRP (`/auth/v4/info`, `/auth/v4`)
  with server-proof check, TOTP (`/auth/v4/2fa`), two-password accounts, the
  key passphrase derived from the (mailbox) password and checked against the
  user keys.
- `hv.rs` – Proton's CAPTCHA solved in the user's browser: a loopback server
  frames `/core/v4/captcha` from its own origin, passes Proton's requests
  through without the framing headers, and takes the `pm_captcha` token. It
  only answers its own `Host`, only takes the token from its own `Origin`,
  and stops after one token or ten minutes.
- `keys.rs` – user, salts and addresses; user keys unlocked with the
  passphrase, address keys through the user keys; decrypting and encrypting
  messages and attachments, and handing session keys to recipients.
- `mail.rs` – labels and folders, metadata pages, full messages, attachments,
  read/unread/delete, label/unlabel, the event stream, and rebuilding the
  RFC 5322 message (plain, with attachments as `mixed`/`related`, and
  PGP/MIME) so the existing ingest stores it like any other mail.

## To check against Proton

None of this has talked to Proton yet. The first sign-in with a test
account is the test of, in this order: the app identity header, SRP, the
CAPTCHA page (the fallback, if Proton refuses the framed page, is a small
webview window), TOTP, key unlocking, the first listing, decrypting a
message, the event stream, an action, a draft, a send to a Proton address
and to another, and an import.
