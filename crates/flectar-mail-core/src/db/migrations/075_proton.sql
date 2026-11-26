-- Proton Mail accounts talk to Proton's own API, so 'proton' joins the mail
-- protocols. Its folders, labels and messages are known by Proton's ids.

CREATE TABLE accounts_new (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE,
  display_name TEXT,
  provider TEXT CHECK (provider IN ('generic', 'gmail', 'microsoft')),
  auth_kind TEXT CHECK (auth_kind IN ('password', 'oauth2')),
  mail_protocol TEXT NOT NULL
    CHECK (mail_protocol IN ('gmail', 'imap', 'jmap', 'pop3', 'local', 'proton')),
  username TEXT,
  jmap_url TEXT NOT NULL DEFAULT '',
  jmap_account_id TEXT,
  incoming_host TEXT,
  incoming_port INTEGER CHECK (incoming_port BETWEEN 0 AND 65535),
  smtp_host TEXT,
  smtp_port INTEGER CHECK (smtp_port BETWEEN 0 AND 65535),
  sync_state TEXT NOT NULL DEFAULT 'idle',
  sync_error TEXT,
  created_at INTEGER NOT NULL,
  settings_json TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  avatar_url TEXT,
  can_create_top_level_mailbox INTEGER NOT NULL DEFAULT 1
    CHECK (can_create_top_level_mailbox IN (0, 1)),
  caught_up_at INTEGER,
  sync_retry_at INTEGER,
  sync_id TEXT
    CHECK (sync_id IS NULL OR (length(sync_id) = 32 AND sync_id NOT GLOB '*[^0-9a-f]*')),
  jmap_max_delayed_send INTEGER NOT NULL DEFAULT 0
    CHECK (jmap_max_delayed_send >= 0),
  name TEXT CHECK (name IS NULL OR length(name) > 0),
  CHECK ((provider = 'gmail') = (mail_protocol = 'gmail')),
  CHECK (provider <> 'microsoft' OR mail_protocol = 'imap'),
  CHECK (mail_protocol NOT IN ('jmap', 'pop3', 'proton') OR provider = 'generic'),
  -- Proton signs in with the password and then keeps session tokens.
  CHECK (mail_protocol <> 'proton' OR auth_kind = 'password'),
  CHECK (mail_protocol <> 'proton' OR sync_id IS NULL),
  CHECK ((mail_protocol = 'local') = (email IS NULL)),
  CHECK ((mail_protocol = 'local') = (provider IS NULL)),
  CHECK ((mail_protocol = 'local') = (auth_kind IS NULL)),
  CHECK ((mail_protocol = 'local') = (username IS NULL)),
  CHECK ((mail_protocol = 'local') = (incoming_host IS NULL)),
  CHECK ((mail_protocol = 'local') = (incoming_port IS NULL)),
  CHECK ((mail_protocol = 'local') = (smtp_host IS NULL)),
  CHECK ((mail_protocol = 'local') = (smtp_port IS NULL)),
  CHECK ((mail_protocol = 'local') = (settings_json IS NULL))
);

INSERT INTO accounts_new (
  id, email, display_name, provider, auth_kind, mail_protocol, username,
  jmap_url, jmap_account_id, incoming_host, incoming_port, smtp_host,
  smtp_port, sync_state, sync_error, created_at, settings_json, sort_order,
  avatar_url, can_create_top_level_mailbox, caught_up_at, sync_retry_at,
  sync_id, jmap_max_delayed_send, name
)
SELECT
  id, email, display_name, provider, auth_kind, mail_protocol, username,
  jmap_url, jmap_account_id, incoming_host, incoming_port, smtp_host,
  smtp_port, sync_state, sync_error, created_at, settings_json, sort_order,
  avatar_url, can_create_top_level_mailbox, caught_up_at, sync_retry_at,
  sync_id, jmap_max_delayed_send, name
FROM accounts;

-- Renaming the new table re-checks every view, and one reading the dropped
-- table would fail that check, so the view over accounts is recreated.
DROP VIEW directory_accounts;
DROP TABLE accounts;
ALTER TABLE accounts_new RENAME TO accounts;

-- The indexes, triggers and view as they were, but for which accounts get a
-- sync id.
CREATE INDEX idx_accounts_sort_order ON accounts(sort_order, id);
CREATE UNIQUE INDEX idx_accounts_one_local ON accounts(mail_protocol)
  WHERE mail_protocol = 'local';
CREATE UNIQUE INDEX idx_accounts_sync_id ON accounts(sync_id) WHERE sync_id IS NOT NULL;

CREATE TRIGGER contact_learning_account_created
AFTER INSERT ON accounts
BEGIN
  INSERT INTO contact_learning_state (account_id, outgoing_since, incoming_since)
  VALUES (
    NEW.id,
    0,
    CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
  );
END;

-- A Proton account gets no sync id, so it stays on this device: its session
-- and keys are not shared, and another device may run a version without
-- Proton accounts.
CREATE TRIGGER accounts_sync_id
AFTER INSERT ON accounts
WHEN NEW.sync_id IS NULL AND NEW.mail_protocol NOT IN ('local', 'proton')
BEGIN
  UPDATE accounts SET sync_id = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;

CREATE VIEW directory_accounts AS
SELECT o.entry_id AS contact_id, b.account_id
FROM carddav_objects o JOIN carddav_addressbooks b ON b.id = o.addressbook_id
WHERE o.entry_id IS NOT NULL
UNION ALL
SELECT e.id, a.id FROM contact_entries e CROSS JOIN accounts a
WHERE a.mail_protocol <> 'local'
  AND NOT EXISTS (SELECT 1 FROM carddav_objects o WHERE o.entry_id = e.id)
UNION ALL
SELECT -contact_id, account_id FROM contact_accounts;

ALTER TABLE folders ADD COLUMN proton_id TEXT;
CREATE UNIQUE INDEX idx_folders_proton_id
  ON folders(account_id, proton_id) WHERE proton_id IS NOT NULL;

ALTER TABLE messages ADD COLUMN proton_id TEXT;
CREATE UNIQUE INDEX idx_messages_proton_id
  ON messages(account_id, proton_id) WHERE proton_id IS NOT NULL;

-- Proton's conversations are the threads.
ALTER TABLE threads ADD COLUMN proton_id TEXT;
CREATE UNIQUE INDEX idx_threads_proton_id
  ON threads(account_id, proton_id) WHERE proton_id IS NOT NULL;

-- Where the account is in Proton's stream of changes. Without an event id
-- the mail is listed in full; `pending_event_id` is where the stream stood
-- when that listing began, kept once it is through.
CREATE TABLE proton_sync_state (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  event_id TEXT,
  pending_event_id TEXT
);
