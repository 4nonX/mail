//! A Proton account's synchronization worker.
//!
//! Proton's folders and labels become folders and labels here, the messages
//! are listed as metadata and their bodies fetched, decrypted and stored when
//! they are read. After the first full listing the account follows Proton's
//! event stream.

use super::api::Session;
use super::keys::{self, Address, Decrypter};
use super::mail::{self, Label, Metadata, system};
use super::stored::{self, StoredSession};
use crate::db::repo;
use crate::db::repo::messages::NewMessage;
use crate::error::{CoreError, Result};
use crate::events::CoreEvent;
use crate::models::{
    AccountConfig, AccountSettings, MailProtocol, ServerSearchCursor, now_ms, roles,
};
use crate::sync::engine::{
    PauseEnd, PriorityFetchCmd, SERVER_SEARCH_PAGES, ServerHits, SyncCmd, SyncCtx, caught_up,
    check_interval, note_limit, set_state, set_state_error, wait_for_turn, wait_out_pause,
};
use crate::sync::pacing;
use rusqlite::{OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

/// How often the event stream is asked for changes while the account follows
/// its mail as it arrives. Proton's own apps ask every thirty seconds.
const EVENT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_MESSAGE_BYTES: usize = 128 * 1024 * 1024;
/// Rounds of the event stream one sync follows before it gives way.
const MAX_EVENT_ROUNDS: usize = 1_000;

pub(crate) fn spawn(
    ctx: SyncCtx,
    config: AccountConfig,
    commands: mpsc::Receiver<SyncCmd>,
    reads: mpsc::Receiver<PriorityFetchCmd>,
    settings: watch::Receiver<AccountSettings>,
) -> Vec<JoinHandle<()>> {
    debug_assert_eq!(config.mail_protocol, MailProtocol::Proton);
    let link = Link::for_account(&ctx, config.id);
    vec![
        crate::net::timeouts::spawn(actor(
            ctx.clone(),
            config.clone(),
            link.clone(),
            commands,
            settings,
        )),
        crate::net::timeouts::spawn(body_actor(ctx, config, link, reads)),
    ]
}

/// A signed-in session with the account's keys unlocked.
pub(crate) struct Connected {
    pub session: Session,
    pub keys: Arc<dyn Decrypter>,
    pub addresses: Vec<Address>,
}

/// The one session the account's workers share. Proton's refresh tokens
/// work once, so two sessions of one account would sign each other out.
#[derive(Clone)]
pub(crate) struct Link {
    ctx: SyncCtx,
    account_id: i64,
    connected: Arc<Mutex<Option<Arc<Connected>>>>,
}

/// The links of the accounts in use, by profile and account.
static LINKS: std::sync::OnceLock<std::sync::Mutex<HashMap<(usize, i64), Link>>> =
    std::sync::OnceLock::new();

impl Link {
    /// The account's one link, whoever asks for it: its workers, or
    /// something the user does to the account outside a sync.
    pub(crate) fn for_account(ctx: &SyncCtx, account_id: i64) -> Self {
        let key = (Arc::as_ptr(&ctx.paths) as usize, account_id);
        LINKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert_with(|| Self {
                ctx: ctx.clone(),
                account_id,
                connected: Arc::new(Mutex::new(None)),
            })
            .clone()
    }

    /// Drops the account's link for good, when the account is removed.
    pub(crate) fn forget(ctx: &SyncCtx, account_id: i64) {
        let key = (Arc::as_ptr(&ctx.paths) as usize, account_id);
        if let Some(links) = LINKS.get() {
            links.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
        }
    }

    /// The session, signed in from the stored tokens when there is none yet.
    pub(crate) async fn get(&self, owner: crate::net::proxy::Owner) -> Result<Arc<Connected>> {
        let mut connected = self.connected.lock().await;
        if let Some(connected) = connected.as_ref() {
            return Ok(connected.clone());
        }
        let stored = stored::load(self.ctx.credentials.clone(), self.account_id).await?;
        let session = Session::new(owner, Some(stored.tokens.clone()));
        let credentials = self.ctx.credentials.clone();
        let account_id = self.account_id;
        let key_passphrase = stored.key_passphrase.clone();
        session.keep_tokens_with(Arc::new(move |tokens| {
            let credentials = credentials.clone();
            let refreshed = StoredSession::new(tokens, key_passphrase.clone());
            Box::pin(async move { stored::store(credentials, account_id, &refreshed).await })
        }));
        let user = keys::fetch_user(&session).await?;
        let addresses = keys::fetch_addresses(&session).await?;
        let unlocked = keys::unlock(&user, &addresses, &stored.key_passphrase)
            .map_err(|_| CoreError::NeedsReauth)?;
        let fresh = Arc::new(Connected {
            session,
            keys: unlocked,
            addresses,
        });
        *connected = Some(fresh.clone());
        Ok(fresh)
    }

    /// Forget the session after a failure, so the next use signs in again
    /// from what is stored.
    pub(crate) async fn reset(&self) {
        *self.connected.lock().await = None;
    }
}

fn owner(config: &AccountConfig) -> crate::net::proxy::Owner {
    config.proxy_owner()
}

async fn actor(
    ctx: SyncCtx,
    mut config: AccountConfig,
    link: Link,
    mut rx: mpsc::Receiver<SyncCmd>,
    mut settings: watch::Receiver<AccountSettings>,
) {
    let mut waiters = Vec::new();
    let mut backoff = pacing::Backoff::default();
    // Mail that came in before this worker started is caught up on silently.
    let live_since = crate::sync::ingest::live_since(now_ms());
    let mut first = true;
    if !wait_for_turn(&ctx, config.id, &mut rx, &mut waiters).await {
        return;
    }
    loop {
        if wait_out_pause(&ctx, config.id, &mut rx, &mut waiters).await == PauseEnd::Shutdown {
            return;
        }
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                SyncCmd::Shutdown => return,
                SyncCmd::SyncNow {
                    complete: Some(done),
                } => waiters.push(done),
                _ => {}
            }
        }
        if settings.has_changed().unwrap_or(false) {
            config.settings = settings.borrow_and_update().clone();
        }
        let labels_first = first;
        let outcome = async {
            let connected = link.get(owner(&config)).await?;
            let started = now_ms();
            set_state(&ctx, config.id, "syncing").await;
            if labels_first {
                sync_labels(&ctx, config.id, &connected).await?;
                sync_identities(&ctx, &config, &connected).await?;
            }
            sync_messages(&ctx, &config, &connected, live_since).await?;
            caught_up(&ctx, config.id, started).await;
            crate::sync::engine::settle_waiting_rules(&ctx, config.id).await;
            super::actions::execute(&ctx, &config, &connected).await?;
            Ok::<(), CoreError>(())
        }
        .await;
        let interval = check_interval(&ctx.db, &config.settings).await;
        let delay = match outcome {
            Ok(()) => {
                first = false;
                backoff.reset();
                ctx.pace.account(config.id).reached();
                set_state(&ctx, config.id, "idle").await;
                ctx.bus.emit(CoreEvent::NetworkState { online: true });
                finish_waiters(&mut waiters, Ok(()));
                // Following mail as it arrives means asking the event
                // stream often; otherwise the account's interval decides.
                if pacing::push(&config.settings) {
                    Some(interval.map_or(EVENT_INTERVAL, |interval| interval.min(EVENT_INTERVAL)))
                } else {
                    interval.map(pacing::varied)
                }
            }
            Err(error @ (CoreError::Auth(_) | CoreError::NeedsReauth)) => {
                link.reset().await;
                set_state(&ctx, config.id, "needs_reauth").await;
                finish_waiters(&mut waiters, Err(error.to_string()));
                interval.map(pacing::varied)
            }
            Err(error @ CoreError::RateLimited { .. }) => {
                tracing::warn!(account_id = config.id, %error, "Proton asked to wait");
                note_limit(&ctx, config.id, &error);
                continue;
            }
            Err(error) => {
                link.reset().await;
                first = true;
                let message = error.to_string();
                set_state_error(&ctx, config.id, "offline", &message).await;
                ctx.bus.emit(CoreEvent::NetworkState { online: false });
                finish_waiters(&mut waiters, Err(message));
                let retry = backoff.after(&error).duration;
                Some(interval.map_or(retry, |interval| interval.min(retry)))
            }
        };
        let deadline = tokio::time::sleep(delay.unwrap_or(std::time::Duration::MAX));
        tokio::pin!(deadline);
        // Messages download ahead while nothing else needs the worker, one
        // at a time, giving way as soon as something does.
        let mut downloading = !first;
        let mut failed = HashSet::new();
        loop {
            let wake = next_wake(&mut rx, &mut settings, &mut waiters, deadline.as_mut());
            let wake = if downloading {
                match futures::FutureExt::now_or_never(wake) {
                    Some(wake) => wake,
                    None => {
                        downloading = download_next(&ctx, &config, &link, &mut failed).await;
                        continue;
                    }
                }
            } else {
                wake.await
            };
            match wake {
                Wake::Shutdown => return,
                Wake::Sync => break,
            }
        }
    }
}

enum Wake {
    Shutdown,
    Sync,
}

async fn next_wake(
    rx: &mut mpsc::Receiver<SyncCmd>,
    settings: &mut watch::Receiver<AccountSettings>,
    waiters: &mut Vec<oneshot::Sender<std::result::Result<(), String>>>,
    deadline: std::pin::Pin<&mut tokio::time::Sleep>,
) -> Wake {
    tokio::select! {
        command = rx.recv() => match command {
            None | Some(SyncCmd::Shutdown) => Wake::Shutdown,
            Some(SyncCmd::SyncNow { complete: Some(done) }) => {
                waiters.push(done);
                Wake::Sync
            }
            Some(_) => Wake::Sync,
        },
        _ = settings.changed() => Wake::Sync,
        _ = deadline => Wake::Sync,
    }
}

/// A message with attachments downloads ahead only when the account keeps
/// everything, as Proton hands a message over with its attachments.
const AHEAD_WITHOUT_ATTACHMENTS: i64 = 1024 * 1024;

/// Downloads the newest message within the account's history that isn't
/// here yet and that its download setting covers. Returns whether there may
/// be more.
async fn download_next(
    ctx: &SyncCtx,
    config: &AccountConfig,
    link: &Link,
    failed: &mut HashSet<i64>,
) -> bool {
    use crate::models::DownloadPolicy;
    let largest = match config.settings.download {
        DownloadPolicy::Headers => return false,
        DownloadPolicy::Messages => AHEAD_WITHOUT_ATTACHMENTS,
        DownloadPolicy::Everything => DownloadPolicy::LARGEST_ATTACHMENT,
    };
    let everything = config.settings.download == DownloadPolicy::Everything;
    let account_id = config.id;
    let since = config.settings.mail_history.cutoff_ms_at(now_ms());
    let skip = serde_json::to_string(&failed.iter().collect::<Vec<_>>()).unwrap_or_default();
    let next = ctx
        .db
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT id FROM messages
                     WHERE account_id = ?1 AND proton_id IS NOT NULL AND body_state = 'none'
                       AND is_draft = 0
                       AND (?2 IS NULL OR date >= ?2)
                       AND COALESCE(size, 0) <= ?3
                       AND (?4 OR has_attachments = 0)
                       AND id NOT IN (SELECT value FROM json_each(?5))
                     ORDER BY date DESC LIMIT 1",
                    params![account_id, since, largest, everything, skip],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?)
        })
        .await;
    let Ok(Some(message_id)) = next else {
        return false;
    };
    match fetch_body(ctx, config, link, message_id).await {
        Ok(()) => true,
        Err(
            error @ (CoreError::Auth(_) | CoreError::NeedsReauth | CoreError::RateLimited { .. }),
        ) => {
            tracing::warn!(account_id, %error, "Proton downloads wait for the next sync");
            false
        }
        Err(error) => {
            tracing::warn!(account_id, message_id, %error, "a Proton message did not download");
            failed.insert(message_id);
            // A connection that is down fails them all alike.
            !matches!(error, CoreError::Offline)
        }
    }
}

fn finish_waiters(
    waiters: &mut Vec<oneshot::Sender<std::result::Result<(), String>>>,
    result: std::result::Result<(), String>,
) {
    for waiter in waiters.drain(..) {
        let _ = waiter.send(result.clone());
    }
}

/// The account's addresses it may send from become its sender identities.
async fn sync_identities(ctx: &SyncCtx, config: &AccountConfig, c: &Connected) -> Result<()> {
    let identities = sender_identities(config, &c.addresses);
    let account_id = config.id;
    ctx.db
        .write(move |conn| repo::sender_identities::replace(conn, account_id, &identities))
        .await?;
    Ok(())
}

pub(crate) fn sender_identities(
    config: &AccountConfig,
    addresses: &[Address],
) -> Vec<crate::models::SenderIdentity> {
    let mut usable = addresses
        .iter()
        .filter(|address| address.status == 1 && address.send == 1)
        .collect::<Vec<_>>();
    usable.sort_by_key(|address| address.order);
    let mut identities = usable
        .iter()
        .enumerate()
        .map(|(index, address)| {
            let mut identity = crate::sender_identities::primary_identity(config);
            identity.email = address.email.clone();
            identity.display_name = (!address.display_name.is_empty())
                .then(|| address.display_name.clone())
                .or_else(|| config.display_name.clone());
            identity.is_primary = index == 0;
            identity.is_provider_default = index == 0;
            identity
        })
        .collect::<Vec<_>>();
    if identities.is_empty() {
        identities.push(crate::sender_identities::primary_identity(config));
    }
    identities
}

/// The system folders an account always has, as (Proton id, name, role).
const SYSTEM_FOLDERS: [(&str, &str, &str); 6] = [
    (system::INBOX, "Inbox", roles::INBOX),
    (system::DRAFTS, "Drafts", roles::DRAFTS),
    (system::SENT, "Sent", roles::SENT),
    (system::ARCHIVE, "Archive", roles::ARCHIVE),
    (system::SPAM, "Spam", roles::SPAM),
    (system::TRASH, "Trash", roles::TRASH),
];

/// The path of a folder from its own and its parents' names.
fn folder_path(id: &str, folders: &HashMap<&str, &Label>) -> String {
    let mut parts = Vec::new();
    let mut visited = HashSet::new();
    let mut current = Some(id);
    while let Some(id) = current {
        if !visited.insert(id) {
            break;
        }
        let Some(label) = folders.get(id) else { break };
        parts.push(label.name.as_str());
        current = label
            .parent_id
            .as_deref()
            .filter(|parent| !parent.is_empty());
    }
    parts.reverse();
    parts.join(" / ")
}

/// Stores a folder under its Proton id and returns its id here. A folder of
/// the same path that has no Proton id yet becomes this one.
pub(crate) fn upsert_folder(
    conn: &rusqlite::Connection,
    account_id: i64,
    proton_id: &str,
    path: &str,
    role: Option<&str>,
    custom: bool,
) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM folders WHERE account_id = ?1 AND proton_id = ?2",
            params![account_id, proton_id],
            |row| row.get(0),
        )
        .optional()?;
    let holder: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT id, proton_id FROM folders WHERE account_id = ?1 AND path = ?2",
            params![account_id, path],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let id = match (existing, holder) {
        (Some(id), Some((holder, _))) if holder == id => id,
        (Some(id), holder) => {
            // Another folder has the path: it moves out of the way, and is
            // sorted out when its own turn comes or it is found gone.
            if let Some((holder, _)) = holder {
                conn.execute(
                    "UPDATE folders SET path = path || ' [' || id || ']' WHERE id = ?1",
                    params![holder],
                )?;
            }
            conn.execute(
                "UPDATE folders SET path = ?2 WHERE id = ?1",
                params![id, path],
            )?;
            id
        }
        (None, Some((holder, None))) => {
            conn.execute(
                "UPDATE folders SET proton_id = ?2 WHERE id = ?1",
                params![holder, proton_id],
            )?;
            holder
        }
        (None, Some((holder, Some(_)))) => {
            conn.execute(
                "UPDATE folders SET path = path || ' [' || id || ']' WHERE id = ?1",
                params![holder],
            )?;
            insert_folder(conn, account_id, proton_id, path)?
        }
        (None, None) => insert_folder(conn, account_id, proton_id, path)?,
    };
    conn.execute(
        "UPDATE folders
         SET role = ?2, selectable = 1, missing_on_server = 0,
             can_create_children = ?3, can_rename = ?3, can_delete = ?3
         WHERE id = ?1",
        params![id, role, custom],
    )?;
    Ok(id)
}

fn insert_folder(
    conn: &rusqlite::Connection,
    account_id: i64,
    proton_id: &str,
    path: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO folders (account_id, path, delimiter, proton_id, backfill_done)
         VALUES (?1, ?2, '/', ?3, 0)",
        params![account_id, path, proton_id],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Stores Proton's label as an account label here, known by its Proton id.
/// A label made here under the same name becomes this one.
pub(crate) fn upsert_label(
    conn: &rusqlite::Connection,
    account_id: i64,
    label: &Label,
) -> Result<i64> {
    let color = if label.color.starts_with('#') {
        label.color.as_str()
    } else {
        "#6b7280"
    };
    let known: Option<i64> = conn
        .query_row(
            "SELECT id FROM labels
             WHERE scope = 'account' AND owner_account_id = ?1 AND keyword = ?2",
            params![account_id, label.id],
            |row| row.get(0),
        )
        .optional()?;
    let named: Option<i64> = conn
        .query_row(
            "SELECT id FROM labels
             WHERE scope = 'account' AND owner_account_id = ?1 AND name = ?2 COLLATE NOCASE",
            params![account_id, label.name],
            |row| row.get(0),
        )
        .optional()?;
    match (known, named) {
        (Some(id), named) => {
            // A name another label holds is left to that label.
            if named.is_none_or(|named| named == id) {
                conn.execute(
                    "UPDATE labels SET name = ?2, color = ?3 WHERE id = ?1",
                    params![id, label.name, color],
                )?;
            }
            Ok(id)
        }
        (None, Some(id)) => {
            conn.execute(
                "UPDATE labels SET keyword = ?2, color = ?3, origin = 'provider' WHERE id = ?1",
                params![id, label.id, color],
            )?;
            Ok(id)
        }
        (None, None) => {
            conn.execute(
                "INSERT INTO labels (name, color, keyword, position, scope, owner_account_id, origin)
                 VALUES (?1, ?2, ?3,
                         COALESCE((SELECT MAX(position) + 1 FROM labels WHERE is_auto = 0), 0),
                         'account', ?4, 'provider')",
                params![label.name, color, label.id, account_id],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }
}

/// Brings the account's folders and labels in line with Proton's.
pub(crate) async fn sync_labels(ctx: &SyncCtx, account_id: i64, c: &Connected) -> Result<()> {
    let folders = mail::labels(&c.session, mail::LABEL_TYPE_FOLDER).await?;
    let labels = mail::labels(&c.session, mail::LABEL_TYPE_LABEL).await?;
    let gone = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let mut seen = HashSet::new();
            for (id, name, role) in SYSTEM_FOLDERS {
                upsert_folder(&tx, account_id, id, name, Some(role), false)?;
                seen.insert(id.to_owned());
            }
            let by_id = folders
                .iter()
                .map(|folder| (folder.id.as_str(), folder))
                .collect::<HashMap<_, _>>();
            let mut local = HashMap::new();
            // Parents first, so a renamed parent's path is free for it
            // before its children take theirs.
            let mut ordered = folders.iter().collect::<Vec<_>>();
            ordered.sort_by_key(|folder| folder_path(&folder.id, &by_id).len());
            for folder in ordered {
                let mut path = folder_path(&folder.id, &by_id);
                // A folder named like a system folder stays apart from it.
                if SYSTEM_FOLDERS
                    .iter()
                    .any(|(_, name, _)| name.eq_ignore_ascii_case(&path))
                {
                    path.push_str(" (folder)");
                }
                let id = upsert_folder(&tx, account_id, &folder.id, &path, None, true)?;
                local.insert(folder.id.clone(), id);
                seen.insert(folder.id.clone());
            }
            for folder in &folders {
                let parent = folder
                    .parent_id
                    .as_ref()
                    .and_then(|parent| local.get(parent))
                    .copied();
                repo::folders::set_parent(&tx, local[&folder.id], parent)?;
            }
            let mut label_ids = HashSet::new();
            for label in &labels {
                upsert_label(&tx, account_id, label)?;
                label_ids.insert(label.id.clone());
            }
            // Labels Proton had and no longer has go; ones made here that
            // Proton never had stay until they are first used.
            tx.execute(
                "DELETE FROM labels
                 WHERE scope = 'account' AND owner_account_id = ?1 AND origin = 'provider'
                   AND keyword NOT IN (SELECT value FROM json_each(?2))",
                params![
                    account_id,
                    serde_json::to_string(&label_ids.iter().collect::<Vec<_>>())?
                ],
            )?;
            let mut statement = tx.prepare(
                "SELECT id, proton_id FROM folders
                 WHERE account_id = ?1 AND proton_id IS NOT NULL",
            )?;
            let gone = statement
                .query_map(params![account_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|(_, proton_id)| !seen.contains(proton_id))
                .map(|(id, _)| (id, true))
                .collect::<Vec<_>>();
            drop(statement);
            tx.commit()?;
            Ok(gone)
        })
        .await?;
    if !gone.is_empty() {
        // Proton moves a deleted folder's mail to the Inbox or Trash, which
        // the message changes report; the folder itself goes here.
        crate::sync::forget_unlisted_folders(ctx, account_id, gone).await?;
    }
    ctx.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
    Ok(())
}

/// The folders of an account by Proton id: (folder here, role).
type Folders = HashMap<String, (i64, Option<String>)>;

fn folders_by_proton_id(conn: &rusqlite::Connection, account_id: i64) -> Result<Folders> {
    let mut statement = conn.prepare(
        "SELECT proton_id, id, role FROM folders
         WHERE account_id = ?1 AND proton_id IS NOT NULL",
    )?;
    Ok(statement
        .query_map(params![account_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, Option<String>>(2)?),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?)
}

/// The one folder a message is in. Proton lists it under several ids: its
/// folder, "all mail", "all sent" or "all drafts", the star and its labels.
pub(crate) fn location<'a>(
    labels: &'a [String],
    folders: &'a Folders,
) -> Option<(&'a str, i64, Option<&'a str>)> {
    let find = |id: &str| {
        labels
            .iter()
            .find(|label| label.as_str() == id)
            .and_then(|label| folders.get(label).map(|folder| (label.as_str(), folder)))
    };
    let system_ids = SYSTEM_FOLDERS.map(|(id, _, _)| id);
    let custom = labels.iter().find_map(|label| {
        (!system_ids.contains(&label.as_str()))
            .then(|| folders.get(label).map(|folder| (label.as_str(), folder)))
            .flatten()
    });
    let fallback = |all: &str, id: &'static str| {
        labels
            .iter()
            .any(|label| label == all)
            .then(|| folders.get(id).map(|folder| (id, folder)))
            .flatten()
    };
    find(system::TRASH)
        .or_else(|| find(system::SPAM))
        .or(custom)
        .or_else(|| find(system::ARCHIVE))
        .or_else(|| find(system::INBOX))
        .or_else(|| find(system::DRAFTS))
        .or_else(|| find(system::SENT))
        .or_else(|| fallback(system::ALL_DRAFTS, system::DRAFTS))
        .or_else(|| fallback(system::ALL_SENT, system::SENT))
        .or_else(|| {
            folders
                .get(system::ARCHIVE)
                .map(|folder| (system::ARCHIVE, folder))
        })
        .map(|(id, (folder, role))| (id, *folder, role.as_deref()))
}

#[derive(Default)]
struct State {
    event_id: Option<String>,
    pending_event_id: Option<String>,
}

async fn load_state(ctx: &SyncCtx, account_id: i64) -> Result<State> {
    ctx.db
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT event_id, pending_event_id FROM proton_sync_state
                     WHERE account_id = ?1",
                    params![account_id],
                    |row| {
                        Ok(State {
                            event_id: row.get(0)?,
                            pending_event_id: row.get(1)?,
                        })
                    },
                )
                .optional()?
                .unwrap_or_default())
        })
        .await
}

async fn save_event_id(ctx: &SyncCtx, account_id: i64, event_id: String) -> Result<()> {
    ctx.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO proton_sync_state (account_id, event_id, pending_event_id)
                 VALUES (?1, ?2, NULL)
                 ON CONFLICT(account_id) DO UPDATE
                   SET event_id = excluded.event_id, pending_event_id = NULL",
                params![account_id, event_id],
            )?;
            Ok(())
        })
        .await
}

/// Whether the account's history setting was widened since its mail was
/// listed, which reopens its folders.
async fn history_reopened(ctx: &SyncCtx, account_id: i64) -> Result<bool> {
    ctx.db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM folders
                               WHERE account_id = ?1 AND proton_id IS NOT NULL
                                 AND backfill_done = 0)",
                params![account_id],
                |row| row.get(0),
            )?)
        })
        .await
}

async fn sync_messages(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &Connected,
    live_since: i64,
) -> Result<()> {
    let state = load_state(ctx, config.id).await?;
    let Some(mut event_id) = state.event_id else {
        return full_sync(ctx, config, c, state.pending_event_id, live_since).await;
    };
    if history_reopened(ctx, config.id).await? {
        return full_sync(ctx, config, c, Some(event_id), live_since).await;
    }
    for _ in 0..MAX_EVENT_ROUNDS {
        let events = mail::events_since(&c.session, &event_id).await?;
        if events.refresh != 0 {
            // Proton no longer has the changes since: list everything again.
            return full_sync(ctx, config, c, Some(events.event_id), live_since).await;
        }
        if !events.labels.is_empty() {
            sync_labels(ctx, config.id, c).await?;
        }
        let mut deleted = Vec::new();
        let mut changed = Vec::new();
        for event in events.messages {
            if event.action == 0 {
                deleted.push(event.id);
            } else {
                changed.push(event.id);
            }
        }
        changed.sort();
        changed.dedup();
        for ids in changed.chunks(mail::PAGE_SIZE) {
            // The event's own copy may leave fields out, so each message is
            // read as it is now. One that is gone by now has its own event.
            let messages = mail::metadata_of(&c.session, ids).await?;
            persist(ctx, config, messages, false, None, live_since, true).await?;
        }
        remove(ctx, config.id, deleted).await?;
        let more = events.more != 0;
        if events.event_id != event_id {
            event_id = events.event_id;
            save_event_id(ctx, config.id, event_id.clone()).await?;
        }
        if !more {
            break;
        }
    }
    Ok(())
}

/// Lists all the account's mail, newest first, within its history setting,
/// and removes what Proton no longer has.
async fn full_sync(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &Connected,
    since_event: Option<String>,
    live_since: i64,
) -> Result<()> {
    let account_id = config.id;
    // Changes made while the listing runs are in the stream from here.
    let since_event = match since_event {
        Some(event_id) => event_id,
        None => {
            let event_id = mail::latest_event(&c.session).await?;
            let pending = event_id.clone();
            ctx.db
                .write(move |conn| {
                    conn.execute(
                        "INSERT INTO proton_sync_state (account_id, pending_event_id)
                         VALUES (?1, ?2)
                         ON CONFLICT(account_id) DO UPDATE
                           SET pending_event_id = excluded.pending_event_id",
                        params![account_id, pending],
                    )?;
                    Ok(())
                })
                .await?;
            event_id
        }
    };
    sync_labels(ctx, account_id, c).await?;
    let cutoff = config.settings.mail_history.cutoff_ms_at(now_ms());
    let mut seen = HashSet::new();
    let mut page = 0;
    loop {
        let listed = mail::metadata_page(&c.session, system::ALL_MAIL, page).await?;
        let count = listed.messages.len();
        let oldest = listed.messages.last().map(|message| message.time * 1000);
        seen.extend(listed.messages.iter().map(|message| message.id.clone()));
        persist(ctx, config, listed.messages, true, cutoff, live_since, true).await?;
        page += 1;
        let listed_all = count < mail::PAGE_SIZE || (page * mail::PAGE_SIZE) as u64 >= listed.total;
        let past_history =
            cutoff.is_some_and(|cutoff| oldest.is_some_and(|oldest| oldest < cutoff));
        if listed_all || past_history {
            break;
        }
    }
    let (thread_ids, stale_paths) = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let mut statement = tx.prepare(
                "SELECT id, thread_id, raw_path, proton_id, date FROM messages
                 WHERE account_id = ?1 AND proton_id IS NOT NULL",
            )?;
            let rows = statement
                .query_map(params![account_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            let mut threads = HashSet::new();
            let mut paths = Vec::new();
            for (id, thread_id, path, proton_id, date) in rows {
                // Mail older than the history kept was never listed, so its
                // absence from the listing says nothing.
                if !seen.contains(&proton_id)
                    && cutoff.is_none_or(|cutoff| date >= cutoff)
                    && !repo::actions::has_pending_remote_creation(&tx, id)?
                {
                    threads.extend(thread_id);
                    paths.extend(path);
                    repo::messages::delete(&tx, id)?;
                }
            }
            for thread_id in &threads {
                repo::threads::recompute(&tx, *thread_id)?;
            }
            tx.execute(
                "UPDATE folders SET backfill_done = 1
                 WHERE account_id = ?1 AND proton_id IS NOT NULL",
                params![account_id],
            )?;
            tx.execute(
                "UPDATE messages SET relink_pending = 0
                 WHERE account_id = ?1 AND relink_pending = 1 AND proton_id IS NOT NULL",
                params![account_id],
            )?;
            tx.commit()?;
            Ok((threads.into_iter().collect::<Vec<_>>(), paths))
        })
        .await?;
    publish(ctx, thread_ids, stale_paths).await;
    save_event_id(ctx, account_id, since_event).await
}

async fn publish(ctx: &SyncCtx, thread_ids: Vec<i64>, stale_paths: Vec<String>) {
    for path in stale_paths {
        let _ = tokio::fs::remove_file(path).await;
    }
    if !thread_ids.is_empty() {
        ctx.bus.emit(CoreEvent::MailUpdated { thread_ids });
    }
}

/// Removes messages Proton deleted.
async fn remove(ctx: &SyncCtx, account_id: i64, proton_ids: Vec<String>) -> Result<()> {
    if proton_ids.is_empty() {
        return Ok(());
    }
    let (thread_ids, stale_paths) = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let mut threads = HashSet::new();
            let mut paths = Vec::new();
            for proton_id in proton_ids {
                let row: Option<(i64, Option<i64>, Option<String>)> = tx
                    .query_row(
                        "SELECT id, thread_id, raw_path FROM messages
                         WHERE account_id = ?1 AND proton_id = ?2",
                        params![account_id, proton_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                if let Some((id, thread_id, path)) = row
                    && !repo::actions::has_pending_remote_creation(&tx, id)?
                {
                    threads.extend(thread_id);
                    paths.extend(path);
                    repo::messages::delete(&tx, id)?;
                }
            }
            for thread_id in &threads {
                repo::threads::recompute(&tx, *thread_id)?;
            }
            tx.commit()?;
            Ok((threads.into_iter().collect::<Vec<_>>(), paths))
        })
        .await?;
    publish(ctx, thread_ids, stale_paths).await;
    Ok(())
}

fn address(recipient: &mail::Recipient) -> crate::models::Address {
    crate::models::Address {
        name: (!recipient.name.is_empty() && recipient.name != recipient.address)
            .then(|| recipient.name.clone()),
        email: recipient.address.clone(),
    }
}

pub(crate) fn message_by_proton_id(
    conn: &rusqlite::Connection,
    account_id: i64,
    proton_id: &str,
) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT id FROM messages WHERE account_id = ?1 AND proton_id = ?2",
            params![account_id, proton_id],
            |row| row.get(0),
        )
        .optional()?)
}

/// Stores a page of message metadata: new messages are inserted, known ones
/// brought in line with Proton. `sorted` lets rules and notifications act on
/// what is new; mail a search found is left as it is.
pub(crate) async fn persist(
    ctx: &SyncCtx,
    config: &AccountConfig,
    messages: Vec<Metadata>,
    full_sync: bool,
    insert_after: Option<i64>,
    live_since: i64,
    sorted: bool,
) -> Result<()> {
    if messages.is_empty() {
        return Ok(());
    }
    let account_id = config.id;
    let (thread_ids, notified, stale_paths) = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let settings = repo::settings::get(&tx)?;
            let folders = folders_by_proton_id(&tx, account_id)?;
            let (outgoing_since, incoming_since) =
                repo::contacts::learning_boundaries(&tx, account_id, now_ms())?;
            let own = repo::sender_identities::own_addresses(&tx, account_id)?;
            let sorter = crate::rules::Sorter::load(&tx, account_id)?;
            let caught_up_at = if full_sync {
                tx.query_row(
                    "SELECT caught_up_at FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| row.get::<_, Option<i64>>(0),
                )?
            } else {
                None
            };
            let mut changed_threads = HashSet::new();
            let mut notified = Vec::new();
            let mut stale_paths = Vec::new();
            for meta in messages {
                let Some((location_id, folder_id, role)) = location(&meta.label_ids, &folders)
                else {
                    return Err(CoreError::Network(format!(
                        "Proton message {} is in no folder this account has",
                        meta.id
                    )));
                };
                let date = meta.time.saturating_mul(1000);
                let external_id = meta
                    .external_id
                    .as_deref()
                    .map(|id| id.trim().trim_matches(['<', '>']).to_owned())
                    .filter(|id| !id.is_empty());
                let existing: Option<(i64, Option<i64>, Option<String>)> = tx
                    .query_row(
                        "SELECT id, thread_id, proton_id FROM messages
                         WHERE account_id = ?1 AND proton_id = ?2",
                        params![account_id, meta.id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                // A message this app made, or one an earlier protocol of the
                // account left, is the same message once Proton lists it.
                let existing = match (existing, &external_id) {
                    (Some(row), _) => Some(row),
                    (None, Some(external_id)) => tx
                        .query_row(
                            "SELECT id, thread_id, proton_id FROM messages
                             WHERE account_id = ?1 AND message_id = ?2 AND proton_id IS NULL
                             ORDER BY id LIMIT 1",
                            params![account_id, external_id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .optional()?,
                    (None, None) => None,
                };
                if existing.is_none() && insert_after.is_some_and(|after| date < after) {
                    continue;
                }
                // A message Proton lists without a conversation is its own.
                let conversation = if meta.conversation_id.is_empty() {
                    format!("message:{}", meta.id)
                } else {
                    meta.conversation_id.clone()
                };
                let thread_id = match tx
                    .query_row(
                        "SELECT id FROM threads WHERE account_id = ?1 AND proton_id = ?2",
                        params![account_id, conversation],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                {
                    Some(id) => id,
                    None => match existing.as_ref().and_then(|row| row.1) {
                        Some(id) => {
                            tx.execute(
                                "UPDATE threads SET proton_id = ?2
                                 WHERE id = ?1 AND proton_id IS NULL",
                                params![id, conversation],
                            )?;
                            id
                        }
                        None => {
                            tx.execute(
                                "INSERT INTO threads (account_id, proton_id, subject_norm)
                                 VALUES (?1, ?2, ?3)",
                                params![
                                    account_id,
                                    conversation,
                                    crate::mime::normalize_subject(&meta.subject)
                                ],
                            )?;
                            tx.last_insert_rowid()
                        }
                    },
                };
                let is_read = !meta.is_unread();
                let is_starred = meta.is_starred();
                let is_draft = role == Some(roles::DRAFTS) || meta.has_label(system::ALL_DRAFTS);
                let is_outgoing =
                    !is_draft && (role == Some(roles::SENT) || meta.has_label(system::ALL_SENT));
                let from = (!meta.sender.address.is_empty()).then(|| address(&meta.sender));
                let to = meta.to_list.iter().map(address).collect::<Vec<_>>();
                let cc = meta.cc_list.iter().map(address).collect::<Vec<_>>();
                let has_attachments = meta.num_attachments > 0;
                if let Some((id, existing_thread, _)) = existing
                    && repo::actions::has_pending_remote_creation(&tx, id)?
                {
                    // A queued save or send owns the draft here; only its
                    // link to Proton's copy is kept.
                    tx.execute(
                        "UPDATE messages SET proton_id = ?2 WHERE id = ?1",
                        params![id, meta.id],
                    )?;
                    changed_threads.extend(existing_thread);
                    continue;
                }
                let inserted = existing.is_none();
                let is_junk = matches!(role, Some(roles::SPAM) | Some(roles::TRASH));
                let local_id;
                let mut announce = None;
                if let Some((id, old_thread, _)) = existing {
                    let (pending_flags, pending_folder) =
                        repo::actions::jmap_reconciliation_guards(&tx, id)?;
                    tx.execute(
                        "UPDATE messages SET proton_id = ?2, uid = NULL, thread_id = ?3,
                           folder_id = CASE WHEN ?4 THEN folder_id ELSE ?5 END,
                           message_id = COALESCE(?6, message_id), subject = ?7,
                           from_name = ?8, from_addr = ?9, to_json = ?10, cc_json = ?11,
                           date = ?12, internal_date = ?12,
                           is_read = CASE WHEN ?13 THEN is_read ELSE ?14 END,
                           is_starred = CASE WHEN ?13 THEN is_starred ELSE ?15 END,
                           is_draft = ?16, is_outgoing = ?17, size = ?18,
                           has_attachments = CASE WHEN body_state = 'cached'
                                                  THEN has_attachments ELSE ?19 END
                         WHERE id = ?1",
                        params![
                            id,
                            meta.id,
                            thread_id,
                            pending_folder,
                            folder_id,
                            external_id,
                            meta.subject,
                            from.as_ref().and_then(|value| value.name.clone()),
                            from.as_ref().map(|value| value.email.clone()),
                            serde_json::to_string(&to)?,
                            serde_json::to_string(&cc)?,
                            date,
                            pending_flags,
                            is_read,
                            is_starred,
                            is_draft,
                            is_outgoing,
                            meta.size,
                            has_attachments,
                        ],
                    )?;
                    // A draft changed elsewhere is read again.
                    if is_draft && !pending_folder {
                        let stale: Option<String> = tx
                            .query_row(
                                "SELECT raw_path FROM messages WHERE id = ?1 AND size IS NOT ?2",
                                params![id, meta.size],
                                |row| row.get(0),
                            )
                            .optional()?
                            .flatten();
                        if let Some(path) = stale {
                            tx.execute(
                                "UPDATE messages SET body_state = 'none', raw_path = NULL
                                 WHERE id = ?1",
                                params![id],
                            )?;
                            stale_paths.push(path);
                        }
                    }
                    if let Some(old_thread) = old_thread
                        && old_thread != thread_id
                    {
                        changed_threads.insert(old_thread);
                    }
                    if !pending_flags {
                        repo::labels::reconcile_keywords(&tx, id, &meta.label_ids)?;
                    }
                    local_id = id;
                } else {
                    let from_email = from
                        .as_ref()
                        .map(|sender| sender.email.to_ascii_lowercase())
                        .unwrap_or_default();
                    let new = NewMessage {
                        account_id,
                        folder_id,
                        uid: None,
                        message_id: external_id,
                        gm_msgid: None,
                        gm_thrid: None,
                        subject: meta.subject.clone(),
                        from: from.clone(),
                        to: to.clone(),
                        cc: cc.clone(),
                        bcc: Vec::new(),
                        date,
                        internal_date: Some(date),
                        is_read,
                        is_starred,
                        is_draft,
                        is_outgoing,
                        is_automated: false,
                        has_attachments,
                        size: Some(meta.size),
                        snippet: String::new(),
                        references: Vec::new(),
                        list_unsubscribe: None,
                        list_unsubscribe_post: None,
                        list_id: None,
                        sender_addr: None,
                        sender_verification: crate::models::SenderVerification::None,
                        receipt_to: Vec::new(),
                        receipt_confirm: false,
                        receipt_handled: false,
                        importance: Default::default(),
                    };
                    local_id = repo::messages::insert(&tx, &new, thread_id)?;
                    tx.execute(
                        "UPDATE messages SET proton_id = ?2 WHERE id = ?1",
                        params![local_id, meta.id],
                    )?;
                    repo::labels::reconcile_keywords(&tx, local_id, &meta.label_ids)?;
                    if is_outgoing && settings.collect_outgoing_contacts && date >= outgoing_since {
                        let mut harvested = HashSet::new();
                        for recipient in to.iter().chain(cc.iter()) {
                            let email = recipient.email.to_ascii_lowercase();
                            if !own.contains(&email) && harvested.insert(email) {
                                repo::contacts::harvest(&tx, account_id, recipient, true, date)?;
                            }
                        }
                    }
                    if location_id == system::INBOX
                        && !is_draft
                        && crate::sync::ingest::arrival_eligible(
                            date >= live_since,
                            is_read,
                            is_outgoing,
                            date,
                            now_ms(),
                        )
                    {
                        announce = Some(crate::sync::ingest::chime_worthy(false, &from_email));
                    }
                }
                repo::search::index_message(&tx, local_id)?;
                let turned_away = inserted && sorted && crate::turn_away(&tx, local_id)?;
                let arrived = sorted
                    && inserted
                    && !turned_away
                    && !is_outgoing
                    && !is_draft
                    && (!full_sync || caught_up_at.is_some_and(|at| date >= at));
                let outcome = if arrived {
                    sorter.arrived(
                        &tx,
                        local_id,
                        crate::rules::Arrival {
                            headers: None,
                            text: None,
                            attachments_known: true,
                        },
                    )?
                } else {
                    Default::default()
                };
                if inserted
                    && !is_outgoing
                    && !is_draft
                    && !is_junk
                    && !outcome.unwanted
                    && settings.collect_incoming_contacts
                    && date >= incoming_since
                    && let Some(sender) = &from
                    && !crate::mime::robot_sender(&sender.email)
                    && !repo::blocked::is_blocked(&tx, &sender.email.to_ascii_lowercase())?
                {
                    repo::contacts::harvest(&tx, account_id, sender, false, date)?;
                }
                if let Some(audible) = announce
                    && !turned_away
                {
                    if outcome.waiting {
                        crate::rules::hold(&tx, local_id, audible)?;
                    } else if !outcome.silent() && !notified.contains(&thread_id) {
                        repo::notifications::enqueue(&tx, local_id, audible)?;
                        notified.push(thread_id);
                    }
                }
                changed_threads.insert(thread_id);
            }
            for thread_id in &changed_threads {
                repo::threads::recompute(&tx, *thread_id)?;
            }
            if settings.auto_labels_enabled {
                for &thread_id in &changed_threads {
                    crate::route::route_thread_deterministic(
                        &tx,
                        settings.ai_categorize,
                        thread_id,
                    )?;
                }
            }
            tx.commit()?;
            Ok((
                changed_threads.into_iter().collect::<Vec<_>>(),
                notified,
                stale_paths,
            ))
        })
        .await?;
    publish(ctx, thread_ids, stale_paths).await;
    if !notified.is_empty() {
        ctx.bus.emit(CoreEvent::MailNew {
            account_id,
            thread_ids: notified,
        });
    }
    Ok(())
}

async fn body_actor(
    ctx: SyncCtx,
    config: AccountConfig,
    link: Link,
    mut rx: mpsc::Receiver<PriorityFetchCmd>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            PriorityFetchCmd::Body(message_id) => {
                if let Err(error) = fetch_body(&ctx, &config, &link, message_id).await {
                    tracing::warn!(account_id = config.id, message_id, %error, "Proton body fetch failed");
                    let _ = ctx
                        .db
                        .write(move |conn| repo::messages::set_body_state(conn, message_id, "none"))
                        .await;
                }
            }
            PriorityFetchCmd::Attachment {
                attachment_id,
                complete,
            } => {
                let result = fetch_attachment(&ctx, &config, &link, attachment_id)
                    .await
                    .map_err(|error| error.to_string());
                let _ = complete.send(result);
            }
            PriorityFetchCmd::Search {
                tree,
                cursor,
                limit,
                complete,
            } => {
                let result = search(&ctx, &config, &link, &tree, &cursor, limit)
                    .await
                    .map_err(|error| error.to_string());
                let _ = complete.send(result);
            }
        }
    }
}

/// Fetches a message from Proton, decrypts it and returns it as the message
/// that was sent, with what Proton says about it.
pub(crate) async fn download(c: &Connected, proton_id: &str) -> Result<(Metadata, Vec<u8>)> {
    let (meta, raw) = mail::fetch_rfc822(&c.session, c.keys.as_ref(), proton_id).await?;
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err(CoreError::Other(format!(
            "message exceeds the {} MiB local safety limit",
            MAX_MESSAGE_BYTES / (1024 * 1024)
        )));
    }
    Ok((meta, raw))
}

pub(crate) async fn fetch_body(
    ctx: &SyncCtx,
    config: &AccountConfig,
    link: &Link,
    message_id: i64,
) -> Result<()> {
    let (body_state, proton_id) = ctx
        .db
        .read(move |conn| {
            conn.query_row(
                "SELECT body_state, proton_id FROM messages WHERE id = ?1",
                params![message_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound(format!("message {message_id}")))
        })
        .await?;
    if body_state == "cached" {
        return Ok(());
    }
    let proton_id = proton_id.ok_or_else(|| CoreError::NotFound("Proton message id".into()))?;
    let connected = match link.get(owner(config)).await {
        Ok(connected) => connected,
        Err(error) => {
            link.reset().await;
            return Err(error);
        }
    };
    let (_, raw) = download(&connected, &proton_id).await?;
    let parsed = crate::mime::parse_message(&raw)?;
    let calendar_events = crate::sync::ingest::calendar_parts(&parsed);
    let dir = ctx.paths.mail_dir(config.id);
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{message_id}.proton.eml"));
    crate::file_io::write_atomic(&path, &raw, "Proton message cache").await?;
    let path_string = path.to_string_lossy().into_owned();
    let guarded = proton_id.clone();
    let references = parsed.headers.references.clone();
    let is_automated = parsed.headers.is_automated;
    let (persisted, thread_ids, fresh) = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let current: Option<(Option<String>, Option<i64>)> = tx
                .query_row(
                    "SELECT proton_id, thread_id FROM messages WHERE id = ?1",
                    params![message_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((Some(current_id), thread_id)) = current else {
                return Ok((false, Vec::new(), None));
            };
            if current_id != guarded {
                return Ok((false, Vec::new(), None));
            }
            let mut thread_ids =
                crate::sync::ingest::store_body(&tx, message_id, &path_string, &parsed)?;
            // What the listing could not say comes with the message itself.
            tx.execute(
                "UPDATE messages SET is_automated = ?2 WHERE id = ?1",
                params![message_id, is_automated],
            )?;
            for reference in &references {
                tx.execute(
                    "INSERT OR IGNORE INTO message_refs(message_id, ref_message_id)
                     VALUES (?1, ?2)",
                    params![message_id, reference],
                )?;
            }
            let fresh = crate::rules::resume(&tx, message_id)?
                .filter(|resumed| resumed.announced)
                .map(|resumed| resumed.thread_id);
            if let Some(thread_id) = thread_id {
                repo::threads::recompute(&tx, thread_id)?;
                if !thread_ids.contains(&thread_id) {
                    thread_ids.push(thread_id);
                }
            }
            tx.commit()?;
            Ok((true, thread_ids, fresh))
        })
        .await?;
    if !persisted {
        let _ = tokio::fs::remove_file(path).await;
        return Ok(());
    }
    crate::sync::ingest::store_calendar_events(
        ctx,
        config.id,
        vec![(message_id, calendar_events)],
        crate::sync::ingest::Arrival::Received,
    )
    .await?;
    if !thread_ids.is_empty() {
        ctx.bus.emit(CoreEvent::MailUpdated { thread_ids });
    }
    if let Some(thread_id) = fresh {
        ctx.bus.emit(CoreEvent::MailNew {
            account_id: config.id,
            thread_ids: vec![thread_id],
        });
    }
    Ok(())
}

/// An attachment's bytes, from the stored message; the message is fetched
/// first when it isn't here yet.
async fn fetch_attachment(
    ctx: &SyncCtx,
    config: &AccountConfig,
    link: &Link,
    attachment_id: i64,
) -> Result<Vec<u8>> {
    let (message_id, part_id, raw_path) = ctx
        .db
        .read(move |conn| {
            conn.query_row(
                "SELECT a.message_id, a.part_id, m.raw_path FROM attachments a
                 JOIN messages m ON m.id = a.message_id WHERE a.id = ?1",
                params![attachment_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .map_err(Into::into)
        })
        .await?;
    let part_id = part_id.ok_or_else(|| CoreError::NotFound("attachment MIME part".into()))?;
    let cached = match raw_path {
        Some(path) => crate::file_io::read(path, MAX_MESSAGE_BYTES, "cached Proton message")
            .await
            .ok(),
        None => None,
    };
    let raw = match cached {
        Some(raw) => raw,
        None => {
            ctx.db
                .write(move |conn| repo::messages::set_body_state(conn, message_id, "none"))
                .await?;
            fetch_body(ctx, config, link, message_id).await?;
            let path = ctx
                .db
                .read(move |conn| {
                    repo::messages::get_row(conn, message_id)?
                        .and_then(|row| row.raw_path)
                        .ok_or_else(|| CoreError::NotFound("cached Proton message".into()))
                })
                .await?;
            crate::file_io::read(path, MAX_MESSAGE_BYTES, "cached Proton message").await?
        }
    };
    crate::mime::extract_attachment(&raw, &part_id).map(|(bytes, _)| bytes)
}

/// Searches the account's mail on Proton for `tree`. Proton keeps mail
/// encrypted and searches what it can read: senders, recipients, subjects
/// and what it lists about a message. Text inside messages is found in the
/// mail kept here.
async fn search(
    ctx: &SyncCtx,
    config: &AccountConfig,
    link: &Link,
    tree: &crate::search::Expr,
    cursor: &ServerSearchCursor,
    limit: usize,
) -> Result<ServerHits> {
    let account_id = config.id;
    let folders = ctx
        .db
        .read(move |conn| folders_by_proton_id(conn, account_id))
        .await?;
    let by_role = folders
        .iter()
        .filter_map(|(id, (_, role))| Some((role.clone()?, id.clone())))
        .collect::<HashMap<_, _>>();
    let Some(query) = crate::search::server::proton(tree, &by_role) else {
        return Ok(ServerHits {
            message_ids: Vec::new(),
            next: None,
        });
    };
    let connected = link.get(owner(config)).await?;
    let mut page = cursor.position;
    let mut found = Vec::new();
    let mut new = 0;
    let mut more = true;
    for _ in 0..SERVER_SEARCH_PAGES {
        let listed = mail::search_page(&connected.session, &query, page).await?;
        page += 1;
        let count = listed.messages.len();
        let ids = listed
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect::<Vec<_>>();
        let wanted = ids.clone();
        let missing = ctx
            .db
            .read(move |conn| {
                let mut missing = HashSet::new();
                for id in wanted {
                    if message_by_proton_id(conn, account_id, &id)?.is_none() {
                        missing.insert(id);
                    }
                }
                Ok(missing)
            })
            .await?;
        new += missing.len();
        let unknown = listed
            .messages
            .into_iter()
            .filter(|message| missing.contains(&message.id))
            .collect::<Vec<_>>();
        // Found mail notifies of nothing, and rules leave it as it is.
        persist(ctx, config, unknown, false, None, i64::MAX, false).await?;
        found.extend(ids);
        if count < mail::PAGE_SIZE || page * mail::PAGE_SIZE as u64 >= listed.total {
            more = false;
            break;
        }
        if new >= limit {
            break;
        }
    }
    let message_ids = ctx
        .db
        .read(move |conn| {
            let mut message_ids = Vec::with_capacity(found.len());
            for id in &found {
                message_ids.extend(message_by_proton_id(conn, account_id, id)?);
            }
            Ok(message_ids)
        })
        .await?;
    Ok(ServerHits {
        message_ids,
        next: more.then(|| ServerSearchCursor {
            position: page,
            ..ServerSearchCursor::default()
        }),
    })
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
