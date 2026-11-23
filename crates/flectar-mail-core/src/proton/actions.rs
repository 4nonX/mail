//! Carrying out on Proton what was done to the account's mail here: marks,
//! moves, labels, deletions, drafts and sends.

use super::api::{ApiError, Failure};
use super::mail::{self, system};
use super::send;
use super::sync::Connected;
use crate::db::repo;
use crate::error::{CoreError, Result};
use crate::events::CoreEvent;
use crate::models::{AccountConfig, now_ms, roles};
use crate::sync::engine::SyncCtx;
use rusqlite::{OptionalExtension, params};

/// Runs the account's queued actions that are due.
pub(crate) async fn execute(ctx: &SyncCtx, config: &AccountConfig, c: &Connected) -> Result<()> {
    let account_id = config.id;
    let actions = ctx
        .db
        .read(move |conn| repo::actions::due(conn, account_id, now_ms(), 20))
        .await?;
    for action in actions {
        let action_id = action.id;
        if !ctx
            .db
            .write(move |conn| repo::actions::try_claim(conn, action_id))
            .await?
        {
            continue;
        }
        match execute_action(ctx, config, c, &action).await {
            Ok(()) => {
                ctx.db
                    .write(move |conn| repo::actions::set_state(conn, action_id, "done", None))
                    .await?;
                ctx.bus.emit(CoreEvent::ActionState {
                    action_id,
                    state: "done".into(),
                    error: None,
                });
            }
            Err(error @ (CoreError::Auth(_) | CoreError::NeedsReauth)) => {
                let message = error.to_string();
                ctx.db
                    .write(move |conn| {
                        repo::actions::bump_attempt(conn, action_id, now_ms() + 60_000, &message)
                    })
                    .await?;
                return Err(error);
            }
            Err(error @ CoreError::RateLimited { .. }) => {
                crate::queue::defer_limited(ctx, action_id, &error).await?;
                return Err(error);
            }
            Err(error @ CoreError::SendUncertain(_)) => {
                let message = error.to_string();
                let saved = message.clone();
                ctx.db
                    .write(move |conn| repo::actions::fail_uncertain(conn, action_id, &saved))
                    .await?;
                ctx.bus.emit(CoreEvent::ActionState {
                    action_id,
                    state: "uncertain".into(),
                    error: Some(message),
                });
            }
            Err(error) => {
                let message = error.to_string();
                let attempts = action.attempts + 1;
                // What Proton refuses it refuses again; the rest is retried.
                let refused = matches!(error, CoreError::Other(_));
                if attempts >= 8 || refused {
                    let saved = message.clone();
                    ctx.db
                        .write(move |conn| {
                            repo::actions::set_state(conn, action_id, "failed", Some(&saved))
                        })
                        .await?;
                    ctx.bus.emit(CoreEvent::ActionState {
                        action_id,
                        state: "failed".into(),
                        error: Some(message),
                    });
                } else {
                    let retry_at = now_ms() + (1_i64 << attempts.min(8)) * 1000 + action_id % 997;
                    let saved = message.clone();
                    ctx.db
                        .write(move |conn| {
                            repo::actions::bump_attempt(conn, action_id, retry_at, &saved)
                        })
                        .await?;
                    tracing::warn!(account_id, action_id, kind = %action.kind, error = %message, "Proton action retry scheduled");
                }
            }
        }
    }
    Ok(())
}

/// Where a message the action names stands.
enum Remote {
    /// It is gone here, so there is nothing left to do.
    Gone,
    /// It is here and not on Proton yet.
    Unlinked,
    Linked(String),
}

async fn remote(ctx: &SyncCtx, message_id: Option<i64>) -> Result<Remote> {
    let Some(message_id) = message_id else {
        return Ok(Remote::Gone);
    };
    ctx.db
        .read(move |conn| {
            Ok(
                match conn
                    .query_row(
                        "SELECT proton_id FROM messages WHERE id = ?1",
                        params![message_id],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()?
                {
                    None => Remote::Gone,
                    Some(None) => Remote::Unlinked,
                    Some(Some(id)) => Remote::Linked(id),
                },
            )
        })
        .await
}

fn linked(remote: &Remote) -> Result<Option<&str>> {
    match remote {
        Remote::Gone => Ok(None),
        Remote::Unlinked => Err(CoreError::Network(
            "the message is waiting for its copy on Proton".into(),
        )),
        Remote::Linked(id) => Ok(Some(id)),
    }
}

/// A change to one message. Proton answers a message that is gone with an
/// error of its own, and then there is nothing left to change.
fn changed(result: super::api::ApiResult<()>) -> Result<()> {
    match result {
        Ok(())
        | Err(Failure::Api(ApiError {
            code: 2501 | 15052, ..
        })) => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}

async fn folder_proton_id(
    ctx: &SyncCtx,
    account_id: i64,
    folder_id: i64,
) -> Result<Option<String>> {
    ctx.db
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT proton_id FROM folders WHERE id = ?1 AND account_id = ?2",
                    params![folder_id, account_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten())
        })
        .await
}

/// The Proton id of a label kept here. One made here that Proton doesn't
/// have yet is made there first, under its name.
async fn label_proton_id(
    ctx: &SyncCtx,
    account_id: i64,
    c: &Connected,
    label_id: i64,
) -> Result<String> {
    let label = ctx
        .db
        .read(move |conn| repo::labels::get(conn, label_id))
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("label {label_id}")))?;
    let existing = mail::labels(&c.session, mail::LABEL_TYPE_LABEL).await?;
    let known = existing
        .iter()
        .find(|remote| remote.id == label.keyword)
        .or_else(|| {
            existing
                .iter()
                .find(|remote| remote.name.eq_ignore_ascii_case(&label.name))
        })
        .cloned();
    let remote = match known {
        Some(remote) => remote,
        None => {
            mail::create_label(
                &c.session,
                mail::LABEL_TYPE_LABEL,
                &label.name,
                &label.color,
                None,
            )
            .await?
        }
    };
    let proton_id = remote.id.clone();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "UPDATE labels SET keyword = ?2, origin = 'provider'
                 WHERE id = ?1 AND owner_account_id = ?3",
                params![label_id, remote.id, account_id],
            )?;
            Ok(())
        })
        .await?;
    Ok(proton_id)
}

async fn execute_action(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &Connected,
    action: &repo::actions::PendingAction,
) -> Result<()> {
    let remote = remote(ctx, action.message_id).await?;
    match action.kind.as_str() {
        "empty_trash" => {
            let folder_id = action.payload["folderId"]
                .as_i64()
                .ok_or_else(|| CoreError::Other("the Trash to empty isn't named".into()))?;
            let folder = ctx
                .db
                .read(move |conn| repo::folders::get(conn, folder_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("Trash".into()))?;
            if folder.account_id != config.id || folder.role.as_deref() != Some(roles::TRASH) {
                return Err(CoreError::Other(
                    "the Trash to empty belongs to another account".into(),
                ));
            }
            let snapshot = crate::sync::snapshot_trash_ids(ctx, config.id).await?;
            mail::empty_label(&c.session, system::TRASH).await?;
            crate::sync::finish_empty_trash(ctx, config.id, snapshot).await
        }
        "delete_permanently" | "remove_transferred" => {
            if let Some(message_id) = action.message_id
                && crate::sync::is_local_only_draft(ctx, message_id).await?
            {
                return crate::sync::finish_permanent_delete(ctx, Some(message_id)).await;
            }
            if let Some(proton_id) = linked(&remote)? {
                send::delete_message(&c.session, proton_id).await?;
            }
            crate::sync::finish_permanent_delete(ctx, action.message_id).await
        }
        "mark_folder_read" => {
            let Some(folder_id) = action.payload["folderId"].as_i64() else {
                return Ok(());
            };
            let before = action.payload["before"].as_i64().unwrap_or_else(now_ms);
            let Some(label) = folder_proton_id(ctx, config.id, folder_id).await? else {
                return Ok(());
            };
            mark_folder_read(c, &label, before).await
        }
        "mark_read" | "mark_unread" => {
            let Some(proton_id) = linked(&remote)? else {
                return Ok(());
            };
            let verb = if action.kind == "mark_read" {
                "read"
            } else {
                "unread"
            };
            changed(mail::act(&c.session, verb, &[proton_id.to_owned()]).await)
        }
        "star" | "unstar" => {
            let Some(proton_id) = linked(&remote)? else {
                return Ok(());
            };
            changed(
                mail::relabel(
                    &c.session,
                    action.kind == "star",
                    system::STARRED,
                    &[proton_id.to_owned()],
                )
                .await,
            )
        }
        "read_receipt" => match linked(&remote)? {
            Some(proton_id) => send::read_receipt(&c.session, proton_id).await,
            None => Ok(()),
        },
        "add_label" | "remove_label" => {
            let Some(proton_id) = linked(&remote)? else {
                return Ok(());
            };
            let label_id = action.payload["labelId"]
                .as_i64()
                .ok_or_else(|| CoreError::Other("the label isn't named".into()))?;
            let label = label_proton_id(ctx, config.id, c, label_id).await?;
            changed(
                mail::relabel(
                    &c.session,
                    action.kind == "add_label",
                    &label,
                    &[proton_id.to_owned()],
                )
                .await,
            )
        }
        // Each leaves the message in one folder here, which is where it
        // goes on Proton.
        "archive" | "unarchive" | "trash" | "spam" | "not_spam" | "move" => {
            let Some(proton_id) = linked(&remote)? else {
                return Ok(());
            };
            let Some(message_id) = action.message_id else {
                return Ok(());
            };
            let target = ctx
                .db
                .read(move |conn| {
                    Ok(conn
                        .query_row(
                            "SELECT f.proton_id FROM messages m
                             JOIN folders f ON f.id = m.folder_id WHERE m.id = ?1",
                            params![message_id],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .optional()?
                        .flatten())
                })
                .await?
                .ok_or_else(|| {
                    CoreError::Network("the folder is waiting for its copy on Proton".into())
                })?;
            changed(mail::relabel(&c.session, true, &target, &[proton_id.to_owned()]).await)
        }
        "save_draft" => {
            let draft_id = action.payload["draftId"]
                .as_i64()
                .or(action.message_id)
                .ok_or_else(|| CoreError::Other("the draft to save isn't named".into()))?;
            // The draft was sent or discarded since.
            let is_draft = ctx
                .db
                .read(move |conn| {
                    Ok(conn
                        .query_row(
                            "SELECT is_draft FROM messages WHERE id = ?1",
                            params![draft_id],
                            |row| row.get::<_, bool>(0),
                        )
                        .optional()?
                        .unwrap_or(false))
                })
                .await?;
            if !is_draft {
                return Ok(());
            }
            send::save_draft(ctx, config, c, draft_id, false)
                .await
                .map(drop)
        }
        "delete_draft" => match action.payload["protonId"].as_str() {
            Some(proton_id) => send::delete_message(&c.session, proton_id).await,
            None => Ok(()),
        },
        "send" => send::send(ctx, config, c, action).await,
        "snooze" | "unsnooze" | "show_in" => Ok(()),
        other => Err(CoreError::Other(format!(
            "Proton accounts have no way to {other}"
        ))),
    }
}

/// Marks a folder's unread messages that arrived before `before` (in
/// milliseconds) read, a page at a time until none are left.
async fn mark_folder_read(c: &Connected, label: &str, before: i64) -> Result<()> {
    let query = format!(
        "LabelID={}&Unread=1&End={}",
        percent_encoding::utf8_percent_encode(label, percent_encoding::NON_ALPHANUMERIC),
        before.div_euclid(1000)
    );
    for _ in 0..1_000 {
        let page = mail::search_page(&c.session, &query, 0).await?;
        let ids = page
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }
        mail::act(&c.session, "read", &ids).await?;
        if ids.len() < mail::PAGE_SIZE {
            return Ok(());
        }
    }
    Ok(())
}
