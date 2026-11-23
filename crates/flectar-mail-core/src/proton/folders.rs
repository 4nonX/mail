//! Making, renaming and deleting a Proton account's folders.

use super::mail;
use super::sync::{Link, upsert_folder};
use crate::db::repo;
use crate::error::{CoreError, Result};
use crate::models::AccountConfig;
use crate::sync::engine::SyncCtx;
use rusqlite::{OptionalExtension, params};

/// The color Proton gives a folder nobody chose one for.
const DEFAULT_COLOR: &str = "#8080FF";
/// Between the levels of a folder's path here.
const SEPARATOR: &str = " / ";

fn proton_id(conn: &rusqlite::Connection, folder_id: i64) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT proton_id FROM folders WHERE id = ?1",
            params![folder_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten())
}

/// Makes a folder on Proton, inside `parent` when one is given, and here.
pub(crate) async fn create(
    ctx: &SyncCtx,
    config: &AccountConfig,
    parent: Option<&repo::folders::Folder>,
    name: &str,
) -> Result<i64> {
    if name.contains(SEPARATOR) {
        return Err(CoreError::Other(format!(
            "folder names cannot contain the hierarchy separator {SEPARATOR:?}"
        )));
    }
    let account_id = config.id;
    let parent_remote = match parent {
        Some(parent) => {
            let parent_id = parent.id;
            Some(
                ctx.db
                    .read(move |conn| proton_id(conn, parent_id))
                    .await?
                    .ok_or_else(|| CoreError::NotFound("the parent folder on Proton".into()))?,
            )
        }
        None => None,
    };
    let connected = Link::for_account(ctx, account_id)
        .get(config.proxy_owner())
        .await?;
    let created = mail::create_label(
        &connected.session,
        mail::LABEL_TYPE_FOLDER,
        name,
        DEFAULT_COLOR,
        parent_remote.as_deref(),
    )
    .await?;
    let path = match parent {
        Some(parent) => format!("{}{SEPARATOR}{name}", parent.path),
        None => name.to_owned(),
    };
    let parent_local = parent.map(|parent| parent.id);
    ctx.db
        .write(move |conn| {
            let folder_id = upsert_folder(conn, account_id, &created.id, &path, None, true)?;
            repo::folders::set_parent(conn, folder_id, parent_local)?;
            // It is new, so there is no mail in it left to list.
            conn.execute(
                "UPDATE folders SET backfill_done = 1 WHERE id = ?1",
                params![folder_id],
            )?;
            Ok(folder_id)
        })
        .await
}

/// Renames a folder on Proton. The caller renames it here.
pub(crate) async fn rename(
    ctx: &SyncCtx,
    config: &AccountConfig,
    folder_id: i64,
    name: &str,
) -> Result<()> {
    let remote_id = ctx
        .db
        .read(move |conn| proton_id(conn, folder_id))
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("remote folder {folder_id}")))?;
    let connected = Link::for_account(ctx, config.id)
        .get(config.proxy_owner())
        .await?;
    let folders = mail::labels(&connected.session, mail::LABEL_TYPE_FOLDER).await?;
    let folder = folders
        .iter()
        .find(|folder| folder.id == remote_id)
        .ok_or_else(|| CoreError::NotFound("the folder on Proton".into()))?;
    mail::rename_label(&connected.session, folder, name).await?;
    Ok(())
}

/// Deletes folders on Proton, in the order given: children before parents.
/// Proton keeps their mail, without a folder. The caller removes them here.
pub(crate) async fn delete(
    ctx: &SyncCtx,
    config: &AccountConfig,
    folder_ids: Vec<i64>,
) -> Result<()> {
    let remote_ids = ctx
        .db
        .read(move |conn| {
            folder_ids
                .iter()
                .map(|folder_id| {
                    proton_id(conn, *folder_id)?
                        .ok_or_else(|| CoreError::NotFound(format!("remote folder {folder_id}")))
                })
                .collect::<Result<Vec<_>>>()
        })
        .await?;
    let connected = Link::for_account(ctx, config.id)
        .get(config.proxy_owner())
        .await?;
    for remote_id in remote_ids {
        mail::delete_label(&connected.session, &remote_id).await?;
    }
    Ok(())
}
