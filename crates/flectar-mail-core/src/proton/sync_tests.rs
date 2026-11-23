use super::*;
use crate::accounts::credentials::{CredentialStoreHandle, DevelopmentFileCredentialStore};
use crate::config::Paths;
use crate::db::Db;
use crate::events::EventBus;
use crate::models::MailHistory;
use crate::oauth::tokens::TokenProvider;

async fn fixture() -> (tempfile::TempDir, SyncCtx, AccountConfig) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("mail.db")).unwrap();
    let credentials: CredentialStoreHandle = Arc::new(DevelopmentFileCredentialStore::new(
        dir.path().join("credentials.json"),
    ));
    let tokens = TokenProvider::new(
        credentials.clone(),
        Arc::new(crate::oauth::redirect::LoopbackRedirectBroker::default()),
    );
    let ctx = SyncCtx {
        db,
        calendar_db: Db::deferred_calendar(dir.path().join("calendar.db")),
        bus: EventBus::new(),
        paths: Arc::new(Paths::for_tests(dir.path())),
        tokens,
        credentials,
        pace: Default::default(),
    };
    let mut config = ctx
        .db
        .write(|conn| {
            crate::db::testutil::seed_account(conn);
            conn.execute("DELETE FROM folders WHERE account_id = 1", [])?;
            conn.execute(
                "UPDATE accounts SET mail_protocol = 'proton', sync_id = NULL WHERE id = 1",
                [],
            )?;
            for (id, name, role) in SYSTEM_FOLDERS {
                upsert_folder(conn, 1, id, name, Some(role), false)?;
            }
            upsert_folder(conn, 1, "custom", "Projects", None, true)?;
            Ok(repo::accounts::get_config(conn, 1)?.unwrap())
        })
        .await
        .unwrap();
    config.settings.mail_history = MailHistory::All;
    (dir, ctx, config)
}

fn message(id: &str, labels: &[&str]) -> Metadata {
    serde_json::from_value(serde_json::json!({
        "ID": id,
        "AddressID": "address",
        "ConversationID": "conversation",
        "Subject": "Hello",
        "Sender": {"Name": "Sender", "Address": "sender@mail.example"},
        "ToList": [{"Name": "me@test.dev", "Address": "me@test.dev"}],
        "CCList": [],
        "Time": 1_800_000_000,
        "Size": 2048,
        "Unread": 1,
        "LabelIDs": labels,
        "ExternalID": format!("{id}@mail.example"),
        "NumAttachments": 0,
    }))
    .unwrap()
}

async fn row(ctx: &SyncCtx, proton_id: &'static str) -> Option<(String, bool, bool, i64)> {
    ctx.db
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT f.path, m.is_read, m.is_starred, m.thread_id
                     FROM messages m JOIN folders f ON f.id = m.folder_id
                     WHERE m.account_id = 1 AND m.proton_id = ?1",
                    params![proton_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?)
        })
        .await
        .unwrap()
}

#[test]
fn a_message_is_in_the_one_folder_proton_keeps_it_in() {
    let folders: Folders = [
        ("0", 1, Some("inbox")),
        ("3", 2, Some("trash")),
        ("6", 3, Some("archive")),
        ("7", 4, Some("sent")),
        ("8", 5, Some("drafts")),
        ("custom", 6, None),
    ]
    .into_iter()
    .map(|(id, folder, role)| (id.to_owned(), (folder, role.map(str::to_owned))))
    .collect();
    let at = |labels: &[&str]| {
        let labels = labels.iter().map(|l| (*l).to_owned()).collect::<Vec<_>>();
        location(&labels, &folders).map(|(_, folder, _)| folder)
    };
    assert_eq!(at(&["0", "5", "10"]), Some(1));
    // In the Trash it is nowhere else, whatever else lists it.
    assert_eq!(at(&["2", "3", "5"]), Some(2));
    assert_eq!(at(&["5", "custom", "label"]), Some(6));
    // Mail sent to oneself is in the Inbox.
    assert_eq!(at(&["0", "2", "5", "7"]), Some(1));
    assert_eq!(at(&["2", "5", "7"]), Some(4));
    // "All sent" and "all drafts" alone still say what it is.
    assert_eq!(at(&["2", "5"]), Some(4));
    assert_eq!(at(&["1", "5"]), Some(5));
    // In no folder, as after its folder was deleted: with the archive.
    assert_eq!(at(&["5"]), Some(3));
}

#[test]
fn folder_paths_are_made_of_the_names_from_the_top() {
    let label = |id: &str, name: &str, parent: Option<&str>| Label {
        id: id.into(),
        name: name.into(),
        path: String::new(),
        kind: mail::LABEL_TYPE_FOLDER,
        color: String::new(),
        parent_id: parent.map(str::to_owned),
    };
    let labels = [
        label("a", "Work", None),
        label("b", "Clients", Some("a")),
        label("c", "Loop", Some("d")),
        label("d", "Back", Some("c")),
    ];
    let by_id = labels
        .iter()
        .map(|label| (label.id.as_str(), label))
        .collect::<HashMap<_, _>>();
    assert_eq!(folder_path("b", &by_id), "Work / Clients");
    assert_eq!(folder_path("a", &by_id), "Work");
    // A loop in what Proton sent ends instead of going round.
    assert_eq!(folder_path("c", &by_id), "Back / Loop");
}

#[tokio::test]
async fn listed_mail_is_stored_and_follows_proton_afterwards() {
    let (_dir, ctx, config) = fixture().await;
    persist(
        &ctx,
        &config,
        vec![message("m1", &["0", "5"]), message("m2", &["5", "custom"])],
        true,
        None,
        i64::MAX,
        true,
    )
    .await
    .unwrap();
    let first = row(&ctx, "m1").await.unwrap();
    assert_eq!(
        (first.0.as_str(), first.1, first.2),
        ("Inbox", false, false)
    );
    let second = row(&ctx, "m2").await.unwrap();
    assert_eq!(second.0, "Projects");
    // One conversation on Proton is one thread here.
    assert_eq!(first.3, second.3);

    // Read, starred and moved to the Trash elsewhere.
    let mut changed = message("m1", &["3", "5", "10"]);
    changed.unread = 0;
    persist(&ctx, &config, vec![changed], false, None, i64::MAX, true)
        .await
        .unwrap();
    let first = row(&ctx, "m1").await.unwrap();
    assert_eq!((first.0.as_str(), first.1, first.2), ("Trash", true, true));

    remove(&ctx, 1, vec!["m2".into()]).await.unwrap();
    assert!(row(&ctx, "m2").await.is_none());
    assert!(row(&ctx, "m1").await.is_some());
}

#[tokio::test]
async fn what_was_done_here_is_not_undone_by_an_older_listing() {
    let (_dir, ctx, config) = fixture().await;
    persist(
        &ctx,
        &config,
        vec![message("m1", &["0", "5"])],
        true,
        None,
        i64::MAX,
        true,
    )
    .await
    .unwrap();
    // Read here, and moved to the archive; neither has reached Proton yet.
    ctx.db
        .write(|conn| {
            let (id, thread): (i64, i64) = conn.query_row(
                "SELECT id, thread_id FROM messages WHERE proton_id = 'm1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let archive: i64 = conn.query_row(
                "SELECT id FROM folders WHERE account_id = 1 AND role = 'archive'",
                [],
                |row| row.get(0),
            )?;
            conn.execute(
                "UPDATE messages SET is_read = 1, folder_id = ?2 WHERE id = ?1",
                params![id, archive],
            )?;
            for kind in ["mark_read", "archive"] {
                repo::actions::enqueue(
                    conn,
                    1,
                    kind,
                    Some(id),
                    Some(thread),
                    &serde_json::json!({}),
                    None,
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    persist(
        &ctx,
        &config,
        vec![message("m1", &["0", "5"])],
        false,
        None,
        i64::MAX,
        true,
    )
    .await
    .unwrap();
    let kept = row(&ctx, "m1").await.unwrap();
    assert_eq!((kept.0.as_str(), kept.1), ("Archive", true));
}

#[tokio::test]
async fn mail_older_than_the_history_kept_is_not_stored() {
    let (_dir, ctx, config) = fixture().await;
    let after = 1_800_000_000_000 + 1;
    persist(
        &ctx,
        &config,
        vec![message("old", &["0", "5"])],
        true,
        Some(after),
        i64::MAX,
        true,
    )
    .await
    .unwrap();
    assert!(row(&ctx, "old").await.is_none());
}

#[tokio::test]
async fn protons_labels_become_labels_here_and_mark_their_mail() {
    let (_dir, ctx, config) = fixture().await;
    let label = Label {
        id: "label-1".into(),
        name: "Receipts".into(),
        path: String::new(),
        kind: mail::LABEL_TYPE_LABEL,
        color: "#ff0000".into(),
        parent_id: None,
    };
    let label_id = ctx
        .db
        .write(move |conn| {
            // One made here under the name first is the same label.
            let made = repo::labels::save(conn, None, "receipts", "#000000", 0, Some(1))?;
            let known = upsert_label(conn, 1, &label)?;
            assert_eq!(known, made.id);
            assert_eq!(upsert_label(conn, 1, &label)?, made.id);
            Ok(known)
        })
        .await
        .unwrap();
    persist(
        &ctx,
        &config,
        vec![message("m1", &["0", "5", "label-1"])],
        true,
        None,
        i64::MAX,
        true,
    )
    .await
    .unwrap();
    let labelled: bool = ctx
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM message_labels ml
                               JOIN messages m ON m.id = ml.message_id
                               WHERE m.proton_id = 'm1' AND ml.label_id = ?1)",
                params![label_id],
                |row| row.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(labelled);
}

#[test]
fn folders_keep_their_place_when_proton_renames_them() {
    let conn = crate::db::testutil::conn();
    crate::db::testutil::seed_account(&conn);
    conn.execute("DELETE FROM folders", []).unwrap();
    let first = upsert_folder(&conn, 1, "a", "Work", None, true).unwrap();
    assert_eq!(
        upsert_folder(&conn, 1, "a", "Office", None, true).unwrap(),
        first
    );
    // Another folder takes the old name.
    let second = upsert_folder(&conn, 1, "b", "Work", None, true).unwrap();
    assert_ne!(first, second);
    // And the two swap names.
    assert_eq!(
        upsert_folder(&conn, 1, "a", "Work", None, true).unwrap(),
        first
    );
    assert_eq!(
        upsert_folder(&conn, 1, "b", "Office", None, true).unwrap(),
        second
    );
    let paths: Vec<(String, String)> = conn
        .prepare("SELECT proton_id, path FROM folders ORDER BY proton_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        paths,
        [("a".into(), "Work".into()), ("b".into(), "Office".into())]
    );
}
