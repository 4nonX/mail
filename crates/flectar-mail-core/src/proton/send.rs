//! Writing to a Proton account: drafts, their attachments, sending, read
//! receipts and importing whole messages.
//!
//! Proton never sees a message in the clear from its own apps. A draft's
//! body and attachments are encrypted to the sending address's key; sending
//! hands each recipient the session keys, encrypted to their key when they
//! have one and in the clear when their mail server has to read the message.

use super::api::{ApiError, Failure, FormPart, Session};
use super::keys::{Address, Decrypter, SessionKey};
use super::mail::{self, AttachmentInfo, Message, system};
use super::sync::Connected;
use crate::db::repo;
use crate::error::{CoreError, Result};
use crate::events::CoreEvent;
use crate::models::{AccountConfig, now_ms, roles};
use crate::sync::engine::SyncCtx;
use base64::Engine as _;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How a recipient gets the message.
const SCHEME_INTERNAL: u32 = 1;
const SCHEME_CLEAR: u32 = 4;
const SCHEME_PGP_MIME: u32 = 8;
const SIGNATURE_NONE: u32 = 0;
const SIGNATURE_DETACHED: u32 = 1;
/// Proton's own users.
const RECIPIENT_INTERNAL: u32 = 1;
/// A key that may be encrypted to.
const KEY_ENCRYPTS: u32 = 2;
/// Proton answers with this when a message id names nothing.
const CODE_NOT_FOUND: i64 = 2501;
const CODE_ALREADY_SENT: i64 = 15034;

const FLAG_RECEIVED: u32 = 1;
const FLAG_SENT: u32 = 2;

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn crypto(error: String) -> CoreError {
    CoreError::Other(error)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MessageAnswer {
    message: Message,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AttachmentAnswer {
    attachment: UploadedAttachment,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UploadedAttachment {
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecipientKeys {
    #[serde(default)]
    recipient_type: u32,
    #[serde(default)]
    keys: Vec<RecipientKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecipientKey {
    #[serde(default)]
    flags: u32,
    public_key: String,
}

/// A draft as Proton holds it after [`save_draft`].
pub(crate) struct Draft {
    pub proton_id: String,
    address_id: String,
    /// The body Proton holds, before encryption.
    body: Vec<u8>,
    mime_type: &'static str,
    /// The whole message as other mail systems read it.
    raw: Vec<u8>,
    /// Without angle brackets.
    message_id: String,
    recipients: Vec<String>,
    /// Each attachment Proton holds, with the key that encrypts it.
    attachments: Vec<(String, SessionKey)>,
}

/// The address of the account a message is sent from.
fn sending_address<'a>(addresses: &'a [Address], from: &str) -> Result<&'a Address> {
    addresses
        .iter()
        .find(|address| {
            address.email.eq_ignore_ascii_case(from) && address.status == 1 && address.send == 1
        })
        .ok_or_else(|| {
            CoreError::Other(format!(
                "{from} is not an address this Proton account can send from"
            ))
        })
}

fn recipients_json(addresses: &[crate::models::Address]) -> Value {
    Value::Array(
        addresses
            .iter()
            .map(|address| {
                json!({
                    "Name": address.name.clone().unwrap_or_else(|| address.email.clone()),
                    "Address": address.email,
                })
            })
            .collect(),
    )
}

struct LocalAttachment {
    name: String,
    mime_type: String,
    content_id: Option<String>,
    inline: bool,
    bytes: Vec<u8>,
}

/// Saves a draft kept here to Proton: its text, and its attachments when
/// they differ from the ones Proton has. `exact` uploads the attachments
/// again whatever Proton has, as sending does.
pub(crate) async fn save_draft(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &Connected,
    draft_id: i64,
    exact: bool,
) -> Result<Draft> {
    let account_id = config.id;
    let outgoing = crate::queue::build_outgoing(&ctx.db, &ctx.paths, account_id, draft_id).await?;
    let message_id = outgoing.message_id.trim_matches(['<', '>']).to_owned();
    let stable_id = message_id.clone();
    let (detail, bcc, in_reply_to, existing) = ctx
        .db
        .write(move |conn| {
            conn.execute(
                "UPDATE messages SET message_id = ?2 WHERE id = ?1 AND is_draft = 1",
                params![draft_id, stable_id],
            )?;
            let detail = repo::messages::detail(conn, draft_id)?;
            let (bcc_json, proton_id): (String, Option<String>) = conn.query_row(
                "SELECT bcc_json, proton_id FROM messages WHERE id = ?1",
                params![draft_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let (_, in_reply_to) = repo::messages::draft_reply_headers(conn, draft_id)?;
            let bcc = serde_json::from_str::<Vec<crate::models::Address>>(&bcc_json)?;
            Ok((detail, bcc, in_reply_to, proton_id))
        })
        .await?;
    let address = sending_address(&c.addresses, &detail.from.email)?;
    let parsed = crate::mime::parse_message(&outgoing.raw)?;
    let (body, mime_type) = match &parsed.html {
        Some(html) => (html.clone().into_bytes(), "text/html"),
        None => (
            parsed.text.clone().unwrap_or_default().into_bytes(),
            "text/plain",
        ),
    };
    let mut local = Vec::new();
    for attachment in &parsed.attachments {
        let (bytes, _) = crate::mime::extract_attachment(&outgoing.raw, &attachment.part_id)?;
        local.push(LocalAttachment {
            name: attachment
                .filename
                .clone()
                .unwrap_or_else(|| "attachment".into()),
            mime_type: attachment
                .mime_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".into()),
            content_id: attachment.content_id.clone(),
            inline: attachment.is_inline,
            bytes,
        });
    }
    let sealed = c.keys.encrypt_message(&address.id, &body).map_err(crypto)?;
    let message = json!({
        "Subject": detail.subject,
        "Sender": {
            "Name": detail.from.name.clone().unwrap_or_else(|| address.display_name.clone()),
            "Address": address.email,
        },
        "ToList": recipients_json(&detail.to),
        "CCList": recipients_json(&detail.cc),
        "BCCList": recipients_json(&bcc),
        "Body": sealed.armored,
        "MIMEType": mime_type,
        "ExternalID": message_id,
        "Unread": 0,
    });
    let updated = match &existing {
        Some(proton_id) => {
            match c
                .session
                .put::<MessageAnswer>(
                    &format!("/mail/v4/messages/{}", encoded(proton_id)),
                    &json!({ "Message": message }),
                )
                .await
            {
                Ok(answer) => Some(answer.message),
                // The draft was deleted elsewhere: it is made again.
                Err(Failure::Api(ApiError {
                    code: CODE_NOT_FOUND,
                    ..
                })) => None,
                Err(failure) => return Err(failure.into()),
            }
        }
        None => None,
    };
    let remote = match updated {
        Some(remote) => remote,
        None => {
            let mut request = json!({ "Message": message });
            // A reply is filed with the conversation it answers.
            if let Some(parent) = in_reply_to {
                let parent = parent.trim_matches(['<', '>']).to_owned();
                let parent_id = ctx
                    .db
                    .read(move |conn| {
                        Ok(conn
                            .query_row(
                                "SELECT proton_id FROM messages
                                 WHERE account_id = ?1 AND message_id = ?2
                                   AND proton_id IS NOT NULL LIMIT 1",
                                params![account_id, parent],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()?)
                    })
                    .await?;
                if let Some(parent_id) = parent_id {
                    request["ParentID"] = json!(parent_id);
                    request["Action"] = json!(0);
                }
            }
            let created: MessageAnswer = c.session.post("/mail/v4/messages", &request).await?;
            created.message
        }
    };
    let proton_id = remote.metadata.id.clone();
    let linked = proton_id.clone();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "UPDATE messages SET proton_id = ?2 WHERE id = ?1",
                params![draft_id, linked],
            )?;
            Ok(())
        })
        .await?;

    let mut held = remote.attachments.clone();
    if exact || !same_attachments(&held, &local) {
        for attachment in &held {
            delete_attachment(&c.session, &attachment.id).await?;
        }
        held.clear();
        for attachment in &local {
            let sealed = c
                .keys
                .encrypt_attachment(&address.id, &attachment.bytes)
                .map_err(crypto)?;
            let disposition = if attachment.inline {
                "inline"
            } else {
                "attachment"
            };
            let content_id = attachment.content_id.clone().unwrap_or_default();
            let answer: AttachmentAnswer = c
                .session
                .post_form(
                    "/mail/v4/attachments",
                    &[
                        FormPart {
                            name: "Filename",
                            file: None,
                            data: attachment.name.as_bytes(),
                        },
                        FormPart {
                            name: "MessageID",
                            file: None,
                            data: proton_id.as_bytes(),
                        },
                        FormPart {
                            name: "MIMEType",
                            file: None,
                            data: attachment.mime_type.as_bytes(),
                        },
                        FormPart {
                            name: "Disposition",
                            file: None,
                            data: disposition.as_bytes(),
                        },
                        FormPart {
                            name: "ContentID",
                            file: None,
                            data: content_id.as_bytes(),
                        },
                        FormPart {
                            name: "KeyPackets",
                            file: Some("application/octet-stream"),
                            data: &sealed.key_packets,
                        },
                        FormPart {
                            name: "DataPacket",
                            file: Some("application/octet-stream"),
                            data: &sealed.data_packet,
                        },
                        FormPart {
                            name: "Signature",
                            file: Some("application/octet-stream"),
                            data: &sealed.signature,
                        },
                    ],
                )
                .await?;
            held.push(AttachmentInfo {
                id: answer.attachment.id,
                name: attachment.name.clone(),
                mime_type: attachment.mime_type.clone(),
                disposition: Some(disposition.into()),
                key_packets: B64.encode(&sealed.key_packets),
                headers: Default::default(),
            });
        }
    }
    let mut attachments = Vec::new();
    for attachment in &held {
        let key_packets = B64.decode(&attachment.key_packets).map_err(|_| {
            CoreError::Network("Proton sent an attachment key that is not base64".into())
        })?;
        attachments.push((
            attachment.id.clone(),
            c.keys
                .session_key(&address.id, &key_packets)
                .map_err(crypto)?,
        ));
    }
    Ok(Draft {
        proton_id,
        address_id: address.id.clone(),
        body,
        mime_type,
        raw: outgoing.raw,
        message_id,
        recipients: outgoing.recipients,
        attachments,
    })
}

/// Whether Proton holds the draft's attachments already, by name and count.
fn same_attachments(held: &[AttachmentInfo], local: &[LocalAttachment]) -> bool {
    let mut held = held.iter().map(|a| a.name.as_str()).collect::<Vec<_>>();
    let mut local = local.iter().map(|a| a.name.as_str()).collect::<Vec<_>>();
    held.sort_unstable();
    local.sort_unstable();
    held == local
}

async fn delete_attachment(session: &Session, id: &str) -> Result<()> {
    match session
        .delete::<Value>(&format!("/mail/v4/attachments/{}", encoded(id)))
        .await
    {
        Ok(_)
        | Err(Failure::Api(ApiError {
            code: CODE_NOT_FOUND,
            ..
        })) => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}

/// Deletes a draft or message for good. One that is gone already is done.
pub(crate) async fn delete_message(session: &Session, proton_id: &str) -> Result<()> {
    match mail::act(session, "delete", &[proton_id.to_owned()]).await {
        Ok(())
        | Err(Failure::Api(ApiError {
            code: CODE_NOT_FOUND,
            ..
        })) => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}

/// How one recipient gets the message.
enum Route {
    /// A Proton user: the session keys go encrypted to their key.
    Internal(String),
    /// Someone elsewhere who publishes a key: a PGP/MIME message.
    PgpMime(String),
    /// Someone elsewhere without a key: their mail server reads the message.
    Clear,
}

async fn route(session: &Session, email: &str) -> Result<Route> {
    let keys: RecipientKeys = session
        .get(&format!("/core/v4/keys?Email={}", encoded(email)))
        .await?;
    let key = keys
        .keys
        .into_iter()
        .find(|key| key.flags & KEY_ENCRYPTS != 0)
        .map(|key| key.public_key);
    Ok(match (keys.recipient_type, key) {
        (RECIPIENT_INTERNAL, Some(key)) => Route::Internal(key),
        (RECIPIENT_INTERNAL, None) => {
            return Err(CoreError::Other(format!(
                "{email} has no key Proton can encrypt to"
            )));
        }
        (_, Some(key)) => Route::PgpMime(key),
        (_, None) => Route::Clear,
    })
}

/// The part of a message a PGP/MIME recipient gets encrypted: its content
/// headers and its body, without the headers that travel outside.
fn mime_entity(raw: &[u8]) -> Vec<u8> {
    let (headers, body) = split_message(raw);
    let mut entity = Vec::new();
    for header in headers {
        if is_content_header(&header) {
            entity.extend_from_slice(&header);
        }
    }
    entity.extend_from_slice(b"\r\n");
    entity.extend_from_slice(body);
    entity
}

fn is_content_header(header: &[u8]) -> bool {
    header.len() >= 8 && header[..8].eq_ignore_ascii_case(b"content-")
}

/// A message's header fields, each with its folded lines and line ending,
/// and its body.
fn split_message(raw: &[u8]) -> (Vec<Vec<u8>>, &[u8]) {
    let mut headers: Vec<Vec<u8>> = Vec::new();
    let mut position = 0;
    while position < raw.len() {
        let end = raw[position..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(raw.len(), |offset| position + offset + 1);
        let line = &raw[position..end];
        position = end;
        if line == b"\r\n" || line == b"\n" {
            return (headers, &raw[position..]);
        }
        match headers.last_mut() {
            Some(last)
                if line
                    .first()
                    .is_some_and(|byte| *byte == b' ' || *byte == b'\t') =>
            {
                last.extend_from_slice(line);
            }
            _ => headers.push(line.to_vec()),
        }
    }
    (headers, &[])
}

fn package(mime_type: &str, body: &[u8]) -> Value {
    json!({
        "Addresses": {},
        "MIMEType": mime_type,
        "Type": 0,
        "Body": B64.encode(body),
    })
}

fn clear_key(key: &SessionKey) -> Value {
    json!({ "Key": B64.encode(&key.key), "Algorithm": key.algorithm })
}

/// The packages of a send: who gets which form of the message, and the keys
/// each needs to read it.
fn packages(
    keys: &dyn Decrypter,
    draft: &Draft,
    routes: &BTreeMap<String, Route>,
) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    let direct = routes
        .iter()
        .filter(|(_, route)| !matches!(route, Route::PgpMime(_)))
        .collect::<Vec<_>>();
    if !direct.is_empty() {
        let sealed = keys
            .encrypt_message(&draft.address_id, &draft.body)
            .map_err(crypto)?;
        let mut package = package(draft.mime_type, &sealed.data_packet);
        let mut kinds = 0;
        for (email, route) in direct {
            let recipient = match route {
                Route::Internal(public_key) => {
                    kinds |= SCHEME_INTERNAL;
                    let mut attachment_keys = serde_json::Map::new();
                    for (id, key) in &draft.attachments {
                        attachment_keys.insert(
                            id.clone(),
                            json!(
                                B64.encode(keys.seal_session_key(key, public_key).map_err(crypto)?)
                            ),
                        );
                    }
                    json!({
                        "Type": SCHEME_INTERNAL,
                        "Signature": SIGNATURE_DETACHED,
                        "BodyKeyPacket": B64.encode(
                            keys.seal_session_key(&sealed.session_key, public_key)
                                .map_err(crypto)?
                        ),
                        "AttachmentKeyPackets": attachment_keys,
                    })
                }
                Route::Clear => {
                    kinds |= SCHEME_CLEAR;
                    json!({ "Type": SCHEME_CLEAR, "Signature": SIGNATURE_NONE })
                }
                Route::PgpMime(_) => unreachable!("filtered above"),
            };
            package["Addresses"][email.as_str()] = recipient;
        }
        package["Type"] = json!(kinds);
        if kinds & SCHEME_CLEAR != 0 {
            package["BodyKey"] = clear_key(&sealed.session_key);
            let mut attachment_keys = serde_json::Map::new();
            for (id, key) in &draft.attachments {
                attachment_keys.insert(id.clone(), clear_key(key));
            }
            package["AttachmentKeys"] = Value::Object(attachment_keys);
        }
        out.push(package);
    }
    let encrypted = routes
        .iter()
        .filter_map(|(email, route)| match route {
            Route::PgpMime(key) => Some((email, key)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !encrypted.is_empty() {
        let sealed = keys
            .encrypt_message(&draft.address_id, &mime_entity(&draft.raw))
            .map_err(crypto)?;
        let mut package = package("multipart/mixed", &sealed.data_packet);
        for (email, public_key) in encrypted {
            package["Addresses"][email.as_str()] = json!({
                "Type": SCHEME_PGP_MIME,
                "Signature": SIGNATURE_DETACHED,
                "BodyKeyPacket": B64.encode(
                    keys.seal_session_key(&sealed.session_key, public_key)
                        .map_err(crypto)?
                ),
            });
        }
        package["Type"] = json!(SCHEME_PGP_MIME);
        out.push(package);
    }
    Ok(out)
}

/// Whether Proton has sent the message with this id.
async fn already_sent(session: &Session, proton_id: &str) -> Result<bool> {
    Ok(mail::metadata_of(session, &[proton_id.to_owned()])
        .await?
        .first()
        .is_some_and(|message| message.has_label(system::ALL_SENT)))
}

/// Sends a draft kept here through Proton and files it as sent.
pub(crate) async fn send(
    ctx: &SyncCtx,
    config: &AccountConfig,
    c: &Connected,
    action: &repo::actions::PendingAction,
) -> Result<()> {
    let draft_id = action.payload["draftId"]
        .as_i64()
        .or(action.message_id)
        .ok_or_else(|| CoreError::Other("the send names no draft".into()))?;
    let policy = match action.payload.get("mailSecurity") {
        Some(value) => serde_json::from_value::<crate::mail_security::MailSecurity>(value.clone())?,
        None => config.settings.security.clone(),
    };
    if policy.enabled() {
        return Err(CoreError::Other(
            "Proton signs and encrypts this account's mail itself. Turn off mail security for this message to send it."
                .into(),
        ));
    }
    let (linked, asks_receipt): (Option<String>, bool) = ctx
        .db
        .read(move |conn| {
            let linked = conn
                .query_row(
                    "SELECT proton_id FROM messages WHERE id = ?1",
                    params![draft_id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            Ok((
                linked,
                !repo::messages::receipt_to(conn, draft_id)?.is_empty(),
            ))
        })
        .await?;
    // Proton writes a sent message's headers itself, and has none for this.
    if asks_receipt {
        return Err(CoreError::Other(
            "Proton can't ask for a read receipt. Turn the request off to send this message."
                .into(),
        ));
    }
    // An earlier try may have gone through without its answer arriving.
    if let Some(proton_id) = &linked
        && action.attempts > 0
        && already_sent(&c.session, proton_id).await?
    {
        let outgoing =
            crate::queue::build_outgoing(&ctx.db, &ctx.paths, config.id, draft_id).await?;
        return finish_send(
            ctx,
            config,
            draft_id,
            outgoing.message_id.trim_matches(['<', '>']).to_owned(),
            outgoing.raw,
        )
        .await;
    }
    let draft = save_draft(ctx, config, c, draft_id, true).await?;
    if draft.recipients.is_empty() {
        return Err(CoreError::Other("the message has no recipients".into()));
    }
    let mut routes = BTreeMap::new();
    for email in &draft.recipients {
        let email = email.trim().to_ascii_lowercase();
        if !routes.contains_key(&email) {
            let route = route(&c.session, &email).await?;
            routes.insert(email, route);
        }
    }
    let packages = packages(c.keys.as_ref(), &draft, &routes)?;
    let sent = c
        .session
        .post::<Value>(
            &format!("/mail/v4/messages/{}", encoded(&draft.proton_id)),
            &json!({ "Packages": packages }),
        )
        .await;
    match sent {
        Ok(_)
        | Err(Failure::Api(ApiError {
            code: CODE_ALREADY_SENT,
            ..
        })) => {}
        // Without an answer the message may or may not have gone out.
        Err(Failure::Core(error @ (CoreError::Offline | CoreError::Network(_)))) => {
            return Err(CoreError::SendUncertain(error.to_string()));
        }
        Err(failure) => return Err(failure.into()),
    }
    finish_send(ctx, config, draft_id, draft.message_id, draft.raw).await
}

/// Files a sent draft here as the sent message it now is on Proton.
async fn finish_send(
    ctx: &SyncCtx,
    config: &AccountConfig,
    draft_id: i64,
    message_id: String,
    raw: Vec<u8>,
) -> Result<()> {
    let account_id = config.id;
    let dir = ctx.paths.mail_dir(account_id);
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{draft_id}.proton.eml"));
    crate::file_io::write_atomic(&path, &raw, "sent Proton message").await?;
    let raw_path = path.to_string_lossy().into_owned();
    let sent_at = now_ms();
    let (thread_id, staged_paths) = ctx
        .db
        .write(move |conn| {
            let tx = conn.transaction()?;
            let sent_folder = repo::folders::by_role(&tx, account_id, roles::SENT)?.map(|f| f.id);
            tx.execute(
                "UPDATE messages SET is_draft = 0, is_outgoing = 1, is_read = 1,
                        message_id = ?2, raw_path = ?3,
                        folder_id = COALESCE(?4, folder_id), uid = NULL, date = ?5
                 WHERE id = ?1",
                params![draft_id, message_id, raw_path, sent_folder, sent_at],
            )?;
            tx.execute(
                "DELETE FROM drafts_meta WHERE message_id = ?1",
                params![draft_id],
            )?;
            let staged_paths = repo::messages::take_draft_attachment_paths(&tx, draft_id)?;
            let thread_id = repo::messages::get_row(&tx, draft_id)?.and_then(|row| row.thread_id);
            if let Some(thread_id) = thread_id {
                repo::threads::recompute(&tx, thread_id)?;
            }
            repo::search::index_message(&tx, draft_id)?;
            repo::contacts::record_sent_recipients(&tx, account_id, draft_id, sent_at)?;
            tx.commit()?;
            Ok((thread_id, staged_paths))
        })
        .await?;
    for path in staged_paths {
        crate::remove_staged_attachment(&ctx.paths.draft_attachments_dir(), &path).await;
    }
    if let Some(thread_id) = thread_id {
        ctx.bus.emit(CoreEvent::MailUpdated {
            thread_ids: vec![thread_id],
        });
    }
    Ok(())
}

/// Has Proton send the read receipt the sender of a message asked for.
pub(crate) async fn read_receipt(session: &Session, proton_id: &str) -> Result<()> {
    match session
        .post::<Value>(
            &format!("/mail/v4/messages/{}/receipt", encoded(proton_id)),
            &json!({}),
        )
        .await
    {
        Ok(_)
        | Err(Failure::Api(ApiError {
            code: CODE_NOT_FOUND,
            ..
        })) => Ok(()),
        Err(failure) => Err(failure.into()),
    }
}

/// A whole message as Proton keeps imported mail: its headers as they are,
/// and its content as one encrypted PGP/MIME part.
pub(crate) fn encrypt_rfc822(
    keys: &dyn Decrypter,
    address_id: &str,
    raw: &[u8],
) -> Result<Vec<u8>> {
    let (headers, body) = split_message(raw);
    let mut inner = Vec::new();
    let mut outer = Vec::new();
    for header in &headers {
        if is_content_header(header) {
            inner.extend_from_slice(header);
        } else if !(header.len() >= 13 && header[..13].eq_ignore_ascii_case(b"mime-version:")) {
            outer.extend_from_slice(header);
        }
    }
    if inner.is_empty() {
        inner.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    }
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(body);
    let sealed = keys.encrypt_message(address_id, &inner).map_err(crypto)?;
    let boundary = format!("flectar-{:032x}", rand::random::<u128>());
    outer.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    outer.extend_from_slice(
        sealed
            .armored
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .as_bytes(),
    );
    outer.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(outer)
}

/// What became of an import.
pub(crate) enum Imported {
    Stored,
    /// Proton refused the message, for the reason given.
    Refused(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImportAnswer {
    #[serde(default)]
    responses: Vec<ImportResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImportResponse {
    response: ImportResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImportResult {
    #[serde(default)]
    code: i64,
    #[serde(rename = "MessageID", default)]
    message_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Puts a whole message into one of the account's folders.
pub(crate) async fn import(
    c: &Connected,
    folder_proton_id: &str,
    raw: &[u8],
    seen: bool,
    flagged: bool,
    sent: bool,
) -> Result<Imported> {
    let address = c
        .addresses
        .iter()
        .filter(|address| address.status == 1)
        .min_by_key(|address| address.order)
        .ok_or_else(|| CoreError::Other("the Proton account has no address".into()))?;
    let encrypted = encrypt_rfc822(c.keys.as_ref(), &address.id, raw)?;
    let mut labels = vec![folder_proton_id.to_owned()];
    if flagged {
        labels.push(system::STARRED.to_owned());
    }
    let metadata = json!({
        "0": {
            "AddressID": address.id,
            "LabelIDs": labels,
            "Unread": u8::from(!seen),
            "Flags": if sent { FLAG_SENT } else { FLAG_RECEIVED },
        }
    })
    .to_string();
    let answer = c
        .session
        .post_form::<ImportAnswer>(
            "/mail/v4/messages/import",
            &[
                FormPart {
                    name: "Metadata",
                    file: None,
                    data: metadata.as_bytes(),
                },
                FormPart {
                    name: "0",
                    file: Some("message/rfc822"),
                    data: &encrypted,
                },
            ],
        )
        .await;
    let answer = match answer {
        Ok(answer) => answer,
        // What Proton answers for with the request's own fault, it refused.
        Err(Failure::Api(error)) if (400..500).contains(&error.status) && error.status != 401 => {
            return Ok(Imported::Refused(error.message));
        }
        Err(failure) => return Err(failure.into()),
    };
    let Some(result) = answer.responses.into_iter().next().map(|r| r.response) else {
        return Err(CoreError::Network(
            "Proton did not say what became of the imported message".into(),
        ));
    };
    match (result.code, result.message_id) {
        (1000, Some(_)) => Ok(Imported::Stored),
        (code, _) => {
            Ok(Imported::Refused(result.error.unwrap_or_else(|| {
                format!("Proton answered with code {code}")
            })))
        }
    }
}

/// The folders' Proton ids by their ids here.
pub(crate) fn folder_proton_id(
    conn: &rusqlite::Connection,
    folder_id: i64,
) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT proton_id FROM folders WHERE id = ?1",
            params![folder_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten())
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod tests;
