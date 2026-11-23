//! Proton Mail's mail API: labels, message metadata, full messages, actions
//! and the event stream, plus turning a decrypted Proton message back into
//! the RFC 5322 message the rest of the app stores.

use super::api::{ApiResult, Failure, Session};
use super::keys::Decrypter;
use crate::error::CoreError;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Proton's fixed label IDs.
pub mod system {
    pub const INBOX: &str = "0";
    pub const ALL_DRAFTS: &str = "1";
    pub const ALL_SENT: &str = "2";
    pub const TRASH: &str = "3";
    pub const SPAM: &str = "4";
    pub const ALL_MAIL: &str = "5";
    pub const ARCHIVE: &str = "6";
    pub const SENT: &str = "7";
    pub const DRAFTS: &str = "8";
    pub const STARRED: &str = "10";
}

/// Labels (type 1) can be many per message; folders (type 3) only one.
pub const LABEL_TYPE_LABEL: u8 = 1;
pub const LABEL_TYPE_FOLDER: u8 = 3;

/// A page of message metadata may hold at most this many messages.
pub const PAGE_SIZE: usize = 150;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Label {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(rename = "Type")]
    pub kind: u8,
    #[serde(default)]
    pub color: String,
    #[serde(rename = "ParentID", default)]
    pub parent_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Recipient {
    #[serde(default)]
    pub name: String,
    pub address: String,
}

/// What Proton tells about a message without its body.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Metadata {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(rename = "ConversationID", default)]
    pub conversation_id: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub sender: Recipient,
    #[serde(default)]
    pub to_list: Vec<Recipient>,
    #[serde(rename = "CCList", default)]
    pub cc_list: Vec<Recipient>,
    /// Seconds since the epoch.
    #[serde(default)]
    pub time: i64,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub unread: u8,
    #[serde(rename = "LabelIDs", default)]
    pub label_ids: Vec<String>,
    #[serde(rename = "ExternalID", default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub num_attachments: u32,
}

impl Metadata {
    pub fn is_unread(&self) -> bool {
        self.unread != 0
    }

    pub fn is_starred(&self) -> bool {
        self.label_ids.iter().any(|id| id == system::STARRED)
    }

    pub fn has_label(&self, label_id: &str) -> bool {
        self.label_ids.iter().any(|id| id == label_id)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AttachmentInfo {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "MIMEType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub disposition: Option<String>,
    /// Base64; the session key, encrypted to the address key.
    #[serde(default)]
    pub key_packets: String,
    /// The part's own MIME headers, such as `content-id`.
    #[serde(default)]
    pub headers: serde_json::Map<String, serde_json::Value>,
}

/// A message with its encrypted body.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    #[serde(flatten)]
    pub metadata: Metadata,
    /// The raw header block as it arrived.
    #[serde(default)]
    pub header: String,
    /// Armored OpenPGP message.
    pub body: String,
    #[serde(rename = "MIMEType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LabelsAnswer {
    labels: Vec<Label>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MetadataPage {
    pub total: u64,
    pub messages: Vec<Metadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MessageAnswer {
    message: Message,
}

pub async fn labels(session: &Session, kind: u8) -> ApiResult<Vec<Label>> {
    let answer: LabelsAnswer = session.get(&format!("/core/v4/labels?Type={kind}")).await?;
    Ok(answer.labels)
}

/// One page of the messages under a label, newest first.
pub async fn metadata_page(
    session: &Session,
    label_id: &str,
    page: usize,
) -> ApiResult<MetadataPage> {
    session
        .get(&format!(
            "/mail/v4/messages?LabelID={}&Page={page}&PageSize={PAGE_SIZE}&Sort=Time&Desc=1",
            percent_encoding::utf8_percent_encode(label_id, percent_encoding::NON_ALPHANUMERIC)
        ))
        .await
}

/// The metadata of the messages with these ids that still exist, at most
/// [`PAGE_SIZE`] of them.
pub async fn metadata_of(session: &Session, ids: &[String]) -> ApiResult<Vec<Metadata>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut path = format!("/mail/v4/messages?PageSize={PAGE_SIZE}");
    for id in ids {
        path.push_str("&ID[]=");
        path.extend(percent_encoding::utf8_percent_encode(
            id,
            percent_encoding::NON_ALPHANUMERIC,
        ));
    }
    let page: MetadataPage = session.get(&path).await?;
    Ok(page.messages)
}

/// One page of the messages matching `query` (already encoded parameters),
/// newest first.
pub async fn search_page(session: &Session, query: &str, page: u64) -> ApiResult<MetadataPage> {
    session
        .get(&format!(
            "/mail/v4/messages?{query}&Page={page}&PageSize={PAGE_SIZE}&Sort=Time&Desc=1"
        ))
        .await
}

/// Deletes every message in a folder, such as the Trash.
pub async fn empty_label(session: &Session, label_id: &str) -> ApiResult<()> {
    let _: serde_json::Value = session
        .delete(&format!(
            "/mail/v4/messages/empty?LabelID={}",
            percent_encoding::utf8_percent_encode(label_id, percent_encoding::NON_ALPHANUMERIC)
        ))
        .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LabelAnswer {
    label: Label,
}

/// Makes a label (type 1) or folder (type 3).
pub async fn create_label(
    session: &Session,
    kind: u8,
    name: &str,
    color: &str,
    parent_id: Option<&str>,
) -> ApiResult<Label> {
    let mut body = json!({ "Name": name, "Color": color, "Type": kind });
    if let Some(parent_id) = parent_id {
        body["ParentID"] = json!(parent_id);
    }
    let answer: LabelAnswer = session.post("/core/v4/labels", &body).await?;
    Ok(answer.label)
}

/// Renames a label or folder, keeping its color and place.
pub async fn rename_label(session: &Session, label: &Label, name: &str) -> ApiResult<Label> {
    let mut body = json!({ "Name": name, "Color": label.color });
    if let Some(parent_id) = &label.parent_id {
        body["ParentID"] = json!(parent_id);
    }
    let answer: LabelAnswer = session
        .put(
            &format!(
                "/core/v4/labels/{}",
                percent_encoding::utf8_percent_encode(
                    &label.id,
                    percent_encoding::NON_ALPHANUMERIC
                )
            ),
            &body,
        )
        .await?;
    Ok(answer.label)
}

pub async fn delete_label(session: &Session, id: &str) -> ApiResult<()> {
    let _: serde_json::Value = session
        .delete(&format!(
            "/core/v4/labels/{}",
            percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC)
        ))
        .await?;
    Ok(())
}

pub async fn message(session: &Session, id: &str) -> ApiResult<Message> {
    let answer: MessageAnswer = session
        .get(&format!(
            "/mail/v4/messages/{}",
            percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC)
        ))
        .await?;
    Ok(answer.message)
}

async fn attachment_data(session: &Session, id: &str) -> ApiResult<Vec<u8>> {
    let path = format!(
        "/mail/v4/attachments/{}",
        percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC)
    );
    let (status, bytes) = session.get_bytes(&path).await?;
    if status == 200 {
        return Ok(bytes);
    }
    Err(
        super::api::parse_answer::<serde_json::Value>(status, &bytes)
            .err()
            .unwrap_or_else(|| {
                Failure::Core(CoreError::Network(format!(
                    "Proton answered {status} for an attachment"
                )))
            }),
    )
}

/// Applies an action to messages: `read`, `unread`, `delete`.
pub async fn act(session: &Session, action: &str, ids: &[String]) -> ApiResult<()> {
    let _: serde_json::Value = session
        .put(
            &format!("/mail/v4/messages/{action}"),
            &json!({ "IDs": ids }),
        )
        .await?;
    Ok(())
}

/// Adds (`label`) or removes (`unlabel`) a label or folder.
pub async fn relabel(
    session: &Session,
    add: bool,
    label_id: &str,
    ids: &[String],
) -> ApiResult<()> {
    let action = if add { "label" } else { "unlabel" };
    let _: serde_json::Value = session
        .put(
            &format!("/mail/v4/messages/{action}"),
            &json!({ "LabelID": label_id, "IDs": ids }),
        )
        .await?;
    Ok(())
}

/// Fetches a message and its attachments, decrypts them and rebuilds the
/// message as it was sent.
pub async fn fetch_rfc822(
    session: &Session,
    keys: &dyn Decrypter,
    id: &str,
) -> ApiResult<(Metadata, Vec<u8>)> {
    let message = message(session, id).await?;
    let body = keys
        .decrypt_message(&message.metadata.address_id, &message.body)
        .map_err(|error| Failure::Core(CoreError::Network(error)))?;
    let mut attachments = Vec::new();
    // PGP/MIME messages carry their attachments inside the body.
    if !is_pgp_mime(&message.mime_type) {
        for info in &message.attachments {
            let data = attachment_data(session, &info.id).await?;
            let key_packets = B64.decode(&info.key_packets).map_err(|_| {
                Failure::Core(CoreError::Network(
                    "Proton sent an attachment key that is not base64".into(),
                ))
            })?;
            let plain = keys
                .decrypt_attachment(&message.metadata.address_id, &key_packets, &data)
                .map_err(|error| Failure::Core(CoreError::Network(error)))?;
            attachments.push((info.clone(), plain));
        }
    }
    let raw = build_rfc822(&message, &body, &attachments);
    Ok((message.metadata, raw))
}

fn is_pgp_mime(mime_type: &str) -> bool {
    mime_type.eq_ignore_ascii_case("multipart/mixed")
}

/// Headers that describe the body; the rebuilt message writes its own.
fn is_body_header(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name == "content-type" || name == "content-transfer-encoding" || name == "mime-version"
}

/// The original header block without the body-describing headers, unfolded
/// lines kept together, ending in CRLF.
fn kept_headers(header: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in header.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if !skipping {
                out.push_str(line);
                out.push_str("\r\n");
            }
            continue;
        }
        let name = line.split(':').next().unwrap_or_default();
        skipping = is_body_header(name);
        if !skipping {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out
}

fn wrap_base64(data: &[u8]) -> String {
    let encoded = B64.encode(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    out
}

/// A MIME parameter value, quoted.
fn quoted(value: &str) -> String {
    let clean: String = value
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '"' || c == '\\' { '_' } else { c })
        .collect();
    format!("\"{clean}\"")
}

fn header_value(info: &AttachmentInfo, name: &str) -> Option<String> {
    info.headers.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

/// Rebuilds the RFC 5322 message from Proton's parts.
pub fn build_rfc822(
    message: &Message,
    body: &[u8],
    attachments: &[(AttachmentInfo, Vec<u8>)],
) -> Vec<u8> {
    let mut out = kept_headers(&message.header);
    out.push_str("MIME-Version: 1.0\r\n");
    if is_pgp_mime(&message.mime_type) {
        // The decrypted body is a whole MIME entity with its own headers.
        let mut raw = out.into_bytes();
        let entity = String::from_utf8_lossy(body);
        let entity = entity.trim_start_matches(['\r', '\n']);
        // Normalise bare LF to CRLF so the header/body split stays valid.
        let normalised = entity.replace("\r\n", "\n").replace('\n', "\r\n");
        raw.extend_from_slice(normalised.as_bytes());
        return raw;
    }
    let content_type = if message.mime_type.is_empty() {
        "text/html"
    } else {
        message.mime_type.as_str()
    };
    let text_part = format!(
        "Content-Type: {content_type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        wrap_base64(body)
    );
    if attachments.is_empty() {
        out.push_str(&text_part);
        return out.into_bytes();
    }
    let boundary = format!(
        "flectar-proton-{}",
        message.metadata.id.replace(['=', '/', '+'], "")
    );
    let has_inline = attachments.iter().any(|(info, _)| {
        info.disposition
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case("inline"))
    });
    let multipart = if has_inline { "related" } else { "mixed" };
    out.push_str(&format!(
        "Content-Type: multipart/{multipart}; boundary=\"{boundary}\"\r\n\r\n"
    ));
    out.push_str(&format!("--{boundary}\r\n{text_part}"));
    for (info, data) in attachments {
        let mime = if info.mime_type.is_empty() {
            "application/octet-stream"
        } else {
            info.mime_type.as_str()
        };
        let disposition = info
            .disposition
            .as_deref()
            .filter(|d| d.eq_ignore_ascii_case("inline"))
            .unwrap_or("attachment");
        out.push_str(&format!(
            "--{boundary}\r\nContent-Type: {mime}; name={name}\r\nContent-Disposition: {disposition}; filename={name}\r\nContent-Transfer-Encoding: base64\r\n",
            name = quoted(&info.name),
        ));
        if let Some(content_id) = header_value(info, "content-id") {
            let content_id: String = content_id.chars().filter(|c| !c.is_control()).collect();
            out.push_str(&format!("Content-ID: {content_id}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&wrap_base64(data));
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out.into_bytes()
}

/// One change from Proton's event stream.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageEvent {
    #[serde(rename = "ID")]
    pub id: String,
    /// 0 deleted, 1 created, 2 updated, 3 flags or labels changed.
    pub action: u8,
    #[serde(default)]
    pub message: Option<Metadata>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LabelEvent {
    #[serde(rename = "ID")]
    pub id: String,
    pub action: u8,
    #[serde(default)]
    pub label: Option<Label>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Events {
    #[serde(rename = "EventID")]
    pub event_id: String,
    /// More events wait; ask again at once.
    #[serde(default)]
    pub more: u8,
    /// Proton lost track; everything must be fetched again.
    #[serde(default)]
    pub refresh: u8,
    #[serde(default)]
    pub messages: Vec<MessageEvent>,
    #[serde(default)]
    pub labels: Vec<LabelEvent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LatestEvent {
    #[serde(rename = "EventID")]
    event_id: String,
}

pub async fn latest_event(session: &Session) -> ApiResult<String> {
    let answer: LatestEvent = session.get("/core/v4/events/latest").await?;
    Ok(answer.event_id)
}

pub async fn events_since(session: &Session, event_id: &str) -> ApiResult<Events> {
    session
        .get(&format!(
            "/core/v4/events/{}",
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC)
        ))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(mime_type: &str) -> Message {
        Message {
            metadata: Metadata {
                id: "abc/def==".into(),
                address_id: "addr".into(),
                conversation_id: "conv".into(),
                subject: "Hello".into(),
                sender: Recipient {
                    name: "Ann".into(),
                    address: "ann@example.com".into(),
                },
                to_list: vec![],
                cc_list: vec![],
                time: 1_700_000_000,
                size: 10,
                unread: 1,
                label_ids: vec![system::INBOX.into(), system::STARRED.into()],
                external_id: Some("<id@example.com>".into()),
                num_attachments: 0,
            },
            header: "From: Ann <ann@example.com>\r\nTo: dan@proton.me\r\nSubject: Hello\r\nContent-Type: text/html;\r\n charset=utf-8\r\nMIME-Version: 1.0\r\nMessage-ID: <id@example.com>\r\n".into(),
            body: String::new(),
            mime_type: mime_type.into(),
            attachments: vec![],
        }
    }

    #[test]
    fn flags_come_from_unread_and_the_starred_label() {
        let message = message("text/html");
        assert!(message.metadata.is_unread());
        assert!(message.metadata.is_starred());
        assert!(message.metadata.has_label(system::INBOX));
    }

    #[test]
    fn a_plain_body_is_rebuilt_with_the_original_headers() {
        let raw = build_rfc822(&message("text/html"), "<p>Grüße</p>".as_bytes(), &[]);
        let raw = String::from_utf8(raw).unwrap();
        assert!(raw.starts_with("From: Ann <ann@example.com>\r\n"));
        assert!(raw.contains("Message-ID: <id@example.com>\r\n"));
        // The original body headers, including the folded line, are replaced.
        assert_eq!(raw.matches("Content-Type").count(), 1);
        assert!(!raw.contains(" charset=utf-8\r\nMIME"));
        assert!(raw.contains("Content-Type: text/html; charset=utf-8\r\n"));
        let body = raw.split("\r\n\r\n").nth(1).unwrap().replace("\r\n", "");
        assert_eq!(B64.decode(body).unwrap(), "<p>Grüße</p>".as_bytes());
    }

    #[test]
    fn attachments_become_parts_with_their_content_id() {
        let mut headers = serde_json::Map::new();
        headers.insert("content-id".into(), "<img1>".into());
        let inline = AttachmentInfo {
            id: "att".into(),
            name: "pic \"1\".png".into(),
            mime_type: "image/png".into(),
            disposition: Some("inline".into()),
            key_packets: String::new(),
            headers,
        };
        let raw = build_rfc822(
            &message("text/html"),
            b"<img src=cid:img1>",
            &[(inline, vec![1, 2, 3])],
        );
        let raw = String::from_utf8(raw).unwrap();
        assert!(
            raw.contains("Content-Type: multipart/related; boundary=\"flectar-proton-abcdef\"")
        );
        assert!(raw.contains("Content-Disposition: inline; filename=\"pic _1_.png\""));
        assert!(raw.contains("Content-ID: <img1>\r\n"));
        assert!(raw.contains(&B64.encode([1, 2, 3])));
        assert!(raw.trim_end().ends_with("--flectar-proton-abcdef--"));
    }

    #[test]
    fn a_pgp_mime_body_keeps_its_own_entity_headers() {
        let entity = "Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b--\n";
        let raw = build_rfc822(&message("multipart/mixed"), entity.as_bytes(), &[]);
        let raw = String::from_utf8(raw).unwrap();
        assert!(raw.contains(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
        ));
        assert_eq!(raw.matches("Content-Type: multipart").count(), 1);
    }

    #[test]
    fn events_parse() {
        let events: Events = serde_json::from_str(
            r#"{"Code":1000,"EventID":"e2","More":0,"Refresh":0,
            "Messages":[{"ID":"m1","Action":0},{"ID":"m2","Action":3,"Message":{"ID":"m2","AddressID":"a","LabelIDs":["0","10"],"Unread":0}}],
            "Labels":[{"ID":"l1","Action":1,"Label":{"ID":"l1","Name":"Work","Type":1}}]}"#,
        )
        .unwrap();
        assert_eq!(events.event_id, "e2");
        assert_eq!(events.messages.len(), 2);
        assert!(events.messages[1].message.as_ref().unwrap().is_starred());
        assert_eq!(events.labels[0].label.as_ref().unwrap().name, "Work");
    }
}
