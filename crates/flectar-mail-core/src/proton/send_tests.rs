use super::*;
use crate::proton::keys::Sealed;

/// Keys that "encrypt" by wrapping, so what went where can be read back.
struct Keys;

impl Decrypter for Keys {
    fn decrypt_message(&self, _: &str, armored: &str) -> std::result::Result<Vec<u8>, String> {
        Ok(armored.as_bytes().to_vec())
    }
    fn decrypt_attachment(
        &self,
        _: &str,
        _: &[u8],
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    fn address_ids(&self) -> Vec<String> {
        vec!["address".into()]
    }
    fn encrypt_message(&self, _: &str, plain: &[u8]) -> std::result::Result<Sealed, String> {
        Ok(Sealed {
            armored: format!(
                "-----BEGIN PGP MESSAGE-----\n{}\n-----END PGP MESSAGE-----",
                B64.encode(plain)
            ),
            key_packets: b"own-key-packets".to_vec(),
            data_packet: [b"data:".as_slice(), plain].concat(),
            signature: b"signature".to_vec(),
            session_key: SessionKey {
                key: b"body-key".to_vec(),
                algorithm: "aes256",
            },
        })
    }
    fn encrypt_attachment(&self, id: &str, plain: &[u8]) -> std::result::Result<Sealed, String> {
        self.encrypt_message(id, plain)
    }
    fn session_key(&self, _: &str, _: &[u8]) -> std::result::Result<SessionKey, String> {
        Ok(SessionKey {
            key: b"attachment-key".to_vec(),
            algorithm: "aes256",
        })
    }
    fn seal_session_key(
        &self,
        key: &SessionKey,
        public_key: &str,
    ) -> std::result::Result<Vec<u8>, String> {
        Ok([key.key.as_slice(), b" for ", public_key.as_bytes()].concat())
    }
}

const RAW: &[u8] = b"From: Me <me@proton.test>\r\nTo: you@example.test\r\nSubject: Hello\r\n there\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed;\r\n boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nHi\r\n--b--\r\n";

fn draft() -> Draft {
    Draft {
        proton_id: "draft".into(),
        address_id: "address".into(),
        body: b"<p>Hi</p>".to_vec(),
        mime_type: "text/html",
        raw: RAW.to_vec(),
        message_id: "id@proton.test".into(),
        recipients: Vec::new(),
        attachments: vec![(
            "attachment".into(),
            SessionKey {
                key: b"attachment-key".to_vec(),
                algorithm: "aes256",
            },
        )],
    }
}

fn decoded(value: &Value) -> String {
    String::from_utf8(B64.decode(value.as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn headers_split_from_the_body_with_their_folded_lines() {
    let (headers, body) = split_message(RAW);
    assert_eq!(headers.len(), 5);
    assert_eq!(headers[2], b"Subject: Hello\r\n there\r\n");
    assert!(body.starts_with(b"--b\r\n"));
    let entity = mime_entity(RAW);
    assert!(
        entity.starts_with(b"Content-Type: multipart/mixed;\r\n boundary=\"b\"\r\n\r\n--b\r\n")
    );
    assert!(!String::from_utf8_lossy(&entity).contains("Subject"));
}

#[test]
fn proton_users_get_the_keys_encrypted_and_others_as_their_server_needs() {
    let routes = BTreeMap::from([
        (
            "friend@proton.test".to_owned(),
            Route::Internal("friend-key".into()),
        ),
        ("plain@example.test".to_owned(), Route::Clear),
        (
            "pgp@example.test".to_owned(),
            Route::PgpMime("pgp-key".into()),
        ),
    ]);
    let packages = packages(&Keys, &draft(), &routes).unwrap();
    assert_eq!(packages.len(), 2);

    let direct = &packages[0];
    assert_eq!(direct["MIMEType"], "text/html");
    assert_eq!(direct["Type"], SCHEME_INTERNAL | SCHEME_CLEAR);
    assert_eq!(decoded(&direct["Body"]), "data:<p>Hi</p>");
    let friend = &direct["Addresses"]["friend@proton.test"];
    assert_eq!(friend["Type"], SCHEME_INTERNAL);
    assert_eq!(friend["Signature"], SIGNATURE_DETACHED);
    assert_eq!(decoded(&friend["BodyKeyPacket"]), "body-key for friend-key");
    assert_eq!(
        decoded(&friend["AttachmentKeyPackets"]["attachment"]),
        "attachment-key for friend-key"
    );
    let plain = &direct["Addresses"]["plain@example.test"];
    assert_eq!(plain["Type"], SCHEME_CLEAR);
    assert_eq!(plain["Signature"], SIGNATURE_NONE);
    assert!(plain.get("BodyKeyPacket").is_none());
    // Their server has to read it, so the keys go to Proton in the clear.
    assert_eq!(decoded(&direct["BodyKey"]["Key"]), "body-key");
    assert_eq!(direct["BodyKey"]["Algorithm"], "aes256");
    assert_eq!(
        decoded(&direct["AttachmentKeys"]["attachment"]["Key"]),
        "attachment-key"
    );
    assert!(direct["Addresses"].get("pgp@example.test").is_none());

    let mime = &packages[1];
    assert_eq!(mime["MIMEType"], "multipart/mixed");
    assert_eq!(mime["Type"], SCHEME_PGP_MIME);
    assert!(decoded(&mime["Body"]).starts_with("data:Content-Type: multipart/mixed;"));
    assert!(mime.get("BodyKey").is_none());
    let pgp = &mime["Addresses"]["pgp@example.test"];
    assert_eq!(pgp["Type"], SCHEME_PGP_MIME);
    assert_eq!(decoded(&pgp["BodyKeyPacket"]), "body-key for pgp-key");
}

#[test]
fn only_proton_users_means_no_key_leaves_in_the_clear() {
    let routes = BTreeMap::from([(
        "friend@proton.test".to_owned(),
        Route::Internal("friend-key".into()),
    )]);
    let packages = packages(&Keys, &draft(), &routes).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0]["Type"], SCHEME_INTERNAL);
    assert!(packages[0].get("BodyKey").is_none());
    assert!(packages[0].get("AttachmentKeys").is_none());
}

#[test]
fn an_imported_message_keeps_its_headers_and_encrypts_its_content() {
    let encrypted = encrypt_rfc822(&Keys, "address", RAW).unwrap();
    let text = String::from_utf8(encrypted.clone()).unwrap();
    assert!(text.starts_with("From: Me <me@proton.test>\r\nTo: you@example.test\r\nSubject: Hello\r\n there\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted;"));
    assert_eq!(text.matches("MIME-Version").count(), 1);
    assert!(!text.contains("multipart/mixed"));
    assert!(!text.contains("\r\nHi\r\n"));
    // It reads back as the PGP/MIME message other mail apps know, whose
    // encrypted part holds the content with its own headers.
    let parsed = mail_parser::MessageParser::default()
        .parse(&encrypted)
        .unwrap();
    assert_eq!(parsed.subject(), Some("Hello there"));
    let armored = text
        .split("-----BEGIN PGP MESSAGE-----\r\n")
        .nth(1)
        .unwrap()
        .split("\r\n-----END PGP MESSAGE-----")
        .next()
        .unwrap();
    let inner = String::from_utf8(B64.decode(armored).unwrap()).unwrap();
    assert!(inner.starts_with("Content-Type: multipart/mixed;\r\n boundary=\"b\"\r\n\r\n--b\r\n"));
    assert!(inner.contains("\r\nHi\r\n"));
}

#[test]
fn a_message_without_content_headers_is_imported_as_plain_text() {
    let encrypted = encrypt_rfc822(&Keys, "address", b"Subject: Note\r\n\r\nBody\r\n").unwrap();
    let text = String::from_utf8(encrypted).unwrap();
    let armored = text
        .split("-----BEGIN PGP MESSAGE-----\r\n")
        .nth(1)
        .unwrap()
        .split("\r\n-----END PGP MESSAGE-----")
        .next()
        .unwrap();
    let inner = String::from_utf8(B64.decode(armored).unwrap()).unwrap();
    assert_eq!(
        inner,
        "Content-Type: text/plain; charset=utf-8\r\n\r\nBody\r\n"
    );
}

#[test]
fn drafts_keep_their_attachments_when_the_names_are_the_same() {
    let held = |name: &str| AttachmentInfo {
        id: "id".into(),
        name: name.into(),
        mime_type: "text/plain".into(),
        disposition: None,
        key_packets: String::new(),
        headers: Default::default(),
    };
    let local = |name: &str| LocalAttachment {
        name: name.into(),
        mime_type: "text/plain".into(),
        content_id: None,
        inline: false,
        bytes: Vec::new(),
    };
    assert!(same_attachments(&[], &[]));
    assert!(same_attachments(
        &[held("a"), held("b")],
        &[local("b"), local("a")]
    ));
    assert!(!same_attachments(&[held("a")], &[local("a"), local("a")]));
    assert!(!same_attachments(&[held("a")], &[local("b")]));
}

#[test]
fn only_an_address_that_may_send_sends() {
    let address = |email: &str, send: u8| -> Address {
        serde_json::from_value(json!({
            "ID": email, "Email": email, "Status": 1, "Send": send, "Order": 1, "Keys": []
        }))
        .unwrap()
    };
    let addresses = [address("me@proton.test", 1), address("old@proton.test", 0)];
    assert_eq!(
        sending_address(&addresses, "ME@proton.test").unwrap().email,
        "me@proton.test"
    );
    assert!(sending_address(&addresses, "old@proton.test").is_err());
    assert!(sending_address(&addresses, "other@example.test").is_err());
}
