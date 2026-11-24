// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.
//
//! Drives a Proton Mail Bridge core that Flectar Mail manages itself.
//!
//! Flectar bundles Proton's own Bridge core binary and, instead of asking the
//! person to install and run Bridge, starts it headless and plays the exact
//! role Bridge's own GUI plays: it reads the core's handshake file, connects
//! to its gRPC frontend over TLS with the server token, and drives sign-in.
//! Bridge then exposes the account as a local IMAP/SMTP server that Flectar
//! connects to like any other.
//!
//! The sign-in is genuinely Proton's Bridge authenticating; Flectar never
//! impersonates a Proton app. Bridge itself is a paid-plan feature, so free
//! accounts are rejected by Bridge with [`Error::FreeAccount`].
//!
//! The pieces:
//! - [`BridgeCore`] starts the bundled core and performs the handshake.
//! - [`BridgeClient`] is the gRPC client: the login state machine and the
//!   readout of bridge password, mail-server ports and the TLS certificate.
//! - [`Bridge`] ties the two together for the common case.

// `tonic::Status` is a large type, so every function returning a
// `Result<_, Status>` — the generated gRPC client, the auth interceptor —
// trips `result_large_err`. That size is imposed by tonic, not something this
// crate can fix; our own `Error` keeps the `Status` boxed so it stays small.
#![allow(clippy::result_large_err)]

mod client;
mod config;
mod process;

/// The generated Proton Bridge gRPC types. Public so integration tests can
/// stand up a mock server; not part of this crate's stable surface.
#[doc(hidden)]
pub mod pb {
    // Layout matters: from inside the `grpc` package module, generated code
    // refers to the well-known types as `super::google::protobuf::…`, so the
    // two packages must sit side by side under one parent module.
    pub mod grpc {
        tonic::include_proto!("grpc");
    }
    pub mod google {
        pub mod protobuf {
            tonic::include_proto!("google.protobuf");
        }
    }
}

pub use client::{BridgeClient, LoggedInUser, LoginHandler, MailServerSettings};
pub use config::ServerConfig;
pub use process::{BridgeCore, BridgeOptions};

use std::path::Path;
use std::time::Duration;

/// Anything that can go wrong starting or driving the Bridge core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not start the Proton Bridge core: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("the Proton Bridge core exited before it was ready (code {0})")]
    CoreExited(String),
    #[error("timed out waiting for the Proton Bridge core to come up")]
    ReadyTimeout,
    #[error("the Proton Bridge handshake file could not be read: {0}")]
    Handshake(String),
    #[error("could not connect to the Proton Bridge core: {0}")]
    Connect(String),
    #[error("Proton Bridge rejected the request: {0}")]
    Rpc(Box<tonic::Status>),
    #[error(
        "this Proton account needs a paid plan: Proton Mail Bridge is not available for free accounts"
    )]
    FreeAccount,
    #[error("Proton Bridge sign-in failed: {0}")]
    Login(String),
    #[error("could not read the exported Bridge TLS certificate: {0}")]
    Certificate(String),
    #[error("the Proton Bridge core stopped sending events")]
    StreamClosed,
    #[error("sign-in needs {0}, which could not be provided")]
    HandlerUnavailable(String),
}

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        // Boxed so `Error` stays small (see the crate-level lint note above).
        Error::Rpc(Box::new(status))
    }
}

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A managed Bridge core together with a connected gRPC client.
///
/// Start one with [`Bridge::start`], sign an account in with [`Bridge::login`],
/// read out the connection details, then drop it or call [`Bridge::shutdown`].
/// The core shuts itself down when Flectar exits even if `shutdown` is never
/// reached, because it is started watching Flectar's process id.
pub struct Bridge {
    core: BridgeCore,
    client: BridgeClient,
}

impl Bridge {
    /// Starts the bundled core, waits for its handshake, and connects.
    pub async fn start(options: BridgeOptions) -> Result<Self> {
        let core = BridgeCore::start(options).await?;
        let client = BridgeClient::connect(core.server_config()).await?;
        Ok(Self { core, client })
    }

    /// Signs the given account in through Bridge, driving TOTP, mailbox
    /// password and human verification through `handler` as Bridge asks for
    /// them, and returns the local connection secrets on success.
    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
        handler: &dyn LoginHandler,
    ) -> Result<LoggedInUser> {
        self.client.login(email, password, handler).await
    }

    /// The IMAP and SMTP ports (and their TLS flags) Bridge serves locally.
    pub async fn mail_server_settings(&mut self) -> Result<MailServerSettings> {
        self.client.mail_server_settings().await
    }

    /// Exports Bridge's TLS certificate into `dir` and returns it as PEM, for
    /// Flectar to trust on the local account.
    pub async fn export_tls_certificate(&mut self, dir: &Path) -> Result<String> {
        self.client.export_tls_certificate(dir).await
    }

    /// Stops the core and waits for it to exit.
    pub async fn shutdown(self) {
        self.core.shutdown().await;
    }
}

/// The default time to wait for the core to write its handshake file.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(60);
