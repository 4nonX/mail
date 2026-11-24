// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.

//! The handshake file the Bridge core writes once its gRPC server is up.
//!
//! The core writes `grpcServerConfig.json` into its settings directory,
//! `<config-home>/protonmail/bridge-v3/` by default. Because Flectar points
//! the core's config home at a directory it owns, it knows where to look; it
//! finds the file by name rather than assuming the vendor/version path, so an
//! upstream rename of that directory does not break the handshake.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The gRPC server details the core publishes for its frontend. Field names
/// match the core's JSON exactly (`port`, `cert`, `token`, `fileSocketPath`).
#[derive(Clone, Deserialize)]
pub struct ServerConfig {
    /// The loopback TCP port the gRPC server listens on. Zero when the core
    /// uses a file socket instead (every platform except Windows).
    #[serde(default)]
    pub port: u16,
    /// The self-signed TLS certificate (PEM) the server presents. Its common
    /// name and only SAN is `127.0.0.1`.
    pub cert: String,
    /// The bearer token the client must send as `server-token` metadata on
    /// every call.
    pub token: String,
    /// The Unix domain socket path, when the core uses one instead of TCP.
    #[serde(default, rename = "fileSocketPath")]
    pub file_socket_path: String,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the token or the certificate.
        f.debug_struct("ServerConfig")
            .field("port", &self.port)
            .field("file_socket_path", &self.file_socket_path)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// The handshake file's fixed name.
    pub const FILE_NAME: &'static str = "grpcServerConfig.json";

    /// Parses a handshake file's contents.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    /// True when the server is reachable over loopback TCP (the Windows case
    /// Flectar bundles the core for). A file-socket-only config returns false.
    pub fn is_tcp(&self) -> bool {
        self.port != 0
    }
}

/// Searches `root` (the core's config home) for the handshake file, at most
/// `max_depth` directories deep, and returns the first match. The file lives
/// one or two levels down (`protonmail/bridge-v3/`), so a shallow walk suffices
/// and never descends into Bridge's larger data subtrees.
pub(crate) fn find_handshake_file(root: &Path, max_depth: usize) -> Option<PathBuf> {
    fn walk(dir: &Path, depth: usize, max_depth: usize) -> Option<PathBuf> {
        let candidate = dir.join(ServerConfig::FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if depth >= max_depth {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && let Some(found) = walk(&entry.path(), depth + 1, max_depth)
            {
                return Some(found);
            }
        }
        None
    }
    walk(root, 0, max_depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_tcp_handshake() {
        let config = ServerConfig::parse(
            br#"{"port":41057,"cert":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----","token":"abc","fileSocketPath":""}"#,
        )
        .unwrap();
        assert_eq!(config.port, 41057);
        assert_eq!(config.token, "abc");
        assert!(config.is_tcp());
    }

    #[test]
    fn a_file_socket_config_is_not_tcp() {
        let config =
            ServerConfig::parse(br#"{"port":0,"cert":"x","token":"t","fileSocketPath":"/tmp/s"}"#)
                .unwrap();
        assert!(!config.is_tcp());
        assert_eq!(config.file_socket_path, "/tmp/s");
    }

    #[test]
    fn finds_the_handshake_two_levels_down() {
        let root = std::env::temp_dir().join(format!("fpb-test-{}", std::process::id()));
        let nested = root.join("protonmail").join("bridge-v3");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join(ServerConfig::FILE_NAME);
        std::fs::write(&file, b"{}").unwrap();
        let found = find_handshake_file(&root, 4).expect("file should be found");
        assert_eq!(found, file);
        std::fs::remove_dir_all(&root).ok();
    }
}
