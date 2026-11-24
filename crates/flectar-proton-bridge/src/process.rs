// Copyright (c) 2026 Dan Dressen
//
// This file is part of Flectar Mail and is licensed under AGPL-3.0-only.

//! Starting and stopping the bundled Proton Bridge core process.

use crate::config::{self, ServerConfig};
use crate::{DEFAULT_READY_TIMEOUT, Error, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

/// How to start the Bridge core.
pub struct BridgeOptions {
    /// Path to the bundled Bridge core binary (`bridge` / `bridge.exe`).
    pub core_binary: PathBuf,
    /// A Flectar-owned directory to use as the core's config/data/cache home.
    /// The core writes its handshake file and vault under here, so it stays
    /// isolated from any separately installed Bridge.
    pub config_home: PathBuf,
    /// The core's log level: one of panic, fatal, error, warn, info, debug.
    pub log_level: String,
    /// How long to wait for the handshake file to appear.
    pub ready_timeout: Duration,
}

impl BridgeOptions {
    /// Options with the default log level and ready timeout.
    pub fn new(core_binary: PathBuf, config_home: PathBuf) -> Self {
        Self {
            core_binary,
            config_home,
            log_level: "info".to_owned(),
            ready_timeout: DEFAULT_READY_TIMEOUT,
        }
    }
}

/// A running Bridge core and the handshake it published.
pub struct BridgeCore {
    child: Child,
    server_config: ServerConfig,
}

impl BridgeCore {
    /// Spawns the core headless, watching Flectar's process id, and waits for
    /// it to write its handshake file.
    pub async fn start(options: BridgeOptions) -> Result<Self> {
        std::fs::create_dir_all(&options.config_home)
            .map_err(|error| Error::Handshake(format!("config home: {error}")))?;

        // Make sure no stale handshake from a previous run is mistaken for this
        // one: the core rewrites it on startup, but a leftover with an old port
        // would be read before the rewrite.
        if let Some(stale) = config::find_handshake_file(&options.config_home, 4) {
            let _ = std::fs::remove_file(stale);
        }

        let launcher = options.core_binary.clone();
        let mut command = Command::new(&options.core_binary);
        command
            .arg("--grpc")
            .arg("--no-window")
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .arg("--log-level")
            .arg(&options.log_level)
            // The core records how it was launched so its own updater can
            // re-exec; point it at the bundled binary, not at Flectar.
            .arg("--launcher")
            .arg(&launcher)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        // Confine the core's config, data and cache to our directory on both
        // the Windows target (APPDATA / LOCALAPPDATA) and Unix dev machines
        // (XDG_*), so we know where the handshake lands and leave no state
        // behind elsewhere.
        let home = &options.config_home;
        for key in ["APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"] {
            command.env(key, home);
        }
        command.env("XDG_DATA_HOME", home.join("data"));
        command.env("XDG_CACHE_HOME", home.join("cache"));

        let mut child = command.spawn().map_err(Error::Spawn)?;

        let deadline = Instant::now() + options.ready_timeout;
        loop {
            // The core writes the file to a temp name and renames it, so a
            // read or parse that loses the race just falls through and retries.
            if let Some(path) = config::find_handshake_file(&options.config_home, 4)
                && let Ok(bytes) = std::fs::read(&path)
                && let Ok(server_config) = ServerConfig::parse(&bytes)
            {
                return Ok(Self {
                    child,
                    server_config,
                });
            }

            if let Some(status) = child
                .try_wait()
                .map_err(|error| Error::Handshake(error.to_string()))?
            {
                return Err(Error::CoreExited(status.to_string()));
            }

            if Instant::now() >= deadline {
                let _ = child.start_kill();
                return Err(Error::ReadyTimeout);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The handshake details for connecting to this core.
    pub fn server_config(&self) -> &ServerConfig {
        &self.server_config
    }

    /// Stops the core and waits for it to exit.
    pub async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}
