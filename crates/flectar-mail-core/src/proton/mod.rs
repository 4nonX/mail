//! Proton Mail accounts, through Proton's own API.
//!
//! Proton keeps mail end-to-end encrypted, so there is no IMAP to talk to.
//! These modules sign in the way Proton's apps do, unlock the account's
//! OpenPGP keys locally, and decrypt messages on this device.

pub(crate) mod actions;
pub mod api;
pub mod auth;
pub(crate) mod folders;
pub mod hv;
pub mod keys;
pub mod mail;
pub(crate) mod send;
pub mod setup;
pub mod stored;
pub(crate) mod sync;
