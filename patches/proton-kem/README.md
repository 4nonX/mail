# Proton's OpenPGP backend beside Flectar Mail Sync

Proton accounts use Proton's own OpenPGP crates (`proton-crypto` with the
pure-Rust `proton-rpgp` backend). `proton-rpgp` 0.9.0 and the `ml-kem` 0.2
it builds on pin `kem = "=0.3.0-pre.0"`. Flectar Mail Sync's `hpke` needs
`kem` 0.3, and Cargo can't keep a prerelease and the release of the same
`0.3` line in one build.

So the prerelease is vendored under another name:

| Crate | Source | Change |
| --- | --- | --- |
| `crates/kem-pre` | `kem` 0.3.0-pre.0 from crates.io | package renamed to `kem-pre` |
| `crates/ml-kem-0.2` | `ml-kem` 0.2.3 from crates.io | depends on `kem-pre` under the name `kem` |
| `crates/proton-rpgp` | `proton-rpgp` 0.9.0 from crates.io | depends on `kem-pre` under the name `kem` |

No source file changed; only the `[dependencies.kem]` entry of the two
manifests gained `package = "kem-pre"` and a `path`. The root manifest
patches `ml-kem` and `proton-rpgp` to these copies. `ml-kem` 0.3, which
`hpke` uses, still comes from crates.io, because a patch only replaces the
version it carries.

Drop all three once `proton-rpgp` moves to `ml-kem` 0.3.
