# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.2.0] - 2026-07-19

### Changed
- **dig-social-graph!:** Migrate the `EnvelopeSealer` seam from X25519 (retired slot 0x0011) to
  BLS-G1 (slot 0x0010). `open` now takes the app-held `&SecretKey` for G1-ECDH decapsulation
  (decap is a Diffie-Hellman over raw key material, not a signature — it cannot route through a
  sign-only wallet callback, the #908 boundary); `seal` resolves the recipient's G1 public key.
  Consume `dig-identity` from crates.io (0.4.1) instead of a git tag. (#990, epic #986 / #1169)

## [0.1.0] - 2026-07-18

### Features
- **dig-social-graph:** Connection state machine + seams + SPEC (#986 SG-1) (#1)


