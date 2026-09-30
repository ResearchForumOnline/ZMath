# Preserved signed dual-key envelope research

By **Shafaet Brady Hussain**. This reviewed source preserves the device envelope implementation described in the [August 2026 protected-communications paper](https://github.com/ResearchForumOnline/research/blob/main/papers/zmail-callchat-protected-communications-1.0.md).

`zmath-mail-crypto.js` is unchanged from the evaluated snapshot. SHA-256:

`01c6442ac4080a64a8641ea657cac872f43514c1a9822b11b5ba1eb7287de7d9`

The original six-test file is preserved at `original-tests/zmath-mail-crypto.test.mjs`, SHA-256 `f0039be7b67da0a52f3a1e48aa161c57f1fdf2a6dd009e05f286e39da1f9bb19`. Both match the published paper. That historical test's import and last test refer to the original Roundcube tree; the server/plugin tree is intentionally not bundled. It is evidence, not the portable test entrypoint.

The runnable `core.test.mjs` adapts the five core synthetic tests to repository-relative imports and adds local-module, invalid-version and recipient-limit checks. It uses transient synthetic device keys. No real keys, accounts, messages or directories are included.

## Mechanism

- Two independently generated random AES-256-GCM content keys, separate nonces and domain-separated authenticated layers.
- Ephemeral P-256 ECDH plus HKDF-SHA-256 wraps both content keys for selected recipient devices.
- A P-256 ECDSA signature authenticates the envelope relative to its included signing key.
- Version 2 opaque recipient slots omit recipient addresses and device IDs from the shared object.
- Armor and domain strings preserve compatibility; historic service names do not contact any website.

## Limits

This is historical/experimental source preservation, **not a mail client or live service**. It provides no recipient directory, verified person-to-key binding, transport, device recovery or production UI. A valid signature alone does not prove a human sender's identity. Ordinary email subject/routing metadata and attachments were outside the original protected-mail body protocol. P-256 ECDH is not post-quantum key agreement, and two AES layers are not AES-512.

The original module remains unchanged for provenance. It needs further independent review and hardening before production reuse: stricter direct-API resource/parameter validation, explicit key-lifecycle handling, trust-boundary review and interoperability fixtures. Use the actively bounded [dual-key vault](../../dual-key/) for the included notes/attachment workflow.

Newly published author-owned source is under the repository's [noncommercial license](../../LICENSE); pre-existing papers and any earlier grants retain their own rights.
