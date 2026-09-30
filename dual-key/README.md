# ZMath Dual Key: preserved local vault

By **Shafaet Brady Hussain**. Open [the dual-key app](https://researchforumonline.github.io/ZMath/dual-key/) or serve the repository on localhost. No login, website API, central node, database or subscription is required. All runtime assets are included.

## What this preserves

The original `zmail-platform/site/assets/zmath-shield.js` module and its six-test suite are copied **byte-for-byte** at their compatible relative paths under this folder. The new `app.js`, HTML and CSS provide an independent interface. Historic Zmail names in the preserved module identify formats and old labels; they are not network calls. The new page does not activate the original website controller or require any Zmail service.

The original module SHA-256 is `f12953ded126c9991f4137b64f1aa609fc2391942960b4d7d8a3c7f0ed7d3fc8`. Its test SHA-256 is `744c1896128fc8d76523032fb20990b43025722e7d8bbda2d02cd1c4d0110560`.

## Create and restore

1. Save a long unique passphrase in your password manager. Generate produces 24 random bytes encoded as 48 hexadecimal characters. It is not stored by the app.
2. Select 6–9 distinct grid points in an order you can retain separately.
3. Add a note, an attachment up to 8 MiB, or both. Select **Encrypt & download vault**. Plaintext inputs are cleared after the export succeeds.
4. Keep the `.zmath` download. The encrypted JSON box provides a second copy; it is not a recovery factor.
5. Select **Open a vault**, supply your original passphrase and pattern, then choose the file or paste its JSON. A chosen file takes priority over pasted JSON.
6. Restored notes display as text. Attachments download with an inert `application/octet-stream` MIME type; no content is executed or rendered as HTML.
7. Clear decrypted results when finished. Clearing the UI is not a promise to erase every browser/OS memory copy.

There is no reset or recovery administrator. Losing either input prevents opening the corresponding layer. Save factors before encrypting valuable content.

## Exact format and compatibility

| Property | Preserved value |
| --- | --- |
| Format/version | `zmath-shield`, version `1` |
| Protection identifier | `two-layer-authenticated-encryption` |
| Inner input | The exact passphrase; encrypted payload contains title, note, attachment metadata/bytes and timestamp |
| Outer input | Domain-separated ordered visual-pattern sequence; encrypts the complete inner authenticated envelope |
| Each layer | AES-256-GCM; 128-bit tag; independently random 32-byte salt and 12-byte IV |
| Each key derivation | PBKDF2-HMAC-SHA-256, exactly 600,000 iterations; non-exportable AES key |
| Authentication | Layer/factor/algorithm/work-factor AAD; outer layer also authenticates the visible timestamp |
| Visible information | Timestamp, format identifiers, salts, IV and encrypted length |
| Limits | 12–512 passphrase characters, 100,000 note characters, 8 MiB attachment, 20 MiB imported vault |

Shield `.zmath` files are **different from** the main ZMath Local ZME1 container, its `ZSHIELD1:` message armor, old `zmath_restore` Portable/Exclusive envelopes, and ZeroThink `.ztz` files. Renaming an extension does not convert a format. This page preserves the original Shield derivation so old compatible vaults remain readable with their original inputs.

Legacy Exclusive envelopes depended on a server-held factor. Removing their website reference cannot reconstruct that factor. Keep any original recovery materials. The legacy custom `.ztz` HMAC-stream construction is not installed as a production encryption mode by this release.

## Security and research boundary

The grid has 967,680 possible ordered sequences of 6–9 distinct points, under 20 bits before user bias. It is an additional low-entropy input. **A strong unique passphrase supplies the main resistance to guessing.** Separate salts do not make the pattern a random 256-bit secret. PBKDF2 increases work per guess but is not memory-hard.

Two AES-256-GCM layers do not become AES-512 or automatically double security. This is an original application composition using standard cryptographic primitives, not a new AES variant. Neither the page nor the tests establish quantum protection, post-quantum key exchange, independent certification or security of a compromised device.

The existing [protected-communications paper](https://github.com/ResearchForumOnline/research/blob/main/papers/zmail-callchat-protected-communications-1.0.md) and [encryption-profile audit](https://github.com/ResearchForumOnline/research/blob/main/artifacts/zba-1.1/ENCRYPTION_PROFILE_AUDIT.md) describe this profile. The paper is earlier research evidence; this release adds independently usable source custody and a local interface.

## Checks and license

Run `npm test` from the repository root. This includes the unchanged six-test vault suite plus new UI, source-hash, bounds and independent signed-envelope checks. **Run local self-test** checks synthetic encryption, decryption and wrong-passphrase rejection without using your entered content or inputs.

Newly published author-owned code is covered by [PolyForm Noncommercial 1.0.0](../LICENSE) and the [required notice](../NOTICE). Earlier research papers retain their existing licenses. These tests are regression evidence, not an independent cryptographic audit.
