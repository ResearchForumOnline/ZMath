# ZMath Local: independent preservation release

**By Shafaet Brady Hussain.** A self-hosted browser app for encrypted files and
messages, preserved after the original hosted services were retired. No main
node, login, API key, hosted database, subscription or company endpoint is needed.

## Run locally

Install Python 3, then run in this directory:

```sh
python -m http.server 8765 --bind 127.0.0.1
```

Open `http://127.0.0.1:8765/` in a modern browser. The server only delivers these
static files. Files, passphrases, pattern data and message contents are processed
in the browser and are not uploaded. After the page has loaded it makes no API
calls. Use localhost or HTTPS: Web Crypto and JavaScript modules need a supported
secure context; double-clicking the HTML file is not the recommended route.

The UI has no dependencies, remote fonts, analytics, persistent key store, or
accounts. It uses in-memory inputs and local downloads. Clearing the page does
not guarantee erasure of every browser or operating-system memory copy.

## Protect and restore

1. Generate or enter a unique passphrase of at least 14 characters. Save it safely.
2. Optionally choose a pattern/key file. Exactly the same bytes will be required
   when opening the resulting container.
3. Select a file and choose **Encrypt file**, or use **Messages** for text.
4. Keep the container, passphrase and factors separately. There is no recovery
   service or administrator who can reset a forgotten secret.
5. To restore, supply the same factors and choose the corresponding decrypt action.

File plaintext is limited to 50 MiB; JSON inputs are bounded at 72 MiB. Pattern
and external factor inputs are each limited to 1 MiB. Messages are limited to
12 KiB. All restored files download as attachments; the app does not execute or
preview them. The actual filename, size, timestamp, cryptographic identifiers
and optional factor commitment remain visible in container metadata.

## Profiles and compatibility

| Profile | Behavior |
| --- | --- |
| `ZMATH-PBKDF2-HKDF-AESGCM-2` | Default new-container profile: PBKDF2-HMAC-SHA-256 at 600,000 iterations, HKDF-SHA-256 and AES-256-GCM. Optional pattern file. |
| `ZSHIELD-PBKDF2-AESGCM-1` | Earlier ZShield containers can be opened using the preserved legacy derivation. |
| `ZMATH-PBKDF2-HKDF-AESGCM-QPUFACTOR-3` | Optional additional local factor. Historic identifier retained; the app neither contacts a quantum service nor attests the factor's origin. |

An optional external factor can be any nonempty local secret file. Select the
legacy ZQF1 option only for a structured factor file from an older deployment.
The preserved parser checks its internal commitments and structure. Self-reported
hardware/simulator evidence is **not independent attestation**. No quantum advantage,
QKD, new base cipher or post-quantum public-key security is claimed.

Messages keep `ZSHIELD1:` and `matrix-message` identifiers for compatibility.
New message headers identify transport as `offline`; this app is not a Matrix
client and does not supply a messaging transport. Share an encrypted envelope
using a channel of your choice and share secret factors separately.

Older `zmath_restore` Portable/Exclusive envelopes have a different JSON shape
and are deliberately rejected here. Server-bound Exclusive files cannot be
restored merely by removing the endpoint: the original server factor remains
necessary. Do not discard the original recovery material.

## Source custody and checks

`zshield-core.js`, its regression test and public known-answer vector are copied
byte-for-byte from the reviewed local public-web snapshot evaluated in the
18 August 2026 ZME1 paper. The core SHA-256 remains
`c48b5af56a50a2c75f682d56843fdc9a82da7714cda1ddee602c5620fa5df8d6`.
`PROVENANCE.json` records source-relative paths and exact hashes. These source
snapshots are preserved, not claimed to be newly invented cryptographic primitives.

Run with Node.js 22 or later; no package installation is needed:

```sh
npm test
python scripts/verify_archive.py
python scripts/build_release.py
```

The suite covers file/message round trips, legacy known-answer compatibility,
wrong factors, authenticated metadata tampering, resource bounds, external-factor
contracts, local UI actions and the absence of network APIs. These are author-side
regression tests, not independent cryptographic certification or assurance that
your browser, computer, passphrase or delivery channel is secure.

## License

**This new reviewed user-owned code release is noncommercial source-available**
under [PolyForm Noncommercial License 1.0.0](LICENSE). See [NOTICE](NOTICE) for the
required copyright notice. A noncommercial restriction means it is not an
unrestricted open-source license. Contact the copyright holder before commercial
use; this repository does not grant that use.

Existing research papers already distributed under CC BY 4.0 keep that license,
including its commercial permissions. Earlier grants cannot be withdrawn from
those copies by changing this repository. Third-party code and standards retain
their own rights and are not relicensed here. This small release contains no
bundled third-party libraries; browser Web Crypto and Node are platform facilities.

The [research repository](https://github.com/ResearchForumOnline/research) remains
the home of the papers and public reproducibility companions. Historical website
material is preserved in the [QuantumEncryption1 historical archive](archive/quantumencryption1/index.html).
It does not establish current services, certifications or hardware claims.
