"""Build a deterministic ZMath source/static distribution from a fixed allowlist."""
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'index.html', 'app.js', 'styles.css', 'zshield-core.js', 'qpu-factor-core.js',
    'zshield-core.test.mjs', 'qpu-factor-core.test.mjs', 'preservation.test.mjs',
    'package.json', 'README.md', 'LICENSE', 'NOTICE', 'PROVENANCE.json',
    'VERIFICATION.json', 'test-vectors/zme1-v1.json',
    'scripts/preserve_public_site.py', 'scripts/verify_archive.py', 'scripts/build_release.py',
    'dual-key/index.html', 'dual-key/styles.css', 'dual-key/app.js', 'dual-key/README.md',
    'dual-key/site/assets/zmath-shield.js', 'dual-key/test/zmath-shield.test.mjs',
    'dual-key/test/ui.test.mjs', 'preserved/protected-mail/README.md',
    'preserved/protected-mail/zmath-mail-crypto.js', 'preserved/protected-mail/core.test.mjs',
    'preserved/protected-mail/original-tests/zmath-mail-crypto.test.mjs',
)


def main():
    files = [ROOT / name for name in FILES]
    files += sorted((ROOT / 'archive' / 'quantumencryption1').rglob('*'))
    files = [path for path in files if not path.is_dir()]
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f'Invalid release file: {path.name}')
        if path.suffix not in {'.html', '.css', '.json', '.js', '.mjs', '.md', '.py', ''}:
            raise SystemExit(f'Unexpected file type: {path.name}')
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    version = json.loads((ROOT / 'package.json').read_text(encoding='utf-8'))['version']
    if not isinstance(version, str) or not version or any(c not in '0123456789.' for c in version):
        raise SystemExit('Invalid release version')
    target = output / f'ZMath-Local-v{version}.zip'
    lines = []
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files):
            relative = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            info = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            lines.append(f'{hashlib.sha256(data).hexdigest()}  {relative}')
        manifest_info = zipfile.ZipInfo('SOURCE_SHA256SUMS.txt', (2026, 1, 1, 0, 0, 0))
        manifest_info.create_system = 3
        manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
        manifest_info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(manifest_info, '\n'.join(lines) + '\n')
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix('.zip.sha256').write_text(f'{digest}  {target.name}\n', encoding='ascii')
    print(f'Built {target.name}: {len(files)} reviewed files, SHA-256 {digest}')


if __name__ == '__main__':
    main()
