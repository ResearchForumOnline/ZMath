"""Build a deterministic ZMath source/static distribution from a fixed allowlist."""
import hashlib
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
    target = output / 'ZMath-Local-v1.0.0.zip'
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
        archive.writestr('SOURCE_SHA256SUMS.txt', '\n'.join(lines) + '\n')
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix('.zip.sha256').write_text(f'{digest}  {target.name}\n', encoding='ascii')
    print(f'Built {target.name}: {len(files)} reviewed files, SHA-256 {digest}')


if __name__ == '__main__':
    main()
