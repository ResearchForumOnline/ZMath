"""Check the sanitized former public site without executing its HTML."""
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / 'archive' / 'quantumencryption1'


class Inspector(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.banner = False

    def handle_starttag(self, tag, attrs):
        assert tag not in {'script', 'form', 'iframe', 'object', 'embed'}, (self.path, tag)
        for name, value in attrs:
            assert not name.lower().startswith('on'), (self.path, name)
            if name in {'href', 'src'} and value:
                parsed = urlsplit(value)
                assert parsed.scheme not in {'javascript', 'data'}, (self.path, value)
                if name == 'src':
                    assert not parsed.scheme and not parsed.netloc, (self.path, value)
                if not parsed.scheme and not parsed.netloc and parsed.path:
                    target = (self.path.parent / unquote(parsed.path)).resolve()
                    assert target.is_relative_to(ROOT) and target.exists(), (self.path, value)

    def handle_data(self, value):
        if 'Historical website archive' in value:
            self.banner = True


def main():
    manifest = json.loads((ARCHIVE / 'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
    pages = list(ARCHIVE.rglob('*.html'))
    assert len(pages) == 17, len(pages)
    for path in pages:
        text = path.read_text(encoding='utf-8')
        assert '<?' not in text, path
        parser = Inspector(path)
        parser.feed(text)
        assert parser.banner, path
    for record in manifest['files']:
        target = (ROOT / record['archive']).resolve()
        assert target.is_relative_to(ARCHIVE) and target.is_file(), target
        assert hashlib.sha256(target.read_bytes()).hexdigest() == record['archive_sha256'], target
    print(f'Archive verification passed: {len(pages)} pages, local assets and safe static links.')


if __name__ == '__main__':
    main()
