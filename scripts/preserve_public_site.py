"""Convert an explicit list of former public pages into a static historical archive.

Run with the local former public/ directory as the sole argument. Never traverses
server configuration, enquiries, credentials, databases, backups or API handlers.
"""
from pathlib import Path
import hashlib
import json
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["", "technology", "zero-boundary-algebra", "zmath-file-encryption",
         "security-model", "quantum-encrypted-files", "ionq-quantum-api-integration",
         "post-quantum-cryptography-uk", "government-defence", "operational-hardware",
         "uk-defence-brief", "uk-mod-access-policy", "privacy", "terms", "pricing",
         "contact", "quantum-seal-test"]

def build(source: Path):
    destination = ROOT / "archive" / "quantumencryption1"
    records = []
    for page in PAGES:
        relative = Path(page) / "index.php"
        original = (source / relative).read_bytes()
        html = original.decode("utf-8-sig")
        html = re.sub(r"\A\s*<\?php.*?\?>", "", html, count=1, flags=re.S)
        if "<?" in html:
            raise ValueError(f"Unexpected executable template: {relative}")
        html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.S | re.I)
        html = re.sub(r"<form\b[^>]*>.*?</form>", '<p class="archive-disabled">Historical form removed: this archive makes no enquiries or API requests.</p>', html, flags=re.S | re.I)
        html = re.sub(r'<link[^>]+rel="canonical"[^>]*>', "", html, flags=re.I)
        html = re.sub(r'<meta[^>]+property="og:url"[^>]*>', "", html, flags=re.I)
        prefix = "../" if page else "./"
        def local_link(match):
            attr, value = match.group(1), match.group(2)
            parsed = urlsplit(value)
            if parsed.netloc.lower() in {"quantumencryption1.com", "www.quantumencryption1.com"}:
                value = parsed.path or "/"
            if value.startswith("/assets/css/site.css"):
                value = prefix + "assets/site.css"
            elif value.startswith("/"):
                target = value.strip("/").split("?")[0]
                if target in PAGES:
                    value = prefix + (target + "/" if target else "") + "index.html"
                else:
                    value = "https://github.com/ResearchForumOnline/ZMath"
            elif parsed.netloc.lower() in {"callchat.org", "zerothink.talktoai.org", "openzero.talktoai.org", "docs.talktoai.org", "research.talktoai.org"}:
                value = "https://github.com/ResearchForumOnline/research"
            return f'{attr}="{value}"'
        html = re.sub(r'(href|src)="([^"]*)"', local_link, html)
        banner = '<aside class="archive-notice" role="note"><strong>Historical website archive — preserved 30 September 2026.</strong> This page records earlier project descriptions and marketing. Its claims, pricing, policies, offers and deployment status are historical, not independently verified or current service commitments. Forms, server APIs and live integrations have been removed. <a href="https://github.com/ResearchForumOnline/ZMath">Current preserved source</a>.</aside>'
        html = re.sub(r"(<body\b[^>]*>)", r"\1" + banner, html, count=1, flags=re.I)
        output = destination / page / "index.html"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8", newline="\n")
        records.append({"source": relative.as_posix(), "source_sha256": hashlib.sha256(original).hexdigest(), "archive": output.relative_to(ROOT).as_posix(), "archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
    css = (source / "assets/css/site.css").read_bytes()
    css_file = destination / "assets/site.css"
    css_file.parent.mkdir(parents=True, exist_ok=True)
    css_file.write_bytes(css + b"\n.archive-notice{padding:20px;background:#182536;color:#fff;border-bottom:3px solid #67d8bd;font:16px/1.6 system-ui}.archive-notice a{color:#a1f3d7}.reveal{opacity:1!important;transform:none!important}.archive-disabled{padding:16px;border:1px solid #637080}\n")
    records.append({"source": "assets/css/site.css", "source_sha256": hashlib.sha256(css).hexdigest(), "archive": css_file.relative_to(ROOT).as_posix(), "archive_sha256": hashlib.sha256(css_file.read_bytes()).hexdigest()})
    (destination / "SOURCE_MANIFEST.json").write_text(json.dumps({"schema":"zmath.public-site-preservation.v1", "date":"2026-09-30", "transforms":["PHP response headers removed", "forms and scripts removed", "relative archive links", "historical status banner"], "files":records}, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"pages":len(PAGES),"assets":1,"excluded":"server APIs, enquiries, configs, backups and databases"}))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/preserve_public_site.py PATH_TO_FORMER_PUBLIC_DIRECTORY")
    build(Path(sys.argv[1]).resolve())
