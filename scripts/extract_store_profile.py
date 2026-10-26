#!/usr/bin/env python3
"""Extract committed zstd frames from ipatool-fairplay's generated Go profile.

Usage: extract_store_profile.py path/to/data_generated.go path/to/assets/store
"""

import base64
import json
import pathlib
import re
import sys


def main() -> None:
    source = pathlib.Path(sys.argv[1]).read_text()
    output = pathlib.Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    framework = re.search(r'const generatedFrameworkUUID = "([^"]+)"', source).group(1)
    plugin_uuid = re.search(r'const generatedPluginUUID = "([^"]+)"', source).group(1)
    artifacts = {}
    pattern = re.compile(
        r'var generated(Metadata|Pages|Plugin) = artifact\{\s*'
        r'Name:\s*"([^"]+)",\s*Size:\s*(\d+),\s*'
        r'SHA256:\s*"([0-9a-f]{64})",\s*Encoded:\s*`([^`]+)`',
        re.S,
    )
    for match in pattern.finditer(source):
        key, name, size, digest, encoded = match.groups()
        filename = key.lower() + ".zst"
        frame = base64.b64decode("".join(encoded.split()), validate=True)
        (output / filename).write_bytes(frame)
        artifacts[key.lower()] = {
            "name": name,
            "size": int(size),
            "sha256": digest,
            "file": filename,
        }
    if set(artifacts) != {"metadata", "pages", "plugin"}:
        raise SystemExit("generated profile is missing an artifact")
    manifest = {
        "framework_uuid": framework,
        "plugin_uuid": plugin_uuid,
        "artifacts": artifacts,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
