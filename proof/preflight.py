"""Read-only context/source checks before the compiler environment is invoked."""
import json
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_candidate import context
from guards import archive_files, context_guard, digest, require, read_bounded


def main():
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true", "GitHub Windows only")
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    raw = read_bounded(root / "inputs/manifest.json", 1024 * 1024)
    manifest = json.loads(raw)
    context_guard(context(), manifest, os.environ["APPROVED_COMMIT"], raw, os.environ["APPROVED_MANIFEST"])
    require(os.environ.get("ImageOS") == manifest["runner"]["ImageOS"] and
            os.environ.get("ImageVersion") == manifest["runner"]["ImageVersion"], "reviewed image")
    require(platform.python_version() == manifest["runner"]["python_version"] and
            platform.machine().upper() == "AMD64", "builder Python")
    require(Path(sys.executable).resolve() == (Path(os.environ["RUNNER_TOOL_CACHE"]) /
            manifest["runner"]["python_relative_path"]).resolve(), "builder path")
    inventory = read_bounded(root / "inputs/source-files.json", 1024 * 1024)
    require(digest(inventory) == manifest["source_inventory_sha256"], "inventory digest")
    archive_files(read_bounded(root / "inputs/cffi-2.1.1.tar.gz", 530807, 530807), manifest["source"], json.loads(inventory))
    print("PASS: bounded context/source preflight; no trust or release admission")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"failure_phase": "PREFLIGHT", "failure_type": type(error).__name__,
                          "guard_code": getattr(error, "guard_code", "UNEXPECTED_EXCEPTION")}))
        raise SystemExit(2)
