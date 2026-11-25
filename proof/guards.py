"""Pure input/output checks. Importing this module starts no process or network I/O."""
import base64
import csv
import hashlib
import io
import json
import re
import struct
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import PurePosixPath


class Refused(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        # Stable guard identity, never path/value/credential text after the colon.
        self.guard_code = "G_" + hashlib.sha256(reason.split(":", 1)[0].encode()).hexdigest()[:16]


def read_bounded(path, cap, expected_size=None):
    require(path.is_file() and not path.is_symlink(), "bounded regular file")
    size = path.stat().st_size
    require(0 <= size <= cap and (expected_size is None or size == expected_size), "bounded file size")
    with path.open("rb") as stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap and (expected_size is None or len(data) == expected_size), "bounded file bytes")
    return data


def hash_file(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024 * 1024, "tool file size")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


GENERATED_METADATA = ("PKG-INFO", "setup.cfg", "src/cffi.egg-info/PKG-INFO",
                      "src/cffi.egg-info/SOURCES.txt", "src/cffi.egg-info/dependency_links.txt",
                      "src/cffi.egg-info/entry_points.txt", "src/cffi.egg-info/not-zip-safe",
                      "src/cffi.egg-info/requires.txt", "src/cffi.egg-info/top_level.txt")


def summarize_log(path, limit=131072):
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
        stream.seek(0)
        if size <= limit:
            exported = stream.read(limit)
        else:
            exported = stream.read(limit // 2)
            stream.seek(max(0, size - limit // 2))
            exported += stream.read(limit // 2)
    return {"bytes": size, "sha256": h.hexdigest(), "export_truncated": size > limit}, exported


def source_readback(reference, working, originals, object_name):
    rows = []
    for name, payload in originals.items():
        ref = reference / name
        require(not ref.is_symlink() and ref.is_file() and ref.stat().st_size == len(payload), "reference source changed")
        require(read_bounded(ref, len(payload), len(payload)) == payload, "reference source changed")
        path = working / name
        require(not path.is_symlink(), "working source symlink")
        strict = (name not in GENERATED_METADATA or name == "setup.cfg") and name != object_name
        if strict:
            require(path.is_file() and path.stat().st_size == len(payload), "source changed during build: " + name)
        current = read_bounded(path, len(payload), len(payload)) if strict else (
            read_bounded(path, 8 * 1024 * 1024) if path.is_file() else None)
        # setup.cfg remains strict configuration despite its sdist-generated origin.
        if name not in GENERATED_METADATA or name == "setup.cfg":
            if name != object_name:
                require(current == payload, "source changed during build: " + name)
        if name in GENERATED_METADATA:
            rows.append({"path": name, "before_sha256": digest(payload),
                         "after_sha256": digest(current) if current is not None else None,
                         "raw_comparison": "EXACT" if current == payload else "DIFFERENT",
                         "configuration_still_exact_required": name == "setup.cfg"})
    require({r["path"] for r in rows} == set(GENERATED_METADATA), "generated metadata inventory")
    return rows


def artifact_allowlist(root, expected_wheel):
    allowed = {expected_wheel, "build-record.json", "toolchain.json", "compiler-selection.json"}
    allowed |= {f"stage-{n}.log" for n in range(1, 8)}
    require({p.name for p in root.iterdir()} == allowed, "artifact file allowlist")
    require(all(p.is_file() and not p.is_symlink() for p in root.iterdir()), "artifact regular files")


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) < 240, "name length")
    require(not name.startswith(("/", "\\")) and "\\" not in name and ":" not in name,
            "absolute/Windows path")
    p = PurePosixPath(name)
    require(all(x not in ("", ".", "..") for x in name.rstrip("/").split("/")), "path segments")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{x}{i}" for x in ("COM", "LPT") for i in range(1, 10)}
    require(all(not x.endswith((".", " ")) and x.split(".")[0].upper() not in reserved
                and not any(ord(c) < 32 for c in x) for x in p.parts), "Windows alias")
    return p


def context_guard(context, manifest, approved_commit, manifest_bytes, approved_manifest):
    require(context["repository"] == manifest["repository"], "repository")
    require(context["actor"] == manifest["actor"], "actor")
    require(str(context["repository_id"]) == str(manifest["repository_id"]), "repository identity")
    require(str(context["owner_id"]) == str(manifest["owner_id"]), "owner identity")
    require(context["visibility"] == "public", "visibility")
    require(context["event"] == "workflow_dispatch" and context["ref"] == "refs/heads/main", "event/ref")
    require(context["attempt"] == "1" and context["run_number"] == "4", "one-use workflow")
    require(re.fullmatch(r"[0-9a-f]{40}", approved_commit or "") is not None, "commit format")
    require(context["sha"] == approved_commit, "approved commit")
    require(re.fullmatch(r"[0-9a-f]{64}", approved_manifest or "") is not None, "manifest format")
    require(digest(manifest_bytes) == approved_manifest, "approved manifest")


def archive_files(data, source_pin, inventory):
    require(len(data) == source_pin["bytes"] and digest(data) == source_pin["sha256"], "source digest/size")
    expected = {r["path"]: r for r in inventory}
    require(len(expected) == len(inventory) == 222, "source inventory")
    result, names, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for count, entry in enumerate(archive, 1):
            require(count <= 264, "member count")
            p = safe_name(entry.name)
            require(p.parts[0] == "cffi-2.1.1", "archive root")
            key = entry.name.rstrip("/").casefold()
            require(key not in names, "duplicate/alias")
            names.add(key)
            require(entry.isfile() or entry.isdir(), "archive link or special file")
            if entry.isdir():
                continue
            require(0 <= entry.size <= 8 * 1024 * 1024, "member size")
            total += entry.size
            require(total <= 2209252, "expanded bytes")
            rel = "/".join(p.parts[1:])
            require(rel in expected, "unlisted source")
            payload = archive.extractfile(entry).read(entry.size + 1)
            pin = expected[rel]
            require(len(payload) == pin["bytes"] and digest(payload) == pin["sha256"], "member digest/size")
            result[rel] = payload
    require(len(names) == 264 and total == 2209252 and set(result) == set(expected), "archive completeness")
    return result


def wheel_files(data, filename, max_bytes=8 * 1024 * 1024):
    require(len(data) <= max_bytes, "wheel size")
    result, names, total = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        require(len(wheel.infolist()) <= 2000, "wheel member count")
        for entry in wheel.infolist():
            safe_name(entry.filename)
            key = entry.filename.rstrip("/").casefold()
            require(key not in names, "wheel duplicate/alias")
            names.add(key)
            require(not entry.flag_bits & 1, "encrypted wheel")
            mode = entry.external_attr >> 16
            require((mode & 0o170000) not in (0o120000, 0o020000, 0o060000), "wheel special file")
            if entry.is_dir():
                continue
            total += entry.file_size
            require(total <= 32 * 1024 * 1024 and entry.file_size <= 16 * 1024 * 1024, "wheel expansion")
            result[entry.filename] = wheel.read(entry)
    # Only the outer distribution owns the wheel RECORD. Vendored dist-info
    # entries remain payload data and must still pass the outer RECORD hashes.
    roots = {p.split("/", 1)[0] for p in result
             if "/" in p and p.split("/", 1)[0].endswith(".dist-info")}
    require(len(roots) == 1, "one top-level dist-info")
    records = [p for p in result if p.endswith(".dist-info/RECORD")
               and len(PurePosixPath(p).parts) == 2]
    require(len(records) == 1, "one RECORD")
    record = records[0]
    seen = set()
    for row in csv.reader(io.StringIO(result[record].decode("utf-8"))):
        require(len(row) == 3 and row[0] in result and row[0] not in seen, "RECORD entry")
        name, encoded, size = row
        seen.add(name)
        if name == record:
            require(encoded == size == "", "RECORD self entry")
        else:
            expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(result[name]).digest()).decode().rstrip("=")
            require(encoded == expected and size == str(len(result[name])), "RECORD digest/size")
    require(seen == set(result), "RECORD coverage")
    return result


def tool_wheel(data, pin):
    require(digest(data) == pin["sha256"], "tool wheel digest")
    files = wheel_files(data, pin["filename"])
    for path in files:
        require(not path.lower().endswith((".dll", ".pyd", ".so")), "unexpected native build tool")
        if path.lower().endswith(".exe"):
            allowed = {"pip/_vendor/distlib/" + n for n in
                       ("t32.exe", "t64.exe", "t64-arm.exe", "w32.exe", "w64.exe", "w64-arm.exe")}
            allowed |= {"setuptools/" + n for n in
                        ("cli.exe", "cli-32.exe", "cli-64.exe", "cli-arm64.exe",
                         "gui.exe", "gui-32.exe", "gui-64.exe", "gui-arm64.exe")}
            require(path in allowed, "unexpected executable launcher")
    metadata = [p for p in files if p.endswith(".dist-info/METADATA")
                and len(PurePosixPath(p).parts) == 2]
    require(len(metadata) == 1, "tool METADATA")
    expected_metadata = pin["name"].replace("-", "_") + "-" + pin["version"] + ".dist-info/METADATA"
    require(metadata[0] == expected_metadata, "tool identity")
    m = BytesParser().parsebytes(files[metadata[0]])
    require(m["Name"].lower().replace("_", "-") == pin["name"].lower().replace("_", "-")
            and m["Version"] == pin["version"], "tool identity")
    # No unreviewed dependency resolution. Extra-only dependencies are never installed.
    require(all("extra ==" in r or "extra==" in r for r in m.get_all("Requires-Dist", [])), "unexpected mandatory dependency")
    return files


def candidate_wheel(data, filename, expected_filename):
    require(filename == expected_filename, "candidate tag/name")
    files = wheel_files(data, filename)
    tags = BytesParser().parsebytes(files["cffi-2.1.1.dist-info/WHEEL"])
    require(tags.get_all("Tag") == ["cp312-cp312-win_amd64"] and
            tags.get("Root-Is-Purelib") == "false", "candidate wheel tags")
    binaries = [p for p in files if p.lower().endswith((".pyd", ".dll", ".exe", ".so"))]
    require(binaries == ["_cffi_backend.cp312-win_amd64.pyd"], "candidate native members")
    pe = files[binaries[0]]
    require(len(pe) > 128 and pe[:2] == b"MZ", "candidate PE")
    offset = struct.unpack_from("<I", pe, 60)[0]
    require(offset <= len(pe) - 24 and pe[offset:offset + 4] == b"PE\0\0"
            and struct.unpack_from("<H", pe, offset + 4)[0] == 0x8664, "candidate AMD64")
    m = BytesParser().parsebytes(files["cffi-2.1.1.dist-info/METADATA"])
    require(m["Name"] == "cffi" and m["Version"] == "2.1.1", "candidate identity")
    return {"filename": filename, "bytes": len(data), "sha256": digest(data),
            "native_path": binaries[0], "native_sha256": digest(pe)}


def selected_download(metadata, pin):
    rows = [r for r in metadata["urls"] if r["filename"] == pin["filename"]]
    require(len(rows) == 1, "exact distribution file")
    row = rows[0]
    require(row["digests"]["sha256"] == pin["sha256"] and not row.get("yanked"), "distribution pin")
    from urllib.parse import urlsplit
    url = urlsplit(row["url"])
    require(url.scheme == "https" and url.hostname == "files.pythonhosted.org"
            and not url.username and not url.password and url.port in (None, 443)
            and not url.query and not url.fragment and url.path.endswith("/" + pin["filename"]), "distribution origin")
    require(0 < row["size"] <= 8 * 1024 * 1024, "distribution bytes")
    return row
