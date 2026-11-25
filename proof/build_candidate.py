"""One disposable GitHub Windows build; never invoke this on a retained host."""
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import venv
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guards import (archive_files, candidate_wheel, context_guard, digest,
                    require, selected_download, tool_wheel, summarize_log, source_readback, read_bounded, hash_file)


def context():
    event = json.loads(read_bounded(Path(os.environ["GITHUB_EVENT_PATH"]), 1024 * 1024))
    require(event["repository"]["private"] is False, "public event repository")
    return {"repository": event["repository"]["full_name"], "actor": os.environ["GITHUB_ACTOR"],
            "repository_id": str(event["repository"]["id"]), "owner_id": str(event["repository"]["owner"]["id"]),
            "visibility": "public", "event": os.environ["GITHUB_EVENT_NAME"],
            "ref": os.environ["GITHUB_REF"], "sha": os.environ["GITHUB_SHA"],
            "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "run_number": os.environ["GITHUB_RUN_NUMBER"]}


def fetch(url, cap):
    # No retries, credentials, alternative indexes, or redirect to another origin.
    request = urllib.request.Request(url, headers={"User-Agent": "CFFI-public-build-proof/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        require(response.url == url, "unexpected download redirect")
        data = response.read(cap + 1)
    require(len(data) <= cap, "download cap")
    return data


def tree_bytes(root):
    total = 0
    for path in root.rglob("*"):
        require(not path.is_symlink(), "unexpected workspace symlink")
        if path.is_file():
            total += path.stat().st_size
    return total


def run_checked(argv, cwd, env, work, log, limits, commands):
    require(not log.exists(), "fresh log")
    commands.append([str(x) for x in argv])
    with log.open("xb") as stream:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        start = time.monotonic()
        try:
            while child.poll() is None:
                require(time.monotonic() - start <= limits["child_timeout_seconds"], "child timeout")
                require(log.stat().st_size <= limits["log_max_bytes"], "log cap")
                require(tree_bytes(work) <= limits["workspace_budget_bytes"], "workspace budget")
                time.sleep(0.25)
        finally:
            if child.poll() is None:
                # Only this fresh fixture's child tree. The job timeout/disposal remains the final bound.
                subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                                "/PID", str(child.pid), "/T", "/F"],
                               stdout=stream, stderr=subprocess.STDOUT, timeout=15, check=True)
                child.wait(timeout=15)
    require(log.stat().st_size <= limits["log_max_bytes"], "completed log cap")
    require(child.returncode == 0, "child failed: " + log.name)
    require(tree_bytes(work) <= limits["workspace_budget_bytes"], "completed workspace budget")


def main():
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true", "GitHub Windows only")
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    manifest_bytes = read_bounded(root / "inputs/manifest.json", 1024 * 1024)
    manifest = json.loads(manifest_bytes)
    ctx = context()
    context_guard(ctx, manifest, os.environ["APPROVED_COMMIT"], manifest_bytes,
                  os.environ["APPROVED_MANIFEST"])
    require(os.environ.get("ImageOS") == manifest["runner"]["ImageOS"] and
            os.environ.get("ImageVersion") == manifest["runner"]["ImageVersion"], "reviewed image")
    require(platform.python_version() == "3.12.10" and platform.machine().upper() == "AMD64", "builder Python")
    expected_python = (Path(os.environ["RUNNER_TOOL_CACHE"]) /
                       manifest["runner"]["python_relative_path"]).resolve()
    require(Path(sys.executable).resolve() == expected_python, "exact builder path")
    require(os.environ.get("VSCMD_ARG_TGT_ARCH") == "x64", "x64 developer environment")
    temp_root = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(temp_root.is_dir(), "fixture temp root")
    out = root / "out"
    out.mkdir(exist_ok=False)
    record = {"schema": "cffi-public-source-build.v1", "context": ctx,
              "run_id": os.environ["GITHUB_RUN_ID"], "repository_id": os.environ["GITHUB_REPOSITORY_ID"],
              "manifest_sha256": digest(manifest_bytes), "source_sha256": manifest["source"]["sha256"],
              "image": {"os": os.environ["ImageOS"], "version": os.environ["ImageVersion"]},
              "commands": [], "success": False, "fixture_cleanup_verified": False,
              "target_3_12_14_compatibility_proven": False, "strict_release_gate_closed": False}
    record["context"] = ctx
    record["run_id"] = os.environ["GITHUB_RUN_ID"]
    work = None
    phase = "FIXTURE_SETUP"
    try:
        with tempfile.TemporaryDirectory(prefix="cffi-public-proof-", dir=temp_root) as directory:
            work = Path(directory).resolve()
            require(work.is_relative_to(temp_root) and work.name.startswith("cffi-public-proof-"), "cleanup boundary")
            env = dict(os.environ)
            env.update(TEMP=str(work), TMP=str(work), PIP_NO_INDEX="1", PIP_NO_CACHE_DIR="1",
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1", VSLANG="1033")
            env.pop("PYTHONPATH", None)
            for key in ("CFFI_FORCE_STATIC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "CL", "_CL_", "LINK", "_LINK_", "DISTUTILS_USE_SDK", "MSSdk"):
                require(not env.get(key), "unreviewed compiler override: " + key)
            limits = manifest["limits"]
            stage = 0

            def run(argv, cwd=work):
                nonlocal stage
                stage += 1
                record["last_child_stage"] = stage
                log = work / f"stage-{stage}.log"
                try:
                    run_checked(argv, cwd, env, work, log, limits, record["commands"])
                finally:
                    if log.is_file():
                        info, exported = summarize_log(log)
                        record.setdefault("logs", []).append({"stage": stage, **info})
                        (out / log.name).write_bytes(exported)

            phase = "TOOLCHAIN_ADMISSION"
            tools = {"python": str(expected_python)}
            for name in ("cl", "link", "ml64"):
                found = shutil.which(name + ".exe")
                require(found is not None, "compiler tool missing: " + name)
                path = Path(found).resolve()
                require("Microsoft Visual Studio" in str(path) and "/Hostx64/x64/" in path.as_posix()
                        and "/MSVC/14.44." in path.as_posix(), "reviewed compiler family/path")
                tools[name] = str(path)
            tool_input = work / "tool-paths.json"
            tool_input.write_text(json.dumps(tools), encoding="utf-8")
            run(["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(root / "proof/tool-signatures.ps1"),
                 "-PathsJson", str(tool_input), "-OutputFile", str(out / "toolchain.json")])
            signatures = json.loads(read_bounded(out / "toolchain.json", 1024 * 1024))
            require(set(signatures) == set(tools), "toolchain evidence roles")
            for role, row in signatures.items():
                expected_signer = "Python Software Foundation" if role == "python" else "Microsoft Corporation"
                require(row["status"] == "Valid" and expected_signer in row["signer"], "toolchain signer")
                require(row["sha256"].lower() == hash_file(Path(tools[role])), "toolchain bytes")
            record["toolchain"] = signatures
            env["DISTUTILS_USE_SDK"] = "1"
            env["MSSdk"] = "1"
            record["compiler_environment_binding"] = {"DISTUTILS_USE_SDK": "1", "MSSdk": "1"}
            phase = "SOURCE_REFERENCE"
            data = read_bounded(root / "inputs/cffi-2.1.1.tar.gz", 530807, 530807)
            inventory = json.loads(read_bounded(root / "inputs/source-files.json", 1024 * 1024))
            require(digest(read_bounded(root / "inputs/source-files.json", 1024 * 1024)) == manifest["source_inventory_sha256"], "inventory digest")
            files = archive_files(data, manifest["source"], inventory)
            reference = work / "reference"
            reference.mkdir()
            for name, payload in files.items():
                target = reference / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    stream.write(payload)
            source = work / "build-source"
            shutil.copytree(reference, source)
            record["source_regular_files_verified"] = len(files)
            phase = "LOCKED_BUILD_TOOLS"
            wheels = work / "locked-wheels"
            wheels.mkdir()
            for pin in manifest["build_wheels"]:
                metadata = json.loads(fetch(f"https://pypi.org/pypi/{pin['name']}/{pin['version']}/json", 2 * 1024 * 1024))
                item = selected_download(metadata, pin)
                payload = fetch(item["url"], item["size"])
                require(len(payload) == item["size"] and digest(payload) == pin["sha256"], "locked wheel digest")
                contents = tool_wheel(payload, pin)
                record.setdefault("build_wheels", []).append({**pin, "bytes": len(payload),
                       "bundled_launcher_executables": [n for n in contents if n.endswith(".exe")],
                       "launcher_execution": False})
                with (wheels / pin["filename"]).open("xb") as stream:
                    stream.write(payload)
            phase = "VENV_BOOTSTRAP"
            environment = work / "venv"
            venv.EnvBuilder(with_pip=False).create(environment)
            python = environment / "Scripts/python.exe"
            pip_wheel = wheels / next(p["filename"] for p in manifest["build_wheels"] if p["name"] == "pip")
            bootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
            locked = [str(wheels / pin["filename"]) for pin in manifest["build_wheels"]]
            run([str(python), "-I", "-B", "-c", bootstrap, str(pip_wheel), "--isolated", "install",
                 "--no-index", "--no-deps", "--no-compile", "--no-cache-dir", "--disable-pip-version-check", *locked])
            phase = "BACKEND_COMPILER_BINDING"
            run([str(python), "-I", "-B", str(root / "proof/compiler_selection.py"), str(out / "compiler-selection.json")])
            selected = json.loads(read_bounded(out / "compiler-selection.json", 1024 * 1024))
            require(selected["setuptools_version"] == "84.2.1" and selected["DISTUTILS_USE_SDK"] == "1", "backend environment binding")
            for role in ("cl", "link"):
                require(Path(selected["paths"][role]).resolve() == Path(tools[role]).resolve() and
                        selected["sha256"][role] == hash_file(Path(tools[role])), "backend compiler selection: " + role)
            record["backend_compiler_selection"] = selected
            phase = "ASSEMBLY_REBUILD"
            obj = source / manifest["upstream_object"]
            record["upstream_obj_sha256"] = digest(read_bounded(obj, 8 * 1024 * 1024))
            obj.rename(obj.with_name("win64.upstream.obj"))
            run([tools["ml64"], "/nologo", "/c", "/Fo" + str(obj), str(source / manifest["assembly"])], source)
            require(obj.is_file() and obj.stat().st_size > 20 and read_bounded(obj, 8 * 1024 * 1024)[:2] == b"\x64\x86", "AMD64 assembler output")
            record["rebuilt_obj_sha256"] = digest(read_bounded(obj, 8 * 1024 * 1024))
            record["assembly_sha256"] = digest(read_bounded(source / manifest["assembly"], 3096, 3096))
            phase = "CFFI_WHEEL_BUILD"
            result = work / "wheel-result"
            result.mkdir()
            run([str(python), "-I", "-B", "-m", "pip", "--isolated", "wheel", "--no-index", "--no-deps",
                 "--no-build-isolation", "--no-cache-dir", "--disable-pip-version-check", "--wheel-dir", str(result), str(source)], source)
            built = list(result.iterdir())
            phase = "WHEEL_AND_SOURCE_READBACK"
            require(len(built) == 1 and built[0].name == manifest["expected_wheel"], "one expected wheel")
            wheel_data = read_bounded(built[0], 8 * 1024 * 1024)
            record["wheel"] = candidate_wheel(wheel_data, built[0].name, manifest["expected_wheel"])
            record["generated_metadata_comparisons"] = source_readback(reference, source, files, manifest["upstream_object"])
            require(digest(read_bounded(obj, 8 * 1024 * 1024)) == record["rebuilt_obj_sha256"], "rebuilt object changed")
            record["reference_source_verified_unchanged"] = True
            phase = "PUBLIC_SMOKE"
            run([str(python), "-I", "-B", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
                 "--no-compile", "--no-cache-dir", "--disable-pip-version-check", str(built[0])])
            smoke = ("import cffi,sys;from pathlib import Path;assert cffi.__version__=='2.1.1';"
                     "assert Path(cffi.__file__).resolve().is_relative_to(Path(sys.prefix).resolve());"
                     "f=cffi.FFI();p=f.new('int *',41);assert p[0]==41;p[0]+=1;assert p[0]==42;"
                     "b=f.new('char[]','CafÃ©'.encode());assert f.string(b).decode()=='CafÃ©';"
                     "cb=f.callback('int(int)',lambda x:x+1);assert cb(41)==42;print('PASS: public CFFI smoke')")
            run([str(python), "-I", "-B", "-c", smoke])
            record["public_smoke"] = "PASS"
            phase = "CANDIDATE_EXPORT"
            (out / built[0].name).write_bytes(wheel_data)
            record["success"] = True
    except Exception as exc:
        record["failure_type"] = type(exc).__name__
        record["failure_phase"] = phase
        record["guard_code"] = getattr(exc, "guard_code", "UNEXPECTED_EXCEPTION")
        # Do not leak exception strings, command output or full environment into summaries.
        raise
    finally:
        record["fixture_cleanup_verified"] = work is not None and not work.exists()
        record["preserved_source_archive"] = digest(read_bounded(root / "inputs/cffi-2.1.1.tar.gz", 530807, 530807)) == manifest["source"]["sha256"]
        record["workspace_budget_is_monitored_not_OS_quota"] = True
        (out / "build-record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        require(record["fixture_cleanup_verified"], "cleanup not verified")
        require(sum(p.stat().st_size for p in out.iterdir()) <= manifest["limits"]["artifact_max_bytes"], "output bytes")
    require(record["success"] and record["preserved_source_archive"], "build/source result")


if __name__ == "__main__":
    main()
