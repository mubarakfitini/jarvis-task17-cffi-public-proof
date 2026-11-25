"""Read artifact data and optionally verify signatures; never import the candidate wheel."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_candidate import context
from guards import candidate_wheel, context_guard, digest, require, GENERATED_METADATA, read_bounded, hash_file


def artifact_allowlist(root, manifest):
    expected = {manifest["expected_wheel"], "build-record.json", "toolchain.json", "compiler-selection.json"}
    expected |= {f"stage-{i}.log" for i in range(1, 8)}
    require({p.name for p in root.iterdir()} == expected, "artifact exact allowlist")
    require(all(p.is_file() and not p.is_symlink() for p in root.iterdir()), "artifact regular files")


def inspect_artifact(root, manifest, expected_commit, run_id, manifest_sha256):
    record = json.loads(read_bounded(root / "build-record.json", 1024 * 1024))
    require(record["success"] is True and record["fixture_cleanup_verified"] is True
            and record["preserved_source_archive"] is True, "build/cleanup/source evidence")
    require(record["context"]["sha"] == expected_commit and record["run_id"] == run_id,
            "artifact build identity")
    require(record["source_sha256"] == manifest["source"]["sha256"], "artifact source")
    require(record["reference_source_verified_unchanged"] is True and
            len(record["generated_metadata_comparisons"]) == 9 and
            {r["path"] for r in record["generated_metadata_comparisons"]} == set(GENERATED_METADATA), "source reference evidence")
    require(record["manifest_sha256"] == manifest_sha256 and
            record["context"]["repository"] == manifest["repository"] and
            record["context"]["repository_id"] == manifest["repository_id"], "artifact manifest/repository")
    require(len(record["rebuilt_obj_sha256"]) == 64 and
            record["assembly_sha256"] == "020ed36b231fadd51fcd93c1a92648c1346df9ec6a536ae892b807aed20cc1ad",
            "assembly evidence")
    require(record["public_smoke"] == "PASS" and record["source_regular_files_verified"] == 222, "artifact checks")
    require(record["strict_release_gate_closed"] is False and
            record["target_3_12_14_compatibility_proven"] is False, "bounded scope")
    info = candidate_wheel(read_bounded(root / manifest["expected_wheel"], 8 * 1024 * 1024), manifest["expected_wheel"], manifest["expected_wheel"])
    require(record["wheel"] == info, "wheel readback")
    return info


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true", "GitHub only")
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    raw = read_bounded(root / "inputs/manifest.json", 1024 * 1024)
    manifest = json.loads(raw)
    ctx = context()
    context_guard(ctx, manifest, os.environ["APPROVED_COMMIT"], raw, os.environ["APPROVED_MANIFEST"])
    artifact = root / "candidate"
    require(artifact.is_dir() and not artifact.is_symlink(), "artifact directory")
    require(all(p.is_file() and not p.is_symlink() for p in artifact.iterdir()), "flat regular outputs")
    require(sum(p.stat().st_size for p in artifact.iterdir()) <= manifest["limits"]["artifact_max_bytes"], "artifact size")
    artifact_allowlist(artifact, manifest)
    info = inspect_artifact(artifact, manifest, ctx["sha"], os.environ["GITHUB_RUN_ID"], digest(raw))
    if sys.argv[1:] == ["inspect"]:
        print("PASS: bounded artifact integrity and build record; not release admission")
        return
    require(sys.argv[1:] == ["verify"], "verification mode")
    bundle = Path(os.environ["ATTESTATION_BUNDLE"])
    require(bundle.is_file() and bundle.stat().st_size <= 4 * 1024 * 1024, "attestation bundle")
    gh = shutil.which("gh")
    require(gh is not None, "preinstalled GitHub CLI")
    command = [gh, "attestation", "verify", "--bundle", str(bundle), "--repo", manifest["repository"],
               "--signer-workflow", manifest["repository"] + "/.github/workflows/cffi-proof.yml",
               "--source-digest", ctx["sha"], "--signer-digest", ctx["sha"], "--source-ref", "refs/heads/main",
               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
               "--deny-self-hosted-runners", "--format", "json"]
    evidence = root / "verified"
    evidence.mkdir(exist_ok=False)
    for name in (manifest["expected_wheel"], "build-record.json"):
        output = evidence / (name + ".verification.json")
        with output.open("xb") as stream:
            subprocess.run([*command, str(artifact / name)], stdout=stream, check=True, timeout=90)
        require(output.stat().st_size <= 4 * 1024 * 1024, "verification output cap")
        require(isinstance(json.loads(read_bounded(output, 4 * 1024 * 1024)), list) and json.loads(read_bounded(output, 4 * 1024 * 1024)), "verification result")
    (evidence / "attestation-bundle.json").write_bytes(read_bounded(bundle, 4 * 1024 * 1024))
    (evidence / "verification-summary.json").write_text(json.dumps({
        "repository": manifest["repository"], "commit": ctx["sha"], "run_id": os.environ["GITHUB_RUN_ID"],
        "wheel": info, "gh_executable_sha256": hash_file(Path(gh)),
        "signature_checks_returned_success": True,
        "scope": "Workflow identity, exact commit, source ref and artifact digest verified. Claims about compiler actions remain evidence to review.",
        "target_3_12_14_compatibility_proven": False, "strict_release_gate_closed": False
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
