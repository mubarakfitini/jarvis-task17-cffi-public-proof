# Public CFFI source-build experiment

This repository holds a single isolated Windows AMD64 / CPython 3.12 build experiment for public CFFI 2.1.1. It contains no private application code, account data, database, credentials or conversation history. Nothing deploys to an application or package registry.

The workflow is manually dispatched. Uploading it does not start a build. Execution requires a separately reviewed exact commit and `inputs/manifest.json` digest. Only the owner may dispatch the first attempt of this workflow; reruns and later run numbers are refused.

## Inputs and scope

The CFFI source archive is retained unchanged and checked against its exact SHA-256 and every regular-file digest before extraction. Its raw comparison with the upstream tag has 205 matches, 8 differences and 9 additional metadata paths. The eight differences are Git symbolic links represented as regular target content in the archive. These counts remain unchanged; no full-tree equality or upstream signing trust is claimed.

The Windows source build normally links a bundled `win64.obj`. This experiment preserves that object in its disposable work copy and rebuilds it from the exact `win64.asm` using the recorded Microsoft assembler. A preserved reference copy must remain byte-identical. The separate build copy keeps source and configuration exact; changes to the nine known generated metadata paths are reported with before/after hashes. setup.cfg remains an exact-configuration requirement. Raw differences are never normalized. The unrelated bundled ARM64 library is not part of this AMD64 target.

Exact pip, setuptools and pycparser wheel digests are locked. They are fetched once, verified and inspected before import in a new disposable virtual environment. There is no dependency resolution or fallback. Pip/setuptools may contain fixed bundled Windows launchers; these are inventoried and are not invoked as launchers. Public synthetic checks exercise memory, UTF-8 and a libffi callback through the newly built extension.

## Execution boundaries

There are two fresh standard hosted jobs: Windows build (20 minutes), then Linux artifact inspection, signing and verification (10 minutes). This replaces the initial single-job proposal so that source-build code receives no OIDC or attestation-write permission. Only the signing job receives those short-lived job permissions. No repository secret is referenced. The Linux job never imports or executes the Windows wheel.

The Windows image must match the reviewed image identity. Compiler, assembler, linker and interpreter paths, hashes, versions and Windows signature observations are captured. After rejecting inherited overrides, DISTUTILS_USE_SDK binds the admitted VC environment. A probe in the locked backend environment must select the same compiler and linker paths and hashes before CFFI compilation. The foundation assumption is the specified GitHub-hosted image, Microsoft-signed MSVC 14.44 tools and PSF-signed Python 3.12.10. These observations do not establish full source-to-binary provenance of those tools or the OS.

Each build child has an eight-minute bound. Logs and outputs have size caps; the disposable workspace has a monitored 4 GiB budget, not an OS-enforced disk quota. A limit breach terminates the child tree. The job timeout and hosted-runner disposal are the final containment boundaries. No automatic retry is permitted. The temporary work directory must be removed and that removal verified before signing is allowed. Logs are hashed as a stream and only bounded head/tail bytes are exported. Their original size/hash and truncation state are recorded, including after a log-limit failure. Fixed phase and guard-code diagnostics identify the failing boundary. Artifacts have one-day retention; this is distinct from immediate workspace cleanup.

The signing job first checks an exact output-file allowlist and attests only the explicitly named wheel and build record, then verifies exact repository/workflow, commit, ref and artifact digest using the preinstalled GitHub CLI. Signed predicates still contain build claims that require review; this is not a claim of a hardened SLSA level or complete transitive toolchain trust.

The build uses Python 3.12.10 only in the disposable runner. Compatibility with a separate selected Python 3.12.14 runtime remains unproved. Existing binary/signature/application proofs do not transfer to these replacement bytes. No strict release checker is changed or automatically marked passed. No broader task is completed by this experiment.
