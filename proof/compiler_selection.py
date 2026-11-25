"""Run only in the disposable admitted venv, after locked wheel checks."""
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guards import hash_file


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("DISTUTILS_USE_SDK") != "1":
        raise RuntimeError("Unadmitted compiler environment")
    import importlib.metadata
    from setuptools._distutils.compilers.C import msvc
    if importlib.metadata.version("setuptools") != "84.2.1":
        raise RuntimeError("Backend version")
    module = Path(msvc.__file__).resolve()
    if not module.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("Backend environment")
    compiler = msvc.Compiler()
    compiler.initialize("win-amd64")
    paths = {"cl": str(Path(compiler.cc).resolve()), "link": str(Path(compiler.linker).resolve())}
    result = {"paths": paths, "sha256": {n: hash_file(Path(p)) for n, p in paths.items()},
              "backend_module": str(module), "backend_sha256": hash_file(module),
              "setuptools_version": "84.2.1", "DISTUTILS_USE_SDK": "1"}
    with Path(sys.argv[1]).open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
