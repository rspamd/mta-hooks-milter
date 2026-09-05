"""Fail when Cargo's source archive contains files outside the release allowlist."""
import pathlib
import subprocess


root = pathlib.Path(__file__).resolve().parent.parent
files = subprocess.check_output(
    ["cargo", "package", "--locked", "--allow-dirty", "--list"], cwd=root, text=True
).splitlines()
allowed = {
    "Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json",
    "README.md", "LICENSE.md", "NOTICE", "CHANGELOG.md", "CONTRIBUTING.md",
    "SECURITY.md", "RELEASING.md", "interop/README.md", "interop/Dockerfile",
    "interop/postfix_test.py", ".dockerignore", "scripts/check_package.py",
}
required = {"Cargo.toml", "Cargo.lock", "LICENSE.md", "NOTICE", "src/lib.rs", "src/main.rs"}
unexpected = [name for name in files if name not in allowed and not (
    name.startswith(("src/", "tests/", "examples/")) and name.endswith(".rs")
)]
missing = required.difference(files)
if unexpected or missing:
    raise SystemExit(f"Unexpected package files: {unexpected}; missing: {sorted(missing)}")
print(f"Package allowlist passed: {len(files)} files, no local logs or unexpected files")
