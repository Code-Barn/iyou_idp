# Copyright (C) 2026 David Byers dba Byers Brands
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import subprocess
import sys
from pathlib import Path


def _run_git_cmd(args: list[str], cwd: Path) -> tuple[int, str]:
    res = subprocess.run(
        ["git", "-C", str(cwd)] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    return res.returncode, res.stdout.strip()


def get_commit_sha(repo_path: Path) -> str:
    code, out = _run_git_cmd(["rev-parse", "HEAD"], repo_path)
    if code != 0 or not out:
        sys.stderr.write(f"ERROR: Failed to resolve HEAD for {repo_path}\n")
        sys.exit(1)
    return out


def is_working_tree_clean(repo_path: Path) -> bool:
    code, out = _run_git_cmd(["status", "--porcelain"], repo_path)
    if code != 0:
        sys.stderr.write(f"ERROR: Failed to check working tree status for {repo_path}\n")
        sys.exit(1)
    return len(out.strip()) == 0


def verify_did_rust_pin() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    submodule_path = repo_root / "crates" / "did_rust"

    if not submodule_path.is_dir() or not (submodule_path / ".git").exists():
        sys.stderr.write(f"ERROR: Submodule {submodule_path} is not initialized.\n")
        return 1

    if not is_working_tree_clean(submodule_path):
        sys.stderr.write(
            f"ERROR: Submodule working tree at {submodule_path} has uncommitted changes.\n"
        )
        return 1

    submodule_sha = get_commit_sha(submodule_path)
    print(f"SEC-003: iyou_idp crates/did_rust HEAD: {submodule_sha}")

    sibling_home = repo_root.parent / "iyou_home" / "libs" / "did_rust"
    if sibling_home.is_dir() and (sibling_home / ".git").exists():
        home_sha = get_commit_sha(sibling_home)
        if home_sha != submodule_sha:
            sys.stderr.write(
                "SEC-003 PARITY VIOLATION: Submodule drift detected between consumers!\n"
                f"  iyou_idp (crates/did_rust):    {submodule_sha}\n"
                f"  iyou_home (libs/did_rust):      {home_sha}\n"
                "Both submodules must point to the identical did_rust commit.\n"
            )
            return 1
        print(f"SEC-003: iyou_home libs/did_rust parity verified ({home_sha})")

    canonical = repo_root.parent / "did_rust"
    if canonical.is_dir() and (canonical / ".git").exists():
        canonical_sha = get_commit_sha(canonical)
        if canonical_sha == submodule_sha:
            print(f"SEC-003: Submodule matches canonical did_rust HEAD ({canonical_sha})")
        else:
            print(
                f"SEC-003 NOTICE: Submodule ({submodule_sha[:12]}) differs from canonical HEAD ({canonical_sha[:12]})."
            )

    return 0


if __name__ == "__main__":
    sys.exit(verify_did_rust_pin())
