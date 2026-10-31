"""Restore script to revert dummy files back to original .txt extensions in demo_sandbox/."""

import os
from pathlib import Path
from testbed.attack.file_burst_sim import verify_sandbox_path

EXPECTED_SANDBOX_DIR = Path(os.getenv("DEMO_SANDBOX_DIR", "demo_sandbox")).resolve()


def restore_sandbox(target_dir: Path = EXPECTED_SANDBOX_DIR) -> int:
    safe_dir = verify_sandbox_path(target_dir)
    print(f"[FILE-BURST SIMULATION] Restoring files in {safe_dir}...")

    restored = 0
    # Revert .locked, .bak, .enc
    for ext in ("*.locked", "*.bak", "*.enc", "*.crypt"):
        for f in safe_dir.glob(ext):
            orig_path = f.with_suffix(".txt")
            f.rename(orig_path)
            restored += 1

    # Remove note files
    for n in safe_dir.glob("README*"):
        n.unlink(missing_ok=True)
    for n in safe_dir.glob("HOW_TO_DECRYPT*"):
        n.unlink(missing_ok=True)

    print(f"[FILE-BURST SIMULATION] Restored {restored} files back to .txt.")
    return restored


if __name__ == "__main__":
    restore_sandbox()

