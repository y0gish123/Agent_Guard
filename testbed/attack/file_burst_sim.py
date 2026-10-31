"""File Burst / Ransomware Simulator [FILE-BURST SIMULATION].

Safety Principles:
- Strictly operates ONLY inside the resolved demo_sandbox/ directory.
- Path-escape verification refuses any path traversing outside demo_sandbox/.
- NO encryption, NO file content reading, NO external binaries.
- Purely renames existing dummy files to .locked (or .bak for benign mode).
- Drops a demonstration note: README_RESTORE_FILES.txt.
"""

import argparse
import os
from pathlib import Path
import sys
import time

EXPECTED_SANDBOX_DIR = Path(os.getenv("DEMO_SANDBOX_DIR", "demo_sandbox")).resolve()


def verify_sandbox_path(target_dir: Path) -> Path:
    """Ensure target_dir is strictly inside the resolved demo_sandbox directory."""
    resolved = target_dir.resolve()
    # Check if resolved path is exactly EXPECTED_SANDBOX_DIR or a subfolder
    try:
        resolved.relative_to(EXPECTED_SANDBOX_DIR)
    except ValueError:
        print(f"[FILE-BURST SIMULATION] ERROR: Path escape attempt detected! Target '{target_dir}' resolves to '{resolved}' which is OUTSIDE sandbox '{EXPECTED_SANDBOX_DIR}'. Refusing operation.")
        sys.exit(1)
    return resolved


def run_file_burst(
    target_dir: Path = EXPECTED_SANDBOX_DIR,
    extension: str = ".locked",
    duration_sec: float = 30.0,
    max_files: int = 150,
    drop_note: bool = True,
) -> int:
    safe_dir = verify_sandbox_path(target_dir)

    print("\n" + "=" * 60)
    print(" [FILE-BURST SIMULATION] Starting Safe File Burst Simulation")
    print(f" Sandbox Dir:    {safe_dir}")
    print(f" New Extension:  {extension}")
    print(f" Target Count:   {max_files} files")
    print(f" Duration:       ~{duration_sec}s")
    print(" Safety:         NO encryption, NO content reading, strictly sandbox-isolated.")
    print("=" * 60 + "\n")

    files = [p for p in safe_dir.glob("*.txt") if not p.name.startswith("README")]
    if not files:
        print(f"[FILE-BURST SIMULATION] No .txt files found in {safe_dir}. Creating 150 dummy files first...")
        from testbed.filemon.create_dummy_files import create_dummy_files
        create_dummy_files(max(150, max_files))
        files = [p for p in safe_dir.glob("*.txt") if not p.name.startswith("README")]

    files_to_rename = files[:max_files]
    interval = duration_sec / max(len(files_to_rename), 1)

    print(f"[FILE-BURST SIMULATION] Renaming {len(files_to_rename)} files to {extension}...")
    renamed = 0
    for f in files_to_rename:
        new_path = f.with_suffix(extension)
        try:
            f.rename(new_path)
            renamed += 1
            if interval > 0.05:
                time.sleep(interval)
        except Exception as exc:
            print(f"  Error renaming {f}: {exc}")

    # Drop note if requested and not benign mode
    if drop_note and extension != ".bak":
        note_path = safe_dir / "README_RESTORE_FILES.txt"
        with open(note_path, "w", encoding="utf-8") as f:
            f.write("=== [FILE-BURST SIMULATION] RANSOMWARE NOTE ===\n"
                    "Your files have been renamed for this cyber defense exercise.\n"
                    "No real encryption occurred. Run restore.py to restore.\n")
        print(f"[FILE-BURST SIMULATION] Created demonstration note at {note_path}")

    print(f"\n[FILE-BURST SIMULATION] Completed. Renamed {renamed} files.")
    return renamed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Burst / Ransomware Simulator [FILE-BURST SIMULATION]")
    parser.add_argument("--dir", default=str(EXPECTED_SANDBOX_DIR), help="Target sandbox directory")
    parser.add_argument("--ext", default=".locked", help="Extension to rename to (.locked or .bak)")
    parser.add_argument("--duration", type=float, default=2.0, help="Duration over which to rename files")
    parser.add_argument("--count", type=int, default=120, help="Number of files to rename")
    parser.add_argument("--no-note", action="store_true", help="Do not create ransom note")
    args = parser.parse_args()

    run_file_burst(
        target_dir=Path(args.dir),
        extension=args.ext,
        duration_sec=args.duration,
        max_files=args.count,
        drop_note=not args.no_note,
    )

