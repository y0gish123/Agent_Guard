"""Helper script to create 400 dummy demonstration files in demo_sandbox/."""

import os
from pathlib import Path

SANDBOX_DIR = Path(os.getenv("DEMO_SANDBOX_DIR", "demo_sandbox")).resolve()


def create_dummy_files(count: int = 400) -> None:
    SANDBOX_DIR.mkdir(exist_ok=True, parents=True)
    print(f"[FILE-BURST SIMULATION] Creating {count} dummy files in {SANDBOX_DIR}...")
    for i in range(1, count + 1):
        fpath = SANDBOX_DIR / f"patient_record_{i:03d}.txt"
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"Synthetic Patient Record #{i}\nDepartment: Outpatient Clinic\nConfidentiality: Medical Record\n")
    print(f"[FILE-BURST SIMULATION] Finished creating {count} files.")


if __name__ == "__main__":
    create_dummy_files(400)

