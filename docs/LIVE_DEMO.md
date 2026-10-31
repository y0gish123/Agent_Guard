# AgentGuard AI SOC — Live Demonstration Guide

This guide provides a comprehensive walk-through of the AgentGuard AI SOC product for judges, evaluators, and teammates. It covers live attack simulations, policy gateway enforcement, AI explanations, cryptographic audit verification, and replay fallback procedures.

---

## Architecture Overview

```
                         +-----------------------+
                         | React + Vite Frontend |
                         | (Port 5173 - Browser) |
                         +-----------+-----------+
                                     |
               SSE Live Stream / REST| API Calls (X-User, X-Role)
                                     v
+------------------------+  +-------------------+  +--------------------------+
| Telemetry Watchers     |->| FastAPI Gateway   |->| Mock Enforcement Tool    |
| - Collector (Logs)     |  | (Port 8000)       |  | / Clinic Portal API      |
| - File Watchdog        |  |                   |  | (Port 8001 / Port 8002)  |
| - DNS Watcher          |  | - Deterministic P1-P6|                          |
| - Mail Drop Watcher    |  | - Token Issuer    |  +--------------------------+
| - Telegram Bot         |  | - Hash Audit Chain|               ^
+------------------------+  +---------+---------+               |
            ^                         | Single-Use HMAC Token   |
            |                         +-------------------------+
   Simulated Attacks
   (Localhost only)
```

---

## 1. Quick Startup: Two Operational Modes

### Mode A: Full Live Environment (Recommended for Live Demo)
Starts all 4 services: Backend (8000), Mock Enforcement Tool (8001), Stub Clinic Site (8002), and Log Collector.

**Windows PowerShell:**
```powershell
.\scripts\live_up.ps1 -Mode guarded
```

**macOS / Linux Bash:**
```bash
bash scripts/live_up.sh guarded
```

Then in a second terminal, start the frontend:
```powershell
cd frontend
npm run dev
```
Open **http://localhost:5173** in your browser.

---

### Mode B: Lightweight Replay Mode (Fallback Mode)
If running offline or without background watchers, run the backend and mock tool, then seed the built-in demo scenarios.

**Windows PowerShell:**
```powershell
.\scripts\dev_up.ps1 -Mode guarded
```

In the frontend UI or terminal, click **Demo Tools -> Seed All Scenarios** (or `POST /api/demo/seed?scenario=all`).

---

## 2. Step-by-Step Live Demonstration Script

### Act 1: Telemetry Funnel & Noise Suppression
1. Navigate to the **SOC Overview** tab.
2. Note the **Telemetry Ingestion & Noise Reduction Funnel**:
   - Background telemetry generates benign raw events (e.g. routine file edits, scheduled backup tasks with `backup_agent.exe`).
   - The deterministic pipeline suppresses benign noise while surfacing correlated incidents.
3. Observe the connection pill in the header: **`● LIVE`** (connected via Server-Sent Events `/api/stream`).

---

### Act 2: Account Takeover & Out-of-Scope Target Gating (The Core Principle)
1. In a terminal, run the simulated account takeover attack against the stub clinic site:
   ```powershell
   python testbed/attack/takeover.py
   ```
2. Within seconds, a new incident appears in the dashboard:
   - **Title**: `Suspected account takeover for priya.rec`
   - **Category**: `Account Takeover`
   - **Severity**: `HIGH`
   - **Link Rule**: `LINK_SAME_USER_30M`
3. Click **Investigate →** to open the **Incident Detail Screen**:
   - **Correlated By Rule**: Shows temporal correlation between the 5 failed logins and anomalous success.
   - **Evidence Events Timeline**: Inspect the events. Note that all attribute data is rendered safely as data, not executable HTML.
   - **AI Investigation Panel**: Gemini Flash explains the attack in plain language for a clinic manager. Verified cited event badges (`evt-NNN ✓`) confirm evidence alignment.
4. **Demonstrating Safety Gate 1: Out-of-Scope Target Blocking (CEO Attack)**:
   - In the Response Gateway form, select Action: `lock_account`.
   - Enter Target: `ceo`.
   - Click **Evaluate Policy Preview →**.
   - **Result**: Deterministically **`BLOCK`** with reason code `TARGET_OUT_OF_SCOPE`. The gateway refuses to authorize an action against an unaffected user, preventing prompt injection sabotage.
5. **Demonstrating Safety Gate 2: Authorized In-Scope Response**:
   - Set Target to `priya.rec`. Click **Evaluate Policy Preview →**.
   - **Result**: Decision is **`REVIEW`** with consequence explanation: *"Temporarily disables user login on the clinic patient portal."*
   - Notice that if your role is `Staff (Analyst)`, the approval button is locked with *"Requires Approver role"*.
   - Switch Role to **`Approver (Lead)`** in the top navigation bar.
   - Select **Approve Action**, provide justification, and click **Submit APPROVE Decision**.
   - Click **Execute Authorized Action via Gateway**.
   - A single-use HMAC-SHA256 execution token is minted and validated by the enforcement tool.
   - **Result Banner**: Displays `EXECUTED_OK: Action executed successfully on target.`
   - In the stub clinic site, user `priya.rec` is now locked (HTTP 423 Locked on login attempt).

---

### Act 3: Web SQL Injection & Data Exfiltration Detection
1. Simulate SQL injection and traversal probes against the clinic web portal:
   ```powershell
   python testbed/attack/websqli.py
   ```
2. Observe the new incident:
   - **Category**: `Web Attack (SQLi)`
   - Policy allowlist permits: `isolate_host` or `revoke_session`.
3. Simulate bulk data extraction:
   ```powershell
   python testbed/attack/bulkexport.py
   ```
4. Observe the new incident:
   - **Category**: `Data Exfiltration`
   - Rule D1 fires on rapid patient record access thresholds.

---

### Act 4: Ransomware Burst Activity & Safe Sandbox Simulation
1. Simulate a ransomware file burst inside the dedicated sandbox directory (`C:/demo_sandbox/`):
   ```powershell
   python testbed/attack/file_burst_sim.py
   ```
   *(Note: Safe simulation only. Only touches test files in sandbox, never encrypts real data, rejects paths outside sandbox).*
2. The file watchdog detects the rapid renaming of files to `.locked`.
3. Observe incident:
   - **Category**: `Ransomware Activity`
   - **Severity**: `CRITICAL`
4. Restore sandbox test files at any time:
   ```powershell
   python testbed/attack/restore.py
   ```

---

### Act 5: Interactive Phishing Scanner
1. Navigate to the **Check Message** tab in the frontend.
2. Click **Load Phishing Sample** and click **Check Phishing Risk →**:
   - Calls `/api/phishing/check`.
   - Displays verdict pill **`🔴 RED: HIGH RISK`** with score `85/100`.
   - Breakdown lists detected heuristics: lookalike sender domains (`fakelogin-clinic-portal.org`), urgency pressure cues, and credential requests.
   - Automatically stores the check as an ingested telemetry event (`evt-100N`) so subsequent attacks by the same user escalate to `multi_stage`.
3. Click **Load Benign Sample** and verify it returns **`🟢 GREEN`**.

---

### Act 6: Cryptographic Audit Trail Verification
1. Navigate to the **Audit Trail** tab.
2. Review the chronological ledger: every candidate evaluation, policy decision, approval, and mock tool execution is recorded with its previous block hash and current block hash.
3. Click **Verify Hash Chain 🛡**:
   - Live backend verification executes SHA-256 recalculation across all blocks from genesis.
   - Displays **`✅ Verified Hash Chain Integrity (N blocks valid)`**.
   - If any record is tampered with out-of-band in the SQLite database, the badge immediately turns to **`❌ Tamper Detected`** pinpointing the exact modified sequence number.

---

## 3. Fallback Procedures (If Live Services Have a Hiccup)

If any background watcher or port is occupied during judging:
1. Open the UI and click **⚙ Demo Tools** in the top navigation bar.
2. Click **Seed All Scenarios**: Loads the pre-validated offline scenarios (`account`, `filebursts`, `poisoned`, `web_attack`).
3. Click **Reset Environment**: Instantly wipes the database back to clean genesis and resets the mock enforcement tool state.
4. Set `VITE_USE_FIXTURES=true` in `frontend/.env` to run the frontend entirely decoupled from any running backend.

---

## 4. Known Hackathon Limitations & Engineering Trade-offs

- **HMAC Shared Secret vs. Asymmetric Ed25519**: Single-use tokens currently use HMAC-SHA256 with a shared secret (`HMAC_SECRET`). In an enterprise multi-tenant deployment, asymmetric public-key cryptography (Ed25519) should be used so enforcement agents do not hold the signing key.
- **In-Memory State for Stub Site**: The stub clinic portal runs an in-memory session/lock store for rapid hackathon iteration rather than an external Redis cluster.
- **Language Gating (`ALLOW_UNREVIEWED_LANGS`)**: Non-English explanations (Hindi, Kannada) default to English unless explicitly enabled after native security analyst review to avoid translation drift on critical security advice.

