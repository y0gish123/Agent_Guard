# AgentGuard Detection Validation Results

Generated: 2026-10-31T17:36:45Z

## Summary

| Metric | Value |
|--------|-------|
| True Positives  | 8 |
| True Negatives  | 6 |
| False Positives | 0 |
| False Negatives | 0 |
| Precision       | 100.0% |
| Recall          | 100.0% |
| False Positive Rate | 0.0% |

## Scenario Results

| Scenario | Expected | Actual | Result |
|----------|----------|--------|--------|
| Benign: one wrong password then correct login | TN | TN (0 incidents) | **TN** |
| Benign: owner login from new IP (single R3, no multi-signal) | TN | TN (0 incidents) | **TN** |
| Benign: normal shopping day (10 sequential data reads) | TN | TN (0 incidents) | **TN** |
| Benign: scheduled backup by backup_agent.exe | TN | TN (0 incidents) | **TN** |
| Benign: staff export of 10 records (below threshold) | TN | TN (0 incidents) | **TN** |
| Benign: new staff device (single auth success, no burst) | TN | TN (0 incidents) | **TN** |
| Attack: brute force + login success (R1+R2) | TP (account_takeover) | TP (1 incident(s)) | **TP** |
| Attack: session hijack (same session_id_hash, two IPs) | TP (account_takeover) | TP (1 incident(s)) | **TP** |
| Attack: password spray (1 IP, 6 distinct accounts) | TP (account_takeover) | TP (1 incident(s)) | **TP** |
| Attack: SQLi probe (W1 + W2 threshold) | TP (web_attack) | TP (1 incident(s)) | **TP** |
| Attack: D3 mass delete (35 delete events) | TP (data_exfiltration_suspected) | TP (1 incident(s)) | **TP** |
| Attack: file burst + backup tampering (F1+F2) | TP (ransomware_like_activity) | TP (1 incident(s)) | **TP** |
| Attack: bulk data export (D1, 1000 records) | TP (data_exfiltration_suspected) | TP (1 incident(s)) | **TP** |
| Attack: phishing + brute force (multi_stage) | TP (multi_stage) | TP (1 incident(s)) | **TP** |

> [!NOTE]
> This validation uses synthetic test vectors. Detection is deterministic and rule-based.
> Results reflect the configured thresholds (R1: ≥5 failures, D3: ≥30 deletes, etc.).