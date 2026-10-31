# AgentGuard Performance Test Results

Generated: 2026-10-31T17:36:53Z

## Machine Specification

- OS: Windows (Windows-11-10.0.26300-SP0)
- Python: 3.13.9
- CPU cores: 8

## Results

| Metric | Value |
|--------|-------|
| Total events | 10,000 |
| Batch size | 100 |
| Parse errors | 0 |
| Incidents detected | 0 |
| Generation time | 0.060s |
| Parse time | 0.042s |
| Detection time | 0.079s |
| **Total time** | **0.181s** |
| **Ingest rate** | **55,165 events/s** |
| Peak memory | 55.7 MB |

> [!NOTE]
> SIMULATION: synthetic events only. Detection pipeline runs in-process without database.
> Real ingest rate with SQLite persistence will be lower.