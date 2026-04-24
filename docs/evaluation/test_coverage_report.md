# Test Coverage Report

Generated: 2026-04-23
Command: `python -m pytest tests/ --cov=Model_Pipeline --cov-report=term-missing`

## Test Execution

- Total tests: 43
- Passed: 43
- Failed: 0

## Coverage Summary

| File | Stmts | Miss | Cover | Missing Lines |
|---|---:|---:|---:|---|
| Model_Pipeline/__init__.py | 0 | 0 | 100% | - |
| Model_Pipeline/ai_detector.py | 44 | 5 | 89% | 42-43, 48-50 |
| Model_Pipeline/extract_features.py | 38 | 5 | 87% | 14-16, 19-20 |
| Model_Pipeline/hybrid_detector.py | 24 | 3 | 88% | 23-28 |
| Model_Pipeline/rule_detector.py | 29 | 0 | 100% | - |
| **TOTAL** | **135** | **13** | **90%** | - |

## Notes

- `Model_Pipeline/main_monitor.py` is intentionally excluded from coverage because it is a continuous live-monitoring loop (`while True`) used in runtime operations.
- Full HTML coverage output is generated locally in `htmlcov/`.
