"""Make the shared synthetic test generator (libs/hc_ml/tests/synth.py) importable for service tests."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
for candidate in (HERE.parents[3] / "libs" / "hc_ml" / "tests", HERE.parents[1]):
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
