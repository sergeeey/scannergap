"""BlindSpotSec — Security Blind Spot Scanner.

Meta-scanner that finds vulnerability classes systematically missed
by ALL standard SAST scanners (CodeQL, Semgrep, Snyk, Bandit).

Methodology transferred from ARCHCODE genomics project:
- Quadrant analysis for blind spot detection
- Kill criteria for falsification
- Per-class threshold calibration
"""

__version__ = "0.1.0"
