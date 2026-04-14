"""Quadrant analysis — coverage matrix and blind spot detection.

Adapted from ARCHCODE genomics methodology:
- Q1: Found by multiple scanners (consensus)
- Q2: Found by none = BLIND SPOT (our target)
- Q3: Found by only one scanner (partial coverage)
- Q4: Not a real vulnerability (true negatives)
"""
