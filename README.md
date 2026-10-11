# Queue Covenant

A public queue can obey every formality and still serve the wrong person first.

This contract freezes one service rule and three to eight public service records. Validators extract only the bounded facts needed for ordering: scope status, priority rank, receipt time, and service time. Contract code—not the model—then compares every pair and records each priority inversion.

The final docket is `FAIR`, `INVERSION`, or `INCONCLUSIVE`. Every source digest stays beside its exact slot, and a malformed or out-of-scope record can never be silently counted as fair.

Lifecycle: `OPEN -> FAIR | INVERSION | INCONCLUSIVE`, with owner-only cancellation before review.

The included records are operator-created technical fixtures, not independent government records.

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```
