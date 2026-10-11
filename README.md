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

## StudioNet docket

- Contract: [`0x3621bb078ffcb1f678437db29dd9c10dA8A6CE70`](https://explorer-studio.genlayer.com/address/0x3621bb078ffcb1f678437db29dd9c10dA8A6CE70)
- Reviewed source: [`a76ed86`](https://github.com/warnedwarn/queue-covenant/tree/a76ed86cf5c83f887fba4a8c8c520d00a1cf6f0d)
- Live audit: `QUEUE-1791756981`, final state `INVERSION`, pair `[0,1]`.
- Deployment and audit transactions are preserved under `deployment.json` and `evidence/live-proof.json`.
- Verification: finalized, majority agree, successful execution, exact deployed-source match.
