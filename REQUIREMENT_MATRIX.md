# Requirement matrix

| Requirement | Code path | Evidence status |
|---|---|---|
| Consensus-bound source extraction | `_extract` refetches all slots and uses strict equality | Pending test |
| Complete record coverage | Unique indexes and exact count enforced | Pending test |
| Deterministic outcome | Pairwise inversion loop in `audit_queue` | Pending test |
| Source attribution | Ordered URL and digest arrays | Pending live proof |
| Authorization and replay | Owner-only pre-review cancel; terminal audit | Pending test |
| Deployed-source match | Verification script | Pending deployment |
