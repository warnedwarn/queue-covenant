# Requirement matrix

| Requirement | Code path | Evidence status |
|---|---|---|
| Consensus-bound source extraction | `_extract` refetches all slots and uses strict equality | PASS: forged digest rejected |
| Complete record coverage | Unique indexes and exact count enforced | PASS: direct suite |
| Deterministic outcome | Pairwise inversion loop in `audit_queue` | PASS: inversion and fair cases |
| Source attribution | Ordered URL and digest arrays | PASS: live proof stores four digests |
| Authorization and replay | Owner-only pre-review cancel; terminal audit | PASS: targeted test |
| Deployed-source match | Verification script | PASS: exact byte match |
