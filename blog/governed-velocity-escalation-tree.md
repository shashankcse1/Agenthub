# Escalation Tree — AI Agency

**Keep with:** Field manual · war room · RACI  

---

## Tree

```text
Signal (anomaly / finding / launch pressure)
        │
        ▼
   Steward / On-call
        │
        ├─ Routine Contract/DoD help ──► OACP office hours
        │
        ├─ Exception request ──► Platform (feasible?) ──► CISO (risk A)
        │
        ├─ Governance SLO Red ──► OACP Head (freeze consider) ──► CISO/CTO
        │
        ├─ P1 RT / suspected S1 ──► IR Commander + war room
        │         │
        │         ├─ Customer/regulator impact? ──► Legal + Comms + CISO
        │         └─ Appetite trigger? ──► CRO / Risk Committee
        │
        └─ External claim pressure ──► Publish gate ──► CISO accuracy
                  │
                  └─ Readiness < 32 ──► DENY claim (no appeal to Marketing)
```

## Time expectations

| Path | First human response |
|------|----------------------|
| S1 war room | ≤ 15m |
| Exception | ≤ 5 business days to disposition |
| Freeze decision | ≤ 24h after SLO Red &gt; 7d threshold hit |
| Publish gate | ≤ 5 business days (conference deadline ≠ override) |

## Hard stops (no escalate-to-bypass)

- Fail-open tier-1  
- Permanent exception  
- Skip publish gate for “important” keynote  
