# AI Agency — Risk Appetite Statement

**Document ID:** AI-RISK-001  
**Owner:** Chief Risk Officer (or CISO where combined)  
**Approver:** Board Risk Committee  
**Tied to:** Policy AI-CTRL-001 · Governed Velocity  
**Review:** Annual · after any S1 agent incident  

---

## 1. Purpose

State what risk from AI **agency** the enterprise will seek, accept, or refuse — in plain language leaders can enforce without a model PhD.

## 2. Appetite summary

| Domain | Appetite | Meaning |
|--------|----------|---------|
| Productivity AI (draft, summarize, suggest) | **Open** | Encourage under Contract |
| Tool-using agents in prod | **Cautious** | Allowed when DoD + on-plane + least agency |
| Agents with irreversible side effects | **Restricted** | Dual control mandatory; narrow toolbox |
| Autonomous money movement / IAM change | **Averse** | Human-authorized systems only; no agent sole authority |
| Fail-open mediation on tier-1 | **Refuse** | Never |
| Unmanaged prod provider keys | **Refuse** | Never |
| Permanent Contract exceptions | **Refuse** | Never |
| Residual prompt-injection risk | **Accept (bounded)** | Assume hijack; require containment |

## 3. Statements the Board adopts

1. We prefer **governed velocity** over unmediated speed.  
2. We accept that models can be fooled; we do not accept unbounded blast radius.  
3. We measure success by outcome integrity, revoke time, and evidence — not refusal rates.  
4. We will defer revenue features that cannot meet the Agency Contract.  
5. We will disclose residual risk honestly in day-90 and annual reports.  

## 4. Triggers that tighten appetite

- S1 agent incident  
- Material regulator inquiry  
- Cyber insurance condition breach  
- Governance SLO Red &gt; 7 days (Identity / Escalation / Ledger)  
- Acquisition introducing uncontrolled agency (see M&A addendum)  

On trigger: OACP freeze on net-new prod agents until CISO/CRO reset appetite.

## 5. Metrics that prove appetite is real

On-plane coverage · unmanaged keys = 0 · dual-approval coverage · revoke ≤ 15m · export ≤ 60m · exceptions aged · open RT P1/P2  

If metrics are green but irreversible autonomy expands quietly, appetite is theater — reopen this statement.

---

**Committee approval**

| Role | Name | Date |
|------|------|------|
| CRO / Risk Chair | Program Owner | 2026-08-06 |
| CISO | Program Owner | 2026-08-06 |
| CEO (acknowledge) | Program Owner | 2026-08-06 |

**Adoption:** AI-RISK-001 adopted 2026-08-06 under attestation `PROG-LRS-2026-08-06` (Technology Committee / Program Owner consolidated).
