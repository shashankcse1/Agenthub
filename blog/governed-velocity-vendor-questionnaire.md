# Third-Party / Vendor AI Agency Questionnaire

**Purpose:** Procurement and security review for any vendor whose product can exercise agency inside our environment (agents, copilots, MCP, browser extensions, embedded tools).  
**Standard:** Governed Velocity — Agency Contract  
**Rule:** Incomplete answers are fails. Marketing language is not evidence.

---

## A. Identity & access

1. Does each customer-facing agent/workload use a distinct, revocable identity?  
2. Can we bring our own keys / route inference through our control plane?  
3. What is the maximum credential lifetime? Can we force rotate in &lt; 15 minutes?  
4. Are shared “tenant admin” keys required for day-to-day agent operation? (Yes = fail)  
5. Provide NHI / service account inventory export capability (Y/N + sample).

## B. Mandate & data

6. How do you prevent retrieved content (email, docs, web, tickets) from being treated as instructions?  
7. List data classes your agent can read/write by default.  
8. Can we enforce allow/warn/block/mask policies by data class before provider send?  
9. Is customer data used for training by default? How is opt-out evidenced?  
10. Describe RAG/corpus isolation between tenants (controls + test evidence).

## C. Toolbox & MCP

11. Enumerate all tools, plugins, and MCP servers the product can invoke.  
12. Is the tool graph default-deny with customer allowlist?  
13. Can tool arguments be schema-validated and policy-checked pre-execution?  
14. Can we disable browse / outbound fetch entirely?  
15. Document supply-chain provenance for tools/models (SBOM/AIBOM if any).

## D. Escalation

16. Which actions require human approval out of the box?  
17. Do you support dual control for production-impacting acts in our IdP?  
18. Can approvals be mandatory and non-bypassable by prompt?  
19. Provide an example approval audit record.

## E. Fence

20. Egress: default deny or default allow? Domain allowlist support?  
21. Rate limits and spend budgets: customer-configurable? Per agent?  
22. Kill switch: document steps and measured time-to-disable in a drill.  
23. What happens on policy fail — fail closed or fail open?

## F. Ledger

24. Are allow/deny decisions for tool calls immutably logged?  
25. Can we export evidence bundles filtered by actor, agent, time, decision?  
26. Retention defaults and customer-configurable retention?  
27. Can logs be shipped to our SIEM without content that violates our policy?

## G. Assurance

28. Map your controls to OWASP LLM Top 10 and Agentic risks (table).  
29. Date of last red team including indirect prompt injection and silent egress.  
30. Open critical findings and target remediation dates.  
31. Incident notification SLA to customers.  
32. Will you contractually commit to fail-closed on policy deny?

---

## Scoring

| Result | Rule |
|--------|------|
| Pass | All must-answer items evidenced; fail-closed on deny; revoke &lt; 15m; exportable ledger |
| Conditional | Time-bounded compensating controls + exception register |
| Fail | Shared god keys, fail-open denies, no tool allowlist, or no evidence export |

**Reviewer:** ________ **Date:** ________ **Disposition:** Pass / Conditional / Fail
