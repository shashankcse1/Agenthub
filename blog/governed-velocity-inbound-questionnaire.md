# Inbound Answers — Enterprise Security Questionnaire (AI Agency)

**Purpose:** Consistent answers when customers send SIG/CAIQ-style or custom AI questionnaires  
**Owner:** GTM Sec · **Accuracy A:** CISO  
**Rule:** If Leader Readiness Score &lt; 24, do not use “leader” language in answers

---

## Short-form answers (adapt)

**Q: Do you use AI/LLMs in the product?**  
A: Yes. Production AI agency is mediated through our AI control plane under an Agency Contract (identity, mandate, toolbox, escalation, fence, ledger).

**Q: How do you prevent prompt injection?**  
A: We do not claim elimination. We assume untrusted content can influence models and bound impact via least-agency tools, input/output policies, human escalation for irreversible acts, egress controls, and audited decisions.

**Q: Can the AI take actions in customer environments?**  
A: Only within allowlisted tools/scopes defined per agent Contract. Irreversible classes require human approval paths. Default is least agency.

**Q: Do you train on customer data?**  
A: [Fill per product policy — be exact]. Control-plane logging follows redaction/retention standards; prompts/secrets are not treated as free training corpus unless explicitly contracted.

**Q: Can we get audit logs of AI actions?**  
A: Material allow/deny decisions for inference/tool/egress/approvals are ledgered and exportable within our evidence RTO targets. Chat UI is not the system of record.

**Q: What is your incident response for AI misuse?**  
A: Agent incident playbook: revoke-first golden hour, privilege-graph scoping, fail-closed posture on tier-1, post-incident Contract revision. Comms use side-effect language, not “AI went rogue.”

**Q: Are you compliant with [framework]?**  
A: We map operationally to NIST AI RMF / OWASP LLM & agentic catalogs and maintain a crosswalk. Formal certification claims require Legal — we provide evidence of controls and drills rather than logo collection.

**Q: Can we disable AI features?**  
A: Yes — route/entitlement revoke and tool allowlist removal are supported; kill-switch drills are part of our governance SLOs.

---

## Attach when score allows

- Customer trust pack brief  
- Redacted SLO summary  
- Subprocessor / model routing statement  

**Never attach:** Internal anti-pattern scores, unreleased findings, raw prompts with secrets
