# AI Gateway Leadership Capability Backlog (100)

Date: 2026-08-06  
Status: Complete 1–100 + Packs 10–16 (101–240) Done (GOV-AI-MARKET-001…016)  
Rule: Do not invent stub UIs. Ship packs of real API + tests + operator surface.

## Pack status

| Pack | Theme | Status |
|---|---|---|
| 1 | Market posture + readiness-aware fallback suggest | Done (GOV-AI-MARKET-001) |
| 2 | Auto-router + intended→actual per-request attribution | Done (GOV-AI-MARKET-002) |
| 3 | Leadership index + attribution analytics | Done (GOV-AI-MARKET-003) |
| 4 | Telemetry rankings + judge refine + warmup + Helicone chat fields | Done (GOV-AI-MARKET-004) |
| 5 | Ops pack: compare, export, history, alerts, presets, playground auto-route, ranking→fallback | Done (GOV-AI-MARKET-005) |
| 6 | Live judge gate, liquidity import, inventory, timeseries, A/B, quality gate, health, advisors | Done (GOV-AI-MARKET-006) |
| 7 | Prompt/VK policies, canary/mirror/cache metrics, alerts, QBR/compliance, SDK/OTel/Prom/Grafana | Done (GOV-AI-MARKET-007) |
| 8 | Deprecation, shadow, PII/residency, replay/CSV, warmup purge, weights, gates | Done (GOV-AI-MARKET-008) |
| 9 | Owner/tenant federation, model cards, signed evidence, CI/release, chaos, board, scorecard | Done (GOV-AI-MARKET-009) |
| 10 | Enforcement deepeners + alert delivery + ops hardening (101–120) | Done (GOV-AI-MARKET-010) |
| 11 | Live-path cache/flags/denylist + dashboard/ops deepeners (121–140) | Done (GOV-AI-MARKET-011) |
| 12 | Cache/ops residual close + posture digest (141–160) | Done (GOV-AI-MARKET-012) |
| 13 | Explainability + operator probes (161–180) | Done (GOV-AI-MARKET-013) |
| 14 | Decision audit + incident ops (181–200) | Done (GOV-AI-MARKET-014) |
| 15 | Composite gates + audit hygiene (201–220) | Done (GOV-AI-MARKET-015) |
| 16 | Executive moat + operator excellence (221–240) | Done (GOV-AI-MARKET-016) |

## Capability register (1–100)

### Done (1–100)

1. Best-practices posture scorecard — Done  
2. Readiness-aware fallback suggest — Done  
3. Complexity auto-router classify — Done  
4. Chat `model=auto` / `auto_route` — Done  
5. Intended→actual on chat — Done  
6. Intended→actual on execute-fallback — Done  
7. CostEvent attribution persistence — Done  
8. Attribution analytics rollups — Done  
9. Leadership index composite — Done  
10. Auto-router cost/quality/balanced strategies — Done  
11. Telemetry model rankings — Done  
12. Judge refine (heuristic) — Done  
13. Leadership warmup — Done  
14. Helicone session/user/properties on chat — Done  
15. Auto-route strategy compare — Done  
16. Attribution exclude-warmup filter — Done  
17. Leadership evidence export — Done  
18. Leadership snapshot history — Done  
19. Leadership soft alerts — Done  
20. SDK instrumentation presets — Done  
21. Ranking-aware fallback suggest — Done  
22. Savings estimate from tier mix — Done  
23. Circuit-breaker recommendations — Done  
24. Batch auto-route classify — Done  
25. Playground auto-route checkbox — Done  
26. Apply rankings into Route Priority chain — Done  
27. Download rankings JSON — Done  
28. Download attribution JSON — Done  
29. Download leadership evidence pack — Done  
30. Leadership history refresh UI — Done  

31. Live LLM judge refine (gated simulation-safe) — Done  
32. External OpenRouter liquidity import — Done  
33. Per-tenant binding readiness inventory — Done  
34. Intended→actual hourly timeseries chart API — Done  
35. Auto-route A/B experiment records — Done  
36. Fallback quality gate before promote — Done  
37. Provider health score from hop failures — Done  
38. Budget-aware auto-route ceiling — Done  
39. Latency SLO auto-route bias — Done  
40. Region-aware auto-route — Done  
41. Tool-schema complexity classifier — Done  
42. Multimodal attachment complexity signals — Done  
43. Streaming auto-route metadata frames — Done  
44. Responses API auto-route parity — Done  
45. Embeddings model tier advisor — Done  
46. Rerank model advisor — Done  
47. Image model advisor — Done  
48. Audio model advisor — Done  
49. Realtime model advisor — Done  
50. Assistants model advisor — Done  
51. Fine-tune job model advisor — Done  

52. Prompt registry ↔ auto-route binding — Done  
53. Route-draft auto-route recommendation — Done  
54. Canary + auto-route interaction explain — Done  
55. Mirror traffic attribution tags — Done  
56. Cache hit vs auto-route interaction metrics — Done  
57. Virtual-key scoped auto-route policy — Done  
58. Team-scoped ranking leaderboards — Done  
59. Environment-diff leadership score — Done  
60. Prod dual-approval for leadership warmup — Done  
61. Webhook alert on leadership drop — Done  
62. Slack/email notify channel for alerts — Done  
63. QBR embed of leadership index — Done  
64. Compliance evidence include leadership pack — Done  
65. SDK Python helper for auto-route — Done  
66. SDK JS helper for auto-route — Done  
67. OpenTelemetry span attributes for attribution — Done  
68. Prometheus metrics exporter for leadership — Done  
69. Grafana dashboard JSON export — Done  
70. Datadog marketplace tile notes — Done  

### Done (71–100)

71. Model deprecation advisor from rankings — Done  
72. Shadow-traffic ranking validation — Done  
73. Adversarial prompt tier hard-boost policy — Done  
74. PII-aware model routing bias — Done  
75. Data-residency model filter — Done  
76. Cost anomaly ↔ model switch correlation — Done  
77. Operator “why this model” explain card — Done  
78. Replay request with alternate strategy — Done  
79. Batch CSV upload classify — Done  
80. Nightly leadership snapshot cron — Done  
81. Retention policy for warmup events — Done  
82. Warmup event purge API — Done  
83. Ranking weight tuning runtime config — Done  
84. Judge threshold runtime config — Done  
85. Strategy policy per route_policy_id — Done  
86. Strategy policy per request_tag — Done  
87. Owner-scope ranking isolation — Done  
88. Multi-tenant ranking federation — Done  
89. Model card enrichment from catalog — Done  
90. Provider outage overlay on rankings — Done  
91. Auto apply ranking to all active routes (dual-approval) — Done  
92. Diff previous vs current leadership snapshot — Done  
93. Signed leadership evidence pack — Done  
94. External auditor share link (time-boxed) — Done  
95. Browser extension instrumentation preset — Done  
96. CI gate: leadership score floor — Done  
97. Release-gate leadership attestation — Done  
98. Chaos drill: forced provider fail + attribution — Done  
99. Board one-pager export (PDF/HTML) — Done  
100. Competitive scorecard refresh job (weekly) — Done

## Pack 5 validation

```bash
node --check frontend/app.js
cd backend && python3 -m pytest -q tests/test_gateway_leadership.py tests/test_gateway_auto_router.py tests/test_gateway_best_practices.py
```
