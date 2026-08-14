# Good first issues (seed pack)

Copy any item into a GitHub Issue. Apply labels: `good first issue`, `help wanted`, plus `docs` / `frontend` / `backend` as appropriate.

Maintainers can also run (requires `gh auth login`):

```bash
./scripts/seed_good_first_issues.sh
```

---

### 8. Raise critical-path coverage pack N+1 to ≥99%

**Labels:** `help wanted`, `backend`  
**Acceptance:**

- Pick next service module (see [COVERAGE.md](./COVERAGE.md))  
- Add tests until `pytest --cov=… --cov-fail-under=99` passes  
- Add module to `.coveragerc.critical` only when ready  
- Do not lower the global fail_under  

---

### 1. Add Overview screenshot to README

**Labels:** `good first issue`, `docs`, `frontend`  
**Acceptance:**

- Capture Overview (light theme) after local login  
- Store under `docs/assets/overview.png` (or `.webp`)  
- Embed in root `README.md` under Quick start / Explore  
- Avoid secrets, tokens, or real customer data in the capture  

---

### 2. Broken-link sweep on community docs

**Labels:** `good first issue`, `docs`  
**Acceptance:**

- Check links in `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/EXPLORING.md`  
- Fix or replace dead paths (especially moved LiteLLM / governance files)  
- Note any intentional external 404s in the PR  

---

### 3. SDK “hello chat” sample

**Labels:** `good first issue`, `docs`  
**Acceptance:**

- Add a minimal example to `sdk/python/README.md` and/or `sdk/js/README.md`  
- Show base URL pointing at local gateway, no hardcoded secrets  
- Link the sample from root README SDKs section  

---

### 4. Empty-state copy for Overview spend cards

**Labels:** `good first issue`, `frontend`  
**Acceptance:**

- When spend/audit counts are empty, show one clear sentence + link to Playground or Cost  
- Keep existing control-center visual language (no new card chrome)  
- `node --check frontend/app.js`  

---

### 5. Document plane-split Session Context in EXPLORING

**Labels:** `good first issue`, `docs`  
**Acceptance:**

- Add a short subsection to `docs/EXPLORING.md` for **Plane Split** profile (`:8001` / `:8002`)  
- Link `plane-split-runbook.md`  
- State when to use same-origin `:4173` vs direct backend bases  

---

### 6. Pytest docstring for one public health/auth contract

**Labels:** `good first issue`, `backend`  
**Acceptance:**

- Pick an existing test in `backend/tests/` that lacks a one-line purpose docstring  
- Add a clear docstring stating the contract under test  
- Run that single test file with `pytest -q`  

---

### 7. Issue triage glossary

**Labels:** `good first issue`, `docs`  
**Acceptance:**

- Add `docs/GLOSSARY.md` with 15–25 operator terms (VK, JIT, CPLI, LRS, plane-split, dual-approval, …)  
- Link it from `docs/EXPLORING.md` and `CONTRIBUTING.md`  
