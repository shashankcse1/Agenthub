.PHONY: startall shutdownall startinfra shutinfra statusall migrate downgrade checkall checkall-port smokee2e test-repeat runlocal runlocal-port runlocal-auto runlocal-auto-port restartlocal restartlocal-port restartlocal-auto restartlocal-auto-port startall-port shutdownall-port statusall-port smokee2e-port who-uses-port stop-port port-fix free-8000 doctor-local doctor-local-port dev dev-port dev-clean dev-clean-port up up-clean down go go-port verify verify-port final-gates-quick final-gates-full final-gates-quick-strict-firefox final-gates-quick-strict-all release-evidence release-evidence-strict release-evidence-auto release-evidence-auto-strict release-evidence-ciso release-evidence-ciso-auto risk-closure-dashboard pending-closure-report release-decision-record release-risk-guardrails rate-limit-cutover-check rate-limit-cutover-probe rate-limit-cutover-failover rate-limit-cutover-rollback security-monitoring-check architecture-posture-check ingress-security-validate browser-compat browser-compat-strict-safari browser-compat-strict-firefox browser-compat-strict-all xcode-safari-doctor help-local showstartup

help-local:
	@echo "Local development helpers"
	@echo "  make up"
	@echo "  make up-clean"
	@echo "  make down"
	@echo "  make dev"
	@echo "  make dev-port PORT=8001"
	@echo "  make dev-clean"
	@echo "  make dev-clean-port PORT=8001"
	@echo "  make runlocal-auto"
	@echo "  make restartlocal-auto"
	@echo "  make doctor-local"
	@echo "  make doctor-local-port PORT=8001"
	@echo "  RUNS=8 make test-repeat"
	@echo "  make who-uses-port PORT=8000"
	@echo "  make stop-port PORT=8000"
	@echo "  make port-fix PORT=8000"
	@echo "  make free-8000"
	@echo "  make go"
	@echo "  make go-port PORT=8001"
	@echo "  make showstartup"
	@echo "  make verify"
	@echo "  make verify-port PORT=8001"
	@echo "  make release-evidence RELEASE_ID=<id> [ENV=staging] [OWNER=name]"
	@echo "  make release-evidence-strict RELEASE_ID=<id> [ENV=production] [OWNER=name]"
	@echo "  RELEASE_DECISION=GO RELEASE_ACCEPTED_RISK_APPROVED=yes RELEASE_CISO_ACK=yes make release-evidence-strict RELEASE_ID=<id> [ENV=production] [OWNER=name]"
	@echo "  make release-evidence-auto [ENV=staging] [OWNER=name]"
	@echo "  make release-evidence-auto-strict [ENV=production] [OWNER=name]"
	@echo "  make release-evidence-ciso RELEASE_ID=<id> [OWNER=name]"
	@echo "  make release-evidence-ciso-auto [OWNER=name]"
	@echo "  make risk-closure-dashboard"
	@echo "  make pending-closure-report"
	@echo "  make release-decision-record RELEASE_ID=<id> [ENV=staging] [OWNER=name] [DECISION=TBD] [OUT=../artifacts/release-decision.md]"
	@echo "  make release-risk-guardrails [ENV=staging] [DECISION=TBD] [DECISION_RECORD=../artifacts/release-decision.md] [RISK_EXCEPTION_REF=<id>]"
	@echo "  bash ../scripts/render_risk_closure_dashboard.sh --strict-overdue"
	@echo "  make rate-limit-cutover-check"
	@echo "  make rate-limit-cutover-probe [PORT=8000]"
	@echo "  make rate-limit-cutover-failover"
	@echo "  make rate-limit-cutover-rollback"
	@echo "  make security-monitoring-check"
	@echo "  make architecture-posture-check"
	@echo "  make ingress-security-validate [BASE_URL=https://api.example.com] [TEST_PATH=/health]"
	@echo "  make browser-compat"
	@echo "  make browser-compat-strict-safari"
	@echo "  make browser-compat-strict-firefox"
	@echo "  make browser-compat-strict-all"
	@echo "  make xcode-safari-doctor"
	@echo "  make final-gates-quick"
	@echo "  make final-gates-full"
	@echo "  make final-gates-quick-strict-firefox"
	@echo "  make final-gates-quick-strict-all"

dev:
	./scripts/run_local.sh --auto-port

up: dev

up-clean: dev-clean

down: shutdownall

dev-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make dev-port PORT=<port>"; exit 1; fi
	./scripts/run_local.sh --port=$(PORT) --auto-port

dev-clean:
	$(MAKE) stop-port PORT=8000
	./scripts/run_local.sh --auto-port

dev-clean-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make dev-clean-port PORT=<port>"; exit 1; fi
	$(MAKE) stop-port PORT=$(PORT)
	./scripts/run_local.sh --port=$(PORT) --auto-port

runlocal:
	./scripts/run_local.sh

runlocal-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make runlocal-port PORT=<port>"; exit 1; fi
	./scripts/run_local.sh --port=$(PORT)

runlocal-auto:
	./scripts/run_local.sh --auto-port

runlocal-auto-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make runlocal-auto-port PORT=<port>"; exit 1; fi
	./scripts/run_local.sh --port=$(PORT) --auto-port

restartlocal:
	./scripts/restart_local.sh

restartlocal-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make restartlocal-port PORT=<port>"; exit 1; fi
	./scripts/restart_local.sh --port=$(PORT)

restartlocal-auto:
	./scripts/restart_local.sh --auto-port

restartlocal-auto-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make restartlocal-auto-port PORT=<port>"; exit 1; fi
	./scripts/restart_local.sh --port=$(PORT) --auto-port

startall:
	./scripts/startall.sh

showstartup:
	../scripts/showstartup.sh

shutdownall:
	./scripts/shutdownall.sh

startinfra:
	./scripts/startinfra.sh

shutinfra:
	./scripts/shutinfra.sh

statusall:
	bash ./scripts/statusall.sh

migrate:
	python3 -m alembic upgrade head

downgrade:
	python3 -m alembic downgrade -1

checkall:
	bash ./scripts/checkall.sh

checkall-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make checkall-port PORT=<port>"; exit 1; fi
	API_PORT=$(PORT) bash ./scripts/checkall.sh

smokee2e:
	bash ./scripts/smokee2e.sh

coverage-critical:
	bash ./scripts/check_critical_coverage.sh

test-functional-e2e:
	python3 -m pytest -q tests/test_functional_e2e_console.py --tb=short

test-repeat:
	@RUNS=$${RUNS:-5}; \
	echo "Running pytest $$RUNS time(s)"; \
	for i in $$(seq 1 $$RUNS); do \
		echo "RUN $$i"; \
		python3 -m pytest -q || exit $$?; \
	done

startall-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make startall-port PORT=<port>"; exit 1; fi
	API_PORT=$(PORT) ./scripts/startall.sh

shutdownall-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make shutdownall-port PORT=<port>"; exit 1; fi
	API_PORT=$(PORT) ./scripts/shutdownall.sh

statusall-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make statusall-port PORT=<port>"; exit 1; fi
	API_PORT=$(PORT) bash ./scripts/statusall.sh

smokee2e-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make smokee2e-port PORT=<port>"; exit 1; fi
	API_PORT=$(PORT) bash ./scripts/smokee2e.sh

who-uses-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make who-uses-port PORT=<port>"; exit 1; fi
	@PIDS=$$(lsof -tiTCP:$(PORT) -sTCP:LISTEN -n -P || true); \
	if [ -z "$$PIDS" ]; then \
		echo "No listener found on port $(PORT)."; \
	else \
		echo "Listener(s) on port $(PORT): $$PIDS"; \
		lsof -iTCP:$(PORT) -sTCP:LISTEN -n -P; \
	fi

stop-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make stop-port PORT=<port>"; exit 1; fi
	@PIDS=$$(lsof -tiTCP:$(PORT) -sTCP:LISTEN -n -P || true); \
	if [ -z "$$PIDS" ]; then \
		echo "No listener found on port $(PORT)."; \
	else \
		echo "Stopping listener(s) on port $(PORT): $$PIDS"; \
		kill $$PIDS || true; \
	fi

port-fix:
	@if [ -z "$(PORT)" ]; then echo "Usage: make port-fix PORT=<port>"; exit 1; fi
	$(MAKE) who-uses-port PORT=$(PORT)
	$(MAKE) stop-port PORT=$(PORT)

free-8000:
	$(MAKE) port-fix PORT=8000

go:
	$(MAKE) doctor-local
	$(MAKE) free-8000
	$(MAKE) startall
	@for i in $$(seq 1 20); do \
		if curl -s --max-time 2 http://127.0.0.1:8000/health >/dev/null 2>&1; then \
			break; \
		fi; \
		echo "Waiting for API health on port 8000..."; \
		sleep 1; \
	done
	$(MAKE) smokee2e

go-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make go-port PORT=<port>"; exit 1; fi
	$(MAKE) doctor-local-port PORT=$(PORT)
	$(MAKE) port-fix PORT=$(PORT)
	$(MAKE) startall-port PORT=$(PORT)
	@for i in $$(seq 1 20); do \
		if curl -s --max-time 2 http://127.0.0.1:$(PORT)/health >/dev/null 2>&1; then \
			break; \
		fi; \
		echo "Waiting for API health on port $(PORT)..."; \
		sleep 1; \
	done
	$(MAKE) smokee2e-port PORT=$(PORT)

verify:
	@RUNS=$${RUNS:-3}; \
	echo "[1/3] checkall"; \
	$(MAKE) checkall; \
	echo "[2/3] go"; \
	$(MAKE) go; \
	echo "[3/3] test-repeat RUNS=$$RUNS"; \
	$(MAKE) test-repeat RUNS=$$RUNS

verify-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make verify-port PORT=<port>"; exit 1; fi
	@RUNS=$${RUNS:-3}; \
	echo "[1/3] checkall-port PORT=$(PORT)"; \
	$(MAKE) checkall-port PORT=$(PORT); \
	echo "[2/3] go-port PORT=$(PORT)"; \
	$(MAKE) go-port PORT=$(PORT); \
	echo "[3/3] test-repeat RUNS=$$RUNS"; \
	$(MAKE) test-repeat RUNS=$$RUNS

final-gates-quick:
	@TARGET_API_BASE=$${API_BASE:-http://127.0.0.1:$${API_PORT:-8000}}; \
	API_BASE="$$TARGET_API_BASE" bash ../scripts/run_final_gates.sh --quick

final-gates-full:
	@TARGET_API_BASE=$${API_BASE:-http://127.0.0.1:$${API_PORT:-8000}}; \
	API_BASE="$$TARGET_API_BASE" bash ../scripts/run_final_gates.sh

final-gates-quick-strict-firefox:
	@TARGET_API_BASE=$${API_BASE:-http://127.0.0.1:$${API_PORT:-8000}}; \
	FINAL_GATES_STRICT_FIREFOX=1 API_BASE="$$TARGET_API_BASE" bash ../scripts/run_final_gates.sh --quick

final-gates-quick-strict-all:
	@TARGET_API_BASE=$${API_BASE:-http://127.0.0.1:$${API_PORT:-8000}}; \
	FINAL_GATES_STRICT_SAFARI=1 FINAL_GATES_STRICT_FIREFOX=1 API_BASE="$$TARGET_API_BASE" bash ../scripts/run_final_gates.sh --quick

browser-compat:
	bash ../scripts/check_guardbridge_browser_compat.sh

browser-compat-strict-safari:
	bash ../scripts/check_guardbridge_browser_compat.sh --strict-safari

browser-compat-strict-firefox:
	bash ../scripts/check_guardbridge_browser_compat.sh --strict-firefox-lint

browser-compat-strict-all:
	bash ../scripts/check_guardbridge_browser_compat.sh --strict-safari --strict-firefox-lint

xcode-safari-doctor:
	bash ../scripts/configure_xcode_for_safari_converter.sh

release-evidence:
	@if [ -z "$(RELEASE_ID)" ]; then echo "Usage: make release-evidence RELEASE_ID=<id> [ENV=staging] [OWNER=name]"; exit 1; fi
	@TARGET_ENV=$${ENV:-staging}; OWNER_NAME=$${OWNER:-local-operator}; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$(RELEASE_ID)" --env "$$TARGET_ENV" --owner "$$OWNER_NAME"

release-evidence-strict:
	@if [ -z "$(RELEASE_ID)" ]; then echo "Usage: make release-evidence-strict RELEASE_ID=<id> [ENV=production] [OWNER=name]"; exit 1; fi
	@TARGET_ENV=$${ENV:-production}; OWNER_NAME=$${OWNER:-local-operator}; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$(RELEASE_ID)" --env "$$TARGET_ENV" --owner "$$OWNER_NAME" --strict

release-evidence-auto:
	@TARGET_ENV=$${ENV:-staging}; OWNER_NAME=$${OWNER:-$$(whoami)}; RELEASE_AUTO_ID="rel-$${TARGET_ENV}-$$(date +%Y%m%d-%H%M%S)"; \
	echo "Using RELEASE_ID=$$RELEASE_AUTO_ID"; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$$RELEASE_AUTO_ID" --env "$$TARGET_ENV" --owner "$$OWNER_NAME"

release-evidence-auto-strict:
	@TARGET_ENV=$${ENV:-production}; OWNER_NAME=$${OWNER:-$$(whoami)}; RELEASE_AUTO_ID="rel-$${TARGET_ENV}-$$(date +%Y%m%d-%H%M%S)"; \
	echo "Using RELEASE_ID=$$RELEASE_AUTO_ID"; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$$RELEASE_AUTO_ID" --env "$$TARGET_ENV" --owner "$$OWNER_NAME" --strict

release-evidence-ciso:
	@if [ -z "$(RELEASE_ID)" ]; then echo "Usage: make release-evidence-ciso RELEASE_ID=<id> [OWNER=name]"; exit 1; fi
	@OWNER_NAME=$${OWNER:-ciso-review}; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$(RELEASE_ID)" --env "production" --owner "$$OWNER_NAME" --strict

release-evidence-ciso-auto:
	@OWNER_NAME=$${OWNER:-ciso-review}; RELEASE_AUTO_ID="rel-production-ciso-$$(date +%Y%m%d-%H%M%S)"; \
	echo "Using RELEASE_ID=$$RELEASE_AUTO_ID"; \
	DATABASE_URL=$${DATABASE_URL:-postgresql+psycopg://$$USER@localhost:5432/agenthub} \
	bash ../scripts/release_evidence_bundle.sh --release-id "$$RELEASE_AUTO_ID" --env "production" --owner "$$OWNER_NAME" --strict

risk-closure-dashboard:
	bash ../scripts/render_risk_closure_dashboard.sh docs/governance/security-risk-closure-plan.md

pending-closure-report:
	bash ../scripts/render_pending_closure_report.sh --plan docs/governance/security-risk-closure-plan.md

release-decision-record:
	@if [ -z "$(RELEASE_ID)" ]; then echo "Usage: make release-decision-record RELEASE_ID=<id> [ENV=staging] [OWNER=name] [DECISION=TBD] [OUT=../artifacts/release-decision.md]"; exit 1; fi
	@TARGET_ENV=$${ENV:-staging}; OWNER_NAME=$${OWNER:-local-operator}; DECISION_LABEL=$${DECISION:-TBD}; \
	bash ../scripts/generate_release_decision_record.sh --plan docs/governance/security-risk-closure-plan.md --release-id "$(RELEASE_ID)" --env "$$TARGET_ENV" --owner "$$OWNER_NAME" --decision "$$DECISION_LABEL" $$(if [ -n "$(OUT)" ]; then printf -- "--output %q" "$(OUT)"; fi)

release-risk-guardrails:
	@TARGET_ENV=$${ENV:-staging}; DECISION_LABEL=$${DECISION:-TBD}; DECISION_RECORD_PATH=$${DECISION_RECORD:-}; \
	CMD="bash ../scripts/validate_release_risk_guardrails.sh --plan docs/governance/security-risk-closure-plan.md --env $$TARGET_ENV --decision $$DECISION_LABEL"; \
	if [ -n "$$DECISION_RECORD_PATH" ]; then CMD="$$CMD --decision-record $$DECISION_RECORD_PATH"; fi; \
	if [ -n "$(RISK_EXCEPTION_REF)" ]; then CMD="$$CMD --allow-overdue-exception $(RISK_EXCEPTION_REF)"; fi; \
	eval "$$CMD"

rate-limit-cutover-check:
	bash ./scripts/rate_limit_cutover.sh --mode=check

rate-limit-cutover-probe:
	@TARGET_PORT=$${PORT:-$${API_PORT:-8000}}; \
	bash ./scripts/rate_limit_cutover.sh --mode=probe --port="$$TARGET_PORT"

rate-limit-cutover-failover:
	bash ./scripts/rate_limit_cutover.sh --mode=failover

rate-limit-cutover-rollback:
	bash ./scripts/rate_limit_cutover.sh --mode=rollback

security-monitoring-check:
	bash ./scripts/validate_security_monitoring_setup.sh

architecture-posture-check:
	bash ./scripts/validate_architecture_posture.sh

ingress-security-validate:
	@TARGET_BASE_URL=$${BASE_URL:-$${INGRESS_BASE_URL:-http://127.0.0.1:$${API_PORT:-8000}}}; \
	TARGET_PATH=$${TEST_PATH:-$${INGRESS_TEST_PATH:-/health}}; \
	bash ./scripts/validate_ingress_security_headers.sh --url="$$TARGET_BASE_URL" --path="$$TARGET_PATH"

doctor-local:
	bash ./scripts/doctor_local.sh

doctor-local-port:
	@if [ -z "$(PORT)" ]; then echo "Usage: make doctor-local-port PORT=<port>"; exit 1; fi
	bash ./scripts/doctor_local.sh --port=$(PORT)
