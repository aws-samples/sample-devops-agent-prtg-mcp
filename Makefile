.DEFAULT_GOAL := help
SHELL := /bin/bash

VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
CDK     := ./node_modules/.bin/cdk
CONFIG  ?= config/default.yaml

# Every target that synthesises works without AWS credentials, provided the chosen
# configuration supplies subnet IDs alongside a VPC ID (see docs/deployment-matrix.md).
# These are the identifiers the shipped examples expect; override in your shell.
export DEVOPS_AGENT_SPACE_ID ?= as-example-001
export PRTG_SOURCE_IP        ?= 203.0.113.7

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- Setup ------------------------------------------------------------------

.PHONY: install
install: ## Create the virtualenv and install all dependencies
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements-dev.txt
	npm install --silent
	@echo "Ready. Run 'make test' to verify without touching AWS."

# --- Verify -----------------------------------------------------------------

.PHONY: test
test: ## Run unit tests (no AWS account, no PRTG server required)
	$(PY) -m pytest tests/unit

.PHONY: test-integration
test-integration: ## Run live PRTG tests (needs PRTG_TEST_* env vars; see tests/integration)
	$(PY) -m pytest tests/integration -v -m integration

.PHONY: coverage
coverage: ## Unit tests with a coverage report
	$(PY) -m pytest tests/unit --cov --cov-report=term-missing

.PHONY: lint
lint: ## Check formatting and lint rules
	$(PY) -m ruff check src infrastructure tests app.py
	$(PY) -m ruff format --check src infrastructure tests app.py

.PHONY: format
format: ## Apply formatting and autofixable lint rules
	$(PY) -m ruff check --fix src infrastructure tests app.py
	$(PY) -m ruff format src infrastructure tests app.py

.PHONY: check-sanitisation
check-sanitisation: ## Reject credentials and internal identifiers in tracked files
	@bash scripts/check-sanitisation.sh

.PHONY: schema
schema: ## Write the generated Gateway tool schema to build/ for inspection
	@$(PY) -c "from infrastructure.stacks.mcp_server_stack import write_tool_schema; \
	           print('wrote', write_tool_schema())"

# --- Synthesise -------------------------------------------------------------

.PHONY: synth
synth: ## Synthesise CloudFormation for CONFIG (default: config/default.yaml)
	$(CDK) synth -c config=$(CONFIG)

.PHONY: synth-all
synth-all: ## Synthesise every configuration in config/ - what CI checks
	@failed=0; \
	for cfg in config/*.yaml; do \
	  printf '  %-34s' "$$(basename $$cfg)"; \
	  if $(CDK) synth --quiet -c config=$$cfg >/dev/null 2>/tmp/prtg-synth.log; then \
	    echo "OK"; \
	  else \
	    echo "FAILED"; sed -n '1,25p' /tmp/prtg-synth.log; failed=1; \
	  fi; \
	done; \
	exit $$failed

.PHONY: diff
diff: ## Show what deploying CONFIG would change (needs credentials)
	$(CDK) diff -c config=$(CONFIG)

# --- Deploy -----------------------------------------------------------------

.PHONY: bootstrap
bootstrap: ## Bootstrap CDK in the target account and region (once per account/region)
	$(CDK) bootstrap -c config=$(CONFIG)

.PHONY: deploy
deploy: ## Deploy both stacks for CONFIG
	$(CDK) deploy --all -c config=$(CONFIG)

.PHONY: deploy-mcp
deploy-mcp: ## Deploy only the MCP server (agent -> PRTG)
	$(CDK) deploy -c config=$(CONFIG) '*-mcp-server'

.PHONY: deploy-pipeline
deploy-pipeline: ## Deploy only the alarm pipeline (PRTG -> agent)
	$(CDK) deploy -c config=$(CONFIG) '*-alarm-pipeline'

.PHONY: outputs
outputs: ## Print the stack outputs you need to register the MCP server
	@$(CDK) deploy --all -c config=$(CONFIG) --outputs-file /dev/stdout --require-approval never --no-execute 2>/dev/null \
	  || echo "Deploy first, then read the outputs from the CloudFormation console or 'aws cloudformation describe-stacks'."

.PHONY: destroy
destroy: ## Destroy both stacks. The PRTG credential secret is RETAINED on purpose.
	$(CDK) destroy --all -c config=$(CONFIG)
	@echo
	@echo "The PRTG credential secret was retained, so a redeploy does not lose it."
	@echo "To remove it as well:"
	@echo "  aws secretsmanager delete-secret --secret-id prtg-mcp/credentials \\"
	@echo "    --recovery-window-in-days 7 --region <region>"

# --- Housekeeping -----------------------------------------------------------

.PHONY: clean
clean: ## Remove build and test artefacts
	rm -rf cdk.out build .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true

.PHONY: check
check: lint test synth-all check-sanitisation ## Everything CI runs
	@echo
	@echo "All checks passed with no AWS credentials used."
