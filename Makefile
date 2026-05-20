# Makefile — follows ~/projects/project-guides/META-CLAUDE.md Appendix A.
#
# Conventions:
#   .DEFAULT_GOAL := help    bare `make` lists targets, never deploys.
#   Every public target gets an inline `## description`.
#   Verb-noun ordering: build-X, bump-X, deploy-<env>.
#   Plural `logs`, singular `status`. No `docker-` prefix.
#   `smoke` = post-deploy curl check; `test` = pre-merge gate. Keep separate.
#   `rebuild` = `docker build --no-cache`. Use `restart` for down-then-up.

.DEFAULT_GOAL := help

PROJECT  := honeycow
VPS_HOST := honeycow
VPS_PATH := ~/$(PROJECT).git

PROD_COMPOSE := -f docker-compose.yml -f docker-compose.prod.yml

VERSION := $(shell cat VERSION)
PY      := venv/bin/python
PIP     := venv/bin/pip
PYTEST  := venv/bin/pytest
RUFF    := venv/bin/ruff

# Local dev: bind high ports so we don't need root.
DEV_DNS_PORT  ?= 15353
DEV_HTTP_PORT ?= 18080
DEV_LOG       ?= /tmp/honeycow.jsonl
DEV_PUBLIC_A  ?= 127.0.0.1

# Morning-report inputs (local copies pulled from VPS).
EVENTS ?= /tmp/honeycow-analysis/events.jsonl
UFW    ?= /tmp/honeycow-analysis/ufw.log
HOURS  ?= 24

# Smoke-test target.
HOST ?= 127.0.0.1

.PHONY: help venv install hooks fmt lint check test e2e smoke tire-kick run \
        build up down restart rebuild logs events-tail shell status \
        up-prod down-prod logs-prod \
        logs-wire report-wire \
        deploy setup-remote _sandbox_check \
        bump tag gh-release report clean

help:  ## List targets
	@awk 'BEGIN{FS=":.*##"; printf "HoneyCow v$(VERSION) — targets:\n"} \
	  /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' \
	  $(MAKEFILE_LIST)

# ---- setup ---------------------------------------------------------------

venv:  ## Create ./venv and install deps
	python3 -m venv venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install pytest ruff pip-tools

install:  ## (Re)install deps into existing venv
	$(PIP) install -r requirements.txt

hooks:  ## Install pre-commit hooks
	venv/bin/pre-commit install

# ---- quality -------------------------------------------------------------

fmt:  ## Format with ruff
	$(RUFF) format .

lint:  ## ruff check
	$(RUFF) check .

check: lint test  ## Lint + test (pre-merge gate)

test:  ## Unit tests (no network)
	$(PYTEST) -q tests/

e2e:  ## bash + dig against a local instance
	bash tests/e2e.sh

# ---- local run -----------------------------------------------------------

run:  ## Launch honey_ns.py on high ports (no root needed)
	HONEY_PORT=$(DEV_DNS_PORT) HONEY_HTTP_PORT=$(DEV_HTTP_PORT) \
	HONEY_LOG=$(DEV_LOG) HONEY_PUBLIC_A=$${HONEY_PUBLIC_A:-$(DEV_PUBLIC_A)} \
	HONEY_EXEMPTION_FILE=$${HONEY_EXEMPTION_FILE:-config/exemptions.txt} \
	HONEY_STATIC_INDEX=$${HONEY_STATIC_INDEX:-static/index.html} \
	$(PY) honey_ns.py

# ---- docker (dev — binds 0.0.0.0/::) -------------------------------------

build:  ## docker compose build
	docker compose build

up:  ## docker compose up -d (dev: binds 0.0.0.0/::)
	docker compose up -d

down:  ## docker compose down (NEVER -v — would kill honeycow_logs volume)
	docker compose down

restart: down up  ## Stop and start

rebuild:  ## docker build --no-cache
	docker compose build --no-cache

logs:  ## Tail compose logs
	docker compose logs -f -t

events-tail:  ## Tail JSONL event log inside the container
	docker compose exec honey-ns tail -f /var/log/honeycow/events.jsonl

shell:  ## Interactive container shell (busybox sh — no bash in minimal image)
	docker compose exec honey-ns /bin/sh

# ---- docker (prod — caddy + acme + host-IP bindings from .env) -----------

up-prod:  ## docker compose up -d --build with prod overlay (caddy + acme + host-IP) + caddy reload
	docker compose $(PROD_COMPOSE) up -d --build
	@docker exec honeycow-caddy caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \
		|| echo "(caddy reload skipped — container not running or not yet ready)"

down-prod:  ## Stop prod stack
	docker compose $(PROD_COMPOSE) down

logs-prod:  ## Tail prod logs
	docker compose $(PROD_COMPOSE) logs -f -t

status:  ## docker compose ps on $(VPS_HOST)
	ssh $(VPS_HOST) "cd projects/$(PROJECT) && docker compose $(PROD_COMPOSE) ps"

# ---- wire-monitoring helpers --------------------------------------------

logs-wire:  ## List recent pcaps + tail today's Zeek dns.log on $(VPS_HOST)
	@echo "== recent pcaps =="
	@ssh $(VPS_HOST) 'docker exec honeycow-tcpdump ls -lt /pcaps | head -10'
	@echo
	@echo "== today's Zeek dns.log (tail 20) =="
	@ssh $(VPS_HOST) 'docker exec honeycow-zeek tail -20 /zeek/logs/dns.log' \
		|| echo "(no dns.log yet)"

report-wire:  ## Cross-check Zeek dns.log count vs honeycow events.jsonl count (last $(HOURS)h)
	@tools/report_wire.py --hours $(HOURS) --remote $(VPS_HOST)

# ---- deploy --------------------------------------------------------------

deploy: _sandbox_check  ## Push to origin + prod (prod post-receive runs up-prod)
	git push origin main
	git push prod main

setup-remote:  ## One-time: create bare repo + post-receive hook on $(VPS_HOST)
	ssh $(VPS_HOST) "git init --bare $(VPS_PATH)"
	@echo "Now: install post-receive hook at $(VPS_HOST):$(VPS_PATH)/hooks/post-receive"
	@echo "Then: git remote add prod $(VPS_HOST):$(VPS_PATH)"

# Refuse to deploy from inside an Anthropic sandbox (egress allowlisted).
_sandbox_check:
	@if [ -n "$$ANTHROPIC_SANDBOX" ] || [ -d /mnt/skills ]; then \
	  echo "Refusing to deploy from sandbox."; exit 1; \
	fi

# ---- release -------------------------------------------------------------

bump:  ## Bump version. Usage: make bump V=X.Y.Z
	@test -n "$(V)" || (echo "usage: make bump V=X.Y.Z"; exit 1)
	@echo "$(V)" > VERSION
	git add VERSION
	git commit -m "Bump version to $(V)"

tag: test  ## Tag current commit (requires tests pass)
	git tag v$(VERSION)
	git push origin main v$(VERSION)

gh-release:  ## Create GitHub release for current tag
	gh release create v$(VERSION) --title "v$(VERSION)" --generate-notes

# ---- analysis ------------------------------------------------------------

tire-kick:  ## End-to-end probe + log-correlation test (HOST4=, HOST6=, REMOTE=)
	HOST4=$${HOST4:-$(HOST)} HOST6=$${HOST6:-} REMOTE=$${REMOTE:-} \
		bash tests/tire_kick.sh

smoke:  ## Post-deploy sanity check (HOST=<vps-ipv4>)
	@echo "SOA arbitrary.example @ $(HOST):53"
	@dig @$(HOST) +time=3 +tries=1 SOA arbitrary.example | grep -q '^arbitrary\.example\..*SOA' \
		|| (echo "smoke FAIL: no SOA"; exit 1)
	@echo "A target.example.org @ $(HOST):53"
	@dig @$(HOST) +time=3 +tries=1 +short A target.example.org | grep -qE '^[0-9]' \
		|| (echo "smoke FAIL: no A"; exit 1)
	@echo "TXT random.tld @ $(HOST):53"
	@dig @$(HOST) +time=3 +tries=1 +short TXT random.tld | grep -q 'honeycow' \
		|| (echo "smoke FAIL: no calling-card TXT"; exit 1)
	@echo "smoke OK"

report:  ## Morning report from /tmp/honeycow-analysis/{events.jsonl,ufw.log}
	@tools/morning_report.py --events $(EVENTS) --ufw $(UFW) --hours $(HOURS) \
		$(if $(CERT_ISSUED),--cert-issued $(CERT_ISSUED))

# ---- housekeeping --------------------------------------------------------

clean:  ## Remove caches and build artifacts
	rm -rf __pycache__ */__pycache__ .pytest_cache .ruff_cache *.egg-info
