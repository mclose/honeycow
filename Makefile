.PHONY: help venv install lint test e2e smoke run bump tag gh-release docker-build docker-up docker-down docker-logs docker-up-prod docker-down-prod docker-logs-prod logs clean

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

help:
	@echo "HoneyCow v$(VERSION)"
	@echo ""
	@echo "Setup:"
	@echo "  make venv          create ./venv and install deps"
	@echo "  make install       (re)install deps into existing venv"
	@echo ""
	@echo "Quality:"
	@echo "  make lint          ruff check"
	@echo "  make test          unit tests (no network)"
	@echo "  make e2e           bash + dig against a local instance"
	@echo ""
	@echo "Run:"
	@echo "  make run           launch honey_ns.py on :$(DEV_DNS_PORT) (no root needed)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build       build the honeycow image"
	@echo "  make docker-up          docker compose up -d (dev: binds 0.0.0.0/::)"
	@echo "  make docker-down        docker compose down"
	@echo "  make docker-logs        tail container logs"
	@echo "  make logs               tail JSONL event log volume"
	@echo ""
	@echo "Prod deploy (binds specific public IPs from .env):"
	@echo "  make docker-up-prod     docker compose up -d with prod override"
	@echo "  make docker-down-prod   stop prod stack"
	@echo "  make docker-logs-prod   tail prod logs"
	@echo ""
	@echo "Release:"
	@echo "  make bump V=X.Y.Z  update VERSION and commit"
	@echo "  make tag           tag current commit (requires tests pass)"
	@echo "  make gh-release    create GitHub release for current tag"
	@echo "  make smoke         post-deploy sanity check"

venv:
	python3 -m venv venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install pytest ruff pip-tools

install:
	$(PIP) install -r requirements.txt

lint:
	$(RUFF) check .

test:
	$(PYTEST) -q tests/

e2e:
	bash tests/e2e.sh

run:
	HONEY_PORT=$(DEV_DNS_PORT) HONEY_HTTP_PORT=$(DEV_HTTP_PORT) \
	HONEY_LOG=$(DEV_LOG) HONEY_PUBLIC_A=$${HONEY_PUBLIC_A:-$(DEV_PUBLIC_A)} \
	HONEY_EXEMPTION_FILE=$${HONEY_EXEMPTION_FILE:-exemptions.txt} \
	HONEY_STATIC_INDEX=$${HONEY_STATIC_INDEX:-static/index.html} \
	$(PY) honey_ns.py

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f -t

docker-up-prod:
	docker compose $(PROD_COMPOSE) up -d

docker-down-prod:
	docker compose $(PROD_COMPOSE) down

docker-logs-prod:
	docker compose $(PROD_COMPOSE) logs -f -t

logs:
	docker compose exec honey-ns tail -f /var/log/honeycow/events.jsonl

# Smoke test against a live deployment. HOST defaults to localhost; override
# to point at a remote target.
HOST ?= 127.0.0.1
smoke:
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

# Bump version.
bump:
	@test -n "$(V)" || (echo "usage: make bump V=X.Y.Z"; exit 1)
	@echo "$(V)" > VERSION
	git add VERSION
	git commit -m "Bump version to $(V)"

tag: test
	git tag v$(VERSION)
	git push origin main v$(VERSION)

gh-release:
	gh release create v$(VERSION) --title "v$(VERSION)" --generate-notes

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache .ruff_cache *.egg-info
