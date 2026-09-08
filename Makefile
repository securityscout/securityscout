# securityscout — Makefile.
#
# Bootstrap targets:
#   bootstrap   — install toolchain + Python deps + skill (idempotent)
#   schema      — create / migrate SQLite schema at $(TRIAGE_DB_PATH)
#   verify      — bootstrap acceptance gate; exit 0 = ready to ingest
#
# Pipeline targets that are not yet implemented exit non-zero with a clear
# message.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# This file's directory. $(CURDIR) is the invocation cwd.
MAKEFILE_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

# Project-local venv at .venv/ to dodge PEP 668 on Homebrew Python. Every
# triage.* invocation runs through VENV_PY; rules that need it bail with a
# clear error when it's missing instead of silently using system python.
SYSTEM_PYTHON ?= python3
VENV_DIR    ?= .venv
VENV_PY     := $(VENV_DIR)/bin/python
VENV_PIP    := $(VENV_DIR)/bin/pip

TRIAGE_DB   ?= triage.db
SKILL_HOME  ?= $(HOME)/.cursor/skills/sast-triage
SKILL_FILE  := $(SKILL_HOME)/SKILL.md
# Vendored, polyglot-expanded skill source — checked in so this tool isn't
# coupled to any upstream copy.
VENDORED_SKILL ?= $(CURDIR)/data/sast-triage.SKILL.md

# Only `gh` is needed on the laptop today (org inventory / clone).
# Sandbox scanners (trivy, osv-scanner) and jbang land with later
# workstreams, not in this bootstrap.

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  bootstrap            — install toolchain (brew + pipx fallbacks + pip + skill)"
	@echo "  bootstrap-venv       — create .venv (Python 3.10+)"
	@echo "  bootstrap-brew       — brew install the toolchain (non-fatal if brew unreachable)"
	@echo "  bootstrap-fallbacks  — report missing brew tools"
	@echo "  bootstrap-pip        — install Python deps into .venv"
	@echo "  schema               — create SQLite schema at $(TRIAGE_DB)"
	@echo "  verify               — bootstrap acceptance gate; exit 0 = ready to ingest"
	@echo "  test                 — run pytest + web tests + web production build"
	@echo "  test-py              — run pytest suite"
	@echo "  test-web             — run web Vitest + typecheck + Vite build"
	@echo "  build                — web production build (typecheck + Vite)"
	@echo "  skill                — (re)install ~/.cursor/skills/sast-triage/SKILL.md"
	@echo "  clean-db             — delete $(TRIAGE_DB) (DESTRUCTIVE)"
	@echo "  ingest CSV=path [DRY=1] [EXCLUDE=glob,…] — SAST CSV ingest"
	@echo "  classify-access [COMMIT=1] [HOSTS=h1,h2] [PROBE=per_repo|membership] — flip rows between queued↔no_access via live API"
	@echo "  recon                 — cache recon for REPO + SHA + WORKDIR"
	@echo "  triage                — two-pass worker for FINDING_ID"
	@echo "  verify-verdicts       — harness replay for FINDING_ID"
	@echo "  report|calibrate      — not yet implemented"

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

.PHONY: bootstrap
bootstrap: bootstrap-venv bootstrap-brew bootstrap-fallbacks bootstrap-pip skill
	@echo
	@echo "==> bootstrap complete. Run 'make verify' next."

.PHONY: bootstrap-venv
bootstrap-venv:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "==> creating venv at $(VENV_DIR) using $(SYSTEM_PYTHON)"; \
	  $(SYSTEM_PYTHON) -m venv "$(VENV_DIR)"; \
	  "$(VENV_PIP)" install --upgrade pip >/dev/null; \
	else \
	  echo "✓ venv already present at $(VENV_DIR)"; \
	fi

.PHONY: bootstrap-brew
bootstrap-brew:
	@if command -v gh >/dev/null 2>&1; then \
	  echo "✓ gh already installed at $$(command -v gh)"; \
	  exit 0; \
	fi
	@if ! command -v brew >/dev/null 2>&1; then \
	  echo "!! gh not on PATH and brew missing — install GitHub CLI manually."; \
	  exit 0; \
	fi
	@echo "==> brew install gh"
	@brew install gh || echo "!! brew install gh failed — install GitHub CLI manually."

.PHONY: bootstrap-fallbacks
bootstrap-fallbacks:
	@if command -v gh >/dev/null 2>&1; then \
	  echo "✓ gh already installed at $$(command -v gh)"; \
	else \
	  echo "!! gh MISSING — brew install gh"; \
	fi

.PHONY: bootstrap-pip
bootstrap-pip: bootstrap-venv
	@echo "==> Installing Python dependencies into $(VENV_DIR)"
	@"$(VENV_PIP)" install -e "$(MAKEFILE_DIR)[dev]"

.PHONY: skill
skill:
	@mkdir -p "$(SKILL_HOME)"
	@if [ -f "$(VENDORED_SKILL)" ]; then \
	  cp -f "$(VENDORED_SKILL)" "$(SKILL_FILE)"; \
	  echo "✓ installed $(SKILL_FILE) from $(VENDORED_SKILL)"; \
	else \
	  echo "ERROR: vendored skill not found at $(VENDORED_SKILL)"; \
	  echo "       restore data/sast-triage.SKILL.md from git or set VENDORED_SKILL."; \
	  exit 1; \
	fi

.PHONY: schema
schema:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m triage.db init --path "$(TRIAGE_DB)"

.PHONY: clean-db
clean-db:
	@rm -f "$(TRIAGE_DB)" "$(TRIAGE_DB)-journal" "$(TRIAGE_DB)-wal" "$(TRIAGE_DB)-shm"
	@echo "✓ removed $(TRIAGE_DB) and journals"

.PHONY: verify
verify:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m triage.verify

.PHONY: test test-py test-web build
test: test-py test-web

test-py:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m pytest tests/ -v

test-web:
	@if [ ! -x web/node_modules/.bin/vitest ]; then \
	  echo "ERROR: web deps missing. Run: npm --prefix web install"; exit 1; \
	fi
	@npm --prefix web test
	@npm --prefix web run build

build:
	@if [ ! -x web/node_modules/.bin/vite ]; then \
	  echo "ERROR: web deps missing. Run: npm --prefix web install"; exit 1; \
	fi
	@npm --prefix web run build

# ---------------------------------------------------------------------------
# Ingest
#
# Usage:
#   make ingest CSV=data/csv/<file>.csv          # writes to triage.db
#   make ingest CSV=... DRY=1                    # dry-run, no DB writes
#   make ingest CSV=... EXCLUDE='*foo*,*bar*'    # extra exclude globs
#   make ingest CSV=... NO_DEFAULT_EXCLUDES=1    # opt out of test-fixture filter
# ---------------------------------------------------------------------------

DRY ?=
EXCLUDE ?=
NO_DEFAULT_EXCLUDES ?=

.PHONY: ingest
ingest:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@if [ -z "$(CSV)" ]; then \
	  echo "ERROR: pass CSV=path/to/findings.csv"; exit 1; \
	fi
	@flags=""; \
	if [ -n "$(DRY)" ]; then flags="$$flags --dry-run"; fi; \
	if [ -n "$(EXCLUDE)" ]; then flags="$$flags --exclude-repos '$(EXCLUDE)'"; fi; \
	if [ -n "$(NO_DEFAULT_EXCLUDES)" ]; then flags="$$flags --no-default-excludes"; fi; \
	"$(VENV_PY)" -m triage.ingest --csv "$(CSV)" --db "$(TRIAGE_DB)" $$flags

# ---------------------------------------------------------------------------
# Access classification
#
# Cross-references each reclassifiable finding's repo_url against a live
# access predicate and flips rows between `queued` and `no_access`. Only
# `queued` and `no_access` rows are eligible — every other status is sticky.
#
# Dry-run is the default; pass COMMIT=1 to actually write. HOSTS overrides
# TRIAGE_ACCESS_HOSTS for a one-off run (hosts not in the list default to
# `no_access` — add them once an auth strategy is wired up). PROBE overrides
# TRIAGE_ACCESS_PROBE — `per_repo` (default) or `membership`.
#
# Usage:
#   make classify-access                                # dry-run, default probe
#   make classify-access COMMIT=1                       # apply
#   make classify-access HOSTS=github.com,gitlab.com COMMIT=1
#   make classify-access PROBE=membership               # cheap, misses inheritance
# ---------------------------------------------------------------------------

COMMIT ?=
HOSTS ?=
PROBE ?=

.PHONY: classify-access
classify-access:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@flags=""; \
	if [ -n "$(COMMIT)" ]; then flags="$$flags --apply"; fi; \
	if [ -n "$(HOSTS)" ]; then flags="$$flags --hosts '$(HOSTS)'"; fi; \
	if [ -n "$(PROBE)" ]; then flags="$$flags --probe '$(PROBE)'"; fi; \
	"$(VENV_PY)" -m triage.classify_access --db "$(TRIAGE_DB)" $$flags

# ---------------------------------------------------------------------------
# Recon / two-pass / harness verifier
# ---------------------------------------------------------------------------

REPO ?=
SHA ?=
WORKDIR ?=
FINDING_ID ?=

.PHONY: recon
recon:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m triage.recon --db "$(TRIAGE_DB)" --repo-url "$(REPO)" --sha "$(SHA)" --workdir "$(WORKDIR)"

.PHONY: triage
triage:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m triage.triage_worker --db "$(TRIAGE_DB)" --finding-id "$(FINDING_ID)" $(if $(WORKDIR),--workdir "$(WORKDIR)",)

.PHONY: verify-verdicts
verify-verdicts:
	@if [ ! -x "$(VENV_PY)" ]; then \
	  echo "ERROR: venv not found at $(VENV_DIR). Run 'make bootstrap' first."; exit 1; \
	fi
	@"$(VENV_PY)" -m triage.verifier --db "$(TRIAGE_DB)" --finding-id "$(FINDING_ID)" $(if $(WORKDIR),--workdir "$(WORKDIR)",)

.PHONY: report calibrate
report calibrate:
	@echo "ERROR: '$@' is not yet implemented."
	@exit 2
