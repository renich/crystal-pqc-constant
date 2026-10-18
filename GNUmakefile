# GNUmakefile for crystal-pqc-constant
# Copyleft (C) 2026 Rénich Bon Ćirić <renich@evalinux.com>
# SPDX-License-Identifier: GPL-3.0-or-later

.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
SHELL := /usr/bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := all

CRYSTAL ?= crystal
SHARDS ?= shards
CRTESTFLAGS ?= --error-trace
CRSTLINT ?= crstlint

RST_FILES := $(wildcard *.rst) $(shell find docs -type f -name '*.rst' 2>/dev/null)

.PHONY: all lint test spec check doc-check docs format clean distclean help

all: lint test

bin:
	@mkdir -p $@

bin/ameba: | bin
	@if [ ! -f lib/ameba/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/ameba/src/cli.cr -o $@

bin/flaw: | bin
	@if [ ! -f lib/flaw/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/flaw/src/cli.cr -o $@

lint: bin/ameba bin/flaw
	@echo "==> Checking Crystal code formatting..."
	$(CRYSTAL) tool format --check src spec
	@echo "==> Running Ameba static analysis across src/ and spec/..."
	./bin/ameba --all
	@echo "==> Running Flaw SAST security scanner..."
	./bin/flaw scan .

test: spec

spec:
	$(CRYSTAL) spec $(CRTESTFLAGS)

check: lint test doc-check

doc-check:
	@if command -v $(CRSTLINT) >/dev/null 2>&1; then $(CRSTLINT) -r .; fi
	@if command -v rstcheck >/dev/null 2>&1; then rstcheck $(RST_FILES); fi

docs:
	@echo "==> Generating Crystal API documentation..."
	$(CRYSTAL) docs -o docs/technical/api
	@echo "==> Building Sphinx dirhtml documentation..."
	$(MAKE) -C docs dirhtml

format:
	$(CRYSTAL) tool format src spec

clean:
	rm -rf bin/ coverage/ docs/technical/api/ public/
	$(MAKE) -C docs clean

distclean: clean
	rm -rf lib/ .shards/ shard.lock

help:
	@echo "crystal-pqc-constant GNUmakefile Targets:"
	@echo "  all        - Run static analysis (lint) and spec suite (test)"
	@echo "  lint       - Check formatting, Ameba, and Flaw SAST"
	@echo "  test/spec  - Run Crystal spec test suite"
	@echo "  doc-check  - Validate RST documentation with crstlint and rstcheck"
	@echo "  docs       - Build Crystal API docs and Sphinx dirhtml portal"
	@echo "  format     - Format Crystal sources in src/ and spec/"
	@echo "  clean      - Remove build artifacts and generated docs"
	@echo "  distclean  - Remove all dependencies and build outputs"
