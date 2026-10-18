# GNUmakefile for Sphinx Documentation Suite
.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
SHELL := /usr/bin/bash
.SHELLFLAGS := -euo pipefail -c

SPHINXBUILD ?= sphinx-build
SPHINXAUTOBUILD ?= sphinx-autobuild
CRSTLINT ?= crstlint
SOURCEDIR := .
BUILDDIR := build/dirhtml

.DEFAULT_GOAL := all

.PHONY: all dirhtml html dev check clean help

all: dirhtml

dirhtml: $(BUILDDIR)/index.html

$(BUILDDIR)/index.html: $(shell find . -maxdepth 3 -name '*.rst' -o -name '*.py' 2>/dev/null)
	@echo "==> Building Sphinx documentation with dirhtml builder..."
	$(SPHINXBUILD) -b dirhtml "$(SOURCEDIR)" "$(BUILDDIR)"
	@touch $@

html:
	@echo "==> Building Sphinx documentation with html builder..."
	$(SPHINXBUILD) -b html "$(SOURCEDIR)" "build/html"

dev:
	@echo "==> Starting sphinx-autobuild live reload server..."
	$(SPHINXAUTOBUILD) -b dirhtml "$(SOURCEDIR)" "$(BUILDDIR)"

check:
	@echo "==> Linting reStructuredText documentation using crstlint..."
	@if command -v $(CRSTLINT) >/dev/null 2>&1; then \
		$(CRSTLINT) -r .; \
	else \
		echo "Warning: crstlint not found; skipping RST linting."; \
	fi

clean:
	@echo "==> Cleaning generated documentation build artifacts..."
	rm -rf build/

help:
	@echo "Documentation Build Targets:"
	@echo "  all     - Build dirhtml documentation (default)"
	@echo "  dirhtml - Build clean directory HTML documentation in build/dirhtml/"
	@echo "  html    - Build standard HTML documentation in build/html/"
	@echo "  dev     - Start sphinx-autobuild live reload server"
	@echo "  check   - Run crstlint RST linter on documentation files"
	@echo "  clean   - Remove generated build/ directory"
	@echo "  help    - Show this help message"
