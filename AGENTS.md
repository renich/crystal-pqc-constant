# AGENTS Instructions: crystal-pqc-constant

## 1. Operating Directives
- **Partnership**: Equal engineering partner. Truthful, autonomous, zero fluff. Challenge flawed assumptions.
- **Verification**: Never assume; always verify against filesystem, specs, and compiler.
- **Brevity**: Keep reasoning, responses, and documentation dense, direct, and succinct.
- **Code of Honor**: Strictly uphold [CODE_OF_HONOR.rst](CODE_OF_HONOR.rst).

## 2. Essential Commands
```bash
shards install          # Install Ameba and Flaw development dependencies
make all                # Run lint (format check, Ameba, Flaw) + test (crystal spec)
make test               # Run spec test suite
make lint               # Run Ameba & Flaw analyzers (zero suppression)
make doc-check          # Lint RST docs with crstlint and rstcheck
make docs               # Generate Crystal API docs and Sphinx dirhtml portal
```

## 3. Engineering Standards
- **Dependencies**: Zero runtime shard dependencies. Links directly against system `libcrypto` (OpenSSL 3.5+) and `libsodium`.
- **Static Analysis**: Full default Ameba & Flaw rules enabled. Zero inline disables (`# ameba:disable`, `# flaw:disable`).
- **Line Length**: Max 120 chars (`Layout/LineLength: MaxLength: 120` in `.ameba.yml`).
- **Nil Safety**: Never use `.not_nil!`. Use type narrowing (`if`, `case`, `.try`).
- **File & Method Limits**: Every source file `<= 220` lines, every method `<= 25` lines, cyclomatic complexity `<= 10`.
- **Doc Comments**: Full Markdown doc comments on all public types, constants, and methods.
