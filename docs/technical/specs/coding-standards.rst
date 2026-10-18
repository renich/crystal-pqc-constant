================
Coding Standards
================

Engineering Constraints
-----------------------

#. **Explicit Type Signatures**: Every method defines explicit parameter and return types.
#. **Zero Unsafe Nil Assertions**: ``.not_nil!`` is strictly prohibited across ``src/`` and ``spec/``.
#. **Structural Complexity Limits**: Every source file is at most 220 lines, every method is at most 25 lines, and cyclomatic complexity is at most 10.
#. **Zero Linter Suppression**: ``# ameba:disable`` and ``# flaw:disable`` directives are forbidden.
#. **Concurrency Hygiene**: Uses Crystal 1.21+ ``Sync::Mutex`` for fiber-safe synchronization across parallel execution contexts.
