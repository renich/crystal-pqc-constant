================
Coding Standards
================

Requirement Mapping
-------------------

Fulfills ``[FUNC-004]`` and ``[FUNC-005]``.

[TECH-004] Static Analysis and Structural Complexity Guardrails
---------------------------------------------------------------

All source files in ``src/`` and ``spec/`` must satisfy the following deterministic engineering constraints:

#. **Explicit Type Signatures**: Every method definition across ``src/`` must declare explicit parameter types and return types.
#. **Zero Unsafe Nil Assertions**: Usage of ``.not_nil!`` is strictly prohibited across ``src/`` and ``spec/``. Pointer checks must use ``.null?`` and raise typed ``PQCError`` subclasses.
#. **Structural Size and Complexity Ceilings**: Every source file must contain at most 220 lines, every method must contain at most 25 lines, parameter lists must contain at most 5 parameters, and cyclomatic complexity must remain at or below 10.
#. **Zero Linter Suppression**: Inline suppression comments (``# ameba:disable`` and ``# flaw:disable``) are strictly prohibited. Both ``./bin/ameba --all`` and ``./bin/flaw scan .`` must exit with zero findings.
#. **Concurrency Hygiene**: Shared state initialization and guarded buffer operations must use ``Sync::Mutex`` and ``Atomic(Bool)`` to guarantee thread safety under Crystal 1.21+ parallel execution contexts.
