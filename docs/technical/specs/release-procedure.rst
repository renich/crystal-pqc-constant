=================
Release Procedure
=================

Requirement Mapping
-------------------

Fulfills ``[FUNC-005]``.

Verification Gateways
---------------------

Every release of ``crystal-pqc-constant`` must pass the following deterministic verification sequence prior to tagging:

#. Execute ``crystal tool format --check src spec`` to verify canonical source formatting.
#. Execute ``make lint`` to run ``ameba`` and ``flaw`` across ``src/`` and ``spec/`` with zero warnings and zero suppressions.
#. Execute ``make test`` to run the complete ``crystal spec`` suite across all ``ML-KEM`` and ``ML-DSA`` parameter sets and concurrent fiber stress tests.
#. Execute ``make doc-check`` and ``make docs`` to validate all reStructuredText files with ``crstlint`` and ``rstcheck`` and build both the Sphinx ``dirhtml`` portal and Crystal API documentation.
#. Update ``CHANGELOG.rst`` and ``shard.yml`` version metadata, commit with a signed Conventional Commit message, and create a GPG-signed annotated tag ``git tag -s vX.Y.Z``.
