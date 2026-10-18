=================
Release Procedure
=================

Verification Gateways
---------------------

#. Execute ``crystal tool format --check src spec`` to verify canonical formatting.
#. Execute ``make lint`` to run ``ameba`` and ``flaw`` with zero warnings or suppressions.
#. Execute ``make test`` to run the full ``crystal spec`` suite across all ``ML-KEM`` and ``ML-DSA`` variants.
#. Execute ``make doc-check`` and ``make docs`` to validate all reStructuredText files with ``crstlint`` and ``rstcheck`` and build both Sphinx ``dirhtml`` and Crystal API documentation.
#. Update ``CHANGELOG.rst`` and ``shard.yml`` version metadata and create a GPG-signed tag ``git tag -s vX.Y.Z``.
