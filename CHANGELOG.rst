=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

[Unreleased]
============

.. rubric:: Added

- Phase 2 (``v0.2.0``) functional and technical specifications ``[FUNC-006]``/``[TECH-006]`` (NIST FIPS 204 domain-separation ``context`` strings of ``0..255`` bytes) and ``[FUNC-007]``/``[TECH-007]`` (deterministic ``(d, z)`` and ``xi`` seed key generation and NIST ACVP Known-Answer Test suite), recorded in ``ADR-002``.
- Dependency-tracked Phase 1 (``TASK-101``..``TASK-105``) and Phase 2 (``TASK-201``..``TASK-204``) roadmaps with critical-path analysis and 1:1 requirement traceability.
- Declarative D2 architecture and roadmap diagrams (``docs/diagrams/architecture.d2``, ``docs/diagrams/roadmaps/roadmap.d2``, ``docs/diagrams/roadmaps/phase-1-mvp.d2``, ``docs/diagrams/roadmaps/phase-2-enhancement.d2``) compiled to SVG and embedded across Sphinx specifications.
- Visual branding assets ``assets/banner.svg`` and ``assets/icon.svg`` and full ``README.md`` and ``CONTRIBUTING.rst`` alignment with the ``init/lib`` standard.

[0.1.0] - 2026-10-18
====================

.. rubric:: Added

- Initial standalone release of ``crystal-pqc-constant`` under ``Crystal::Pqc::Constant``.
- NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``) via ``KEMVariant``, ``SharedSecret``, and ``MLKEMKeyPair``.
- NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm (``ML-DSA-44``, ``ML-DSA-65``, ``ML-DSA-87``) via ``DSAVariant`` and ``MLDSAKeyPair``.
- ``libsodium`` guarded memory ``SecureBuffer`` using ``sodium_malloc``, ``sodium_mprotect_readonly``, ``sodium_mprotect_readwrite``, ``sodium_memzero``, and ``sodium_free`` synchronized with ``Sync::Mutex``.
- OpenSSL 3.5+ ``EVP_PKEY`` and ``EVP_MD_CTX`` C ABI bindings in ``LibCryptoPQC`` with raw keypair consistency verification.
- Typed exception hierarchy: ``PQCError``, ``DisposedError``, ``InvalidKeyError``, ``EncapsulationError``, and ``SignatureError``.
- Complete spec suite, Sphinx documentation hierarchy, ``GNUmakefile``, and GitLab CI pipeline.
