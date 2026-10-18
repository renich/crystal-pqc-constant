=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

[Unreleased]
============

[0.1.1] - 2026-10-18
====================

.. rubric:: Added

- NIST FIPS 204 Section 5.2 domain-separation ``context`` strings (``0..255`` bytes) in ``MLDSAKeyPair#sign``, ``MLDSAKeyPair#verify``, and ``MLDSAKeyPair.verify`` via OpenSSL 3.5+ ``OSSL_SIGNATURE_PARAM_CONTEXT_STRING`` (``[FUNC-006]``, ``[TECH-006]``).
- Deterministic seed-based key generation ``MLKEMKeyPair.from_seed`` (64-byte FIPS 203 ``(d, z)`` seed) and ``MLDSAKeyPair.from_seed`` (32-byte FIPS 204 ``xi`` seed) backed by ``EVP_PKEY_CTX_set_params`` and ``libsodium`` guarded memory (``[FUNC-007]``, ``[TECH-007]``).
- Official NIST ACVP Known-Answer Test verification suite (``spec/acvp_kat_spec.cr``) across all six parameter sets (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``, ``ML-DSA-44``, ``ML-DSA-65``, ``ML-DSA-87``).
- Extracted ``EvpKeyHelper`` into ``src/crystal-pqc-constant/evp_key_helper.cr`` and added ``LibCryptoPQC::OsslParamData`` marshaling in ``src/crystal-pqc-constant/lib_crypto_pqc.cr``.
- Dependency-tracked Phase 1 (``TASK-101``..``TASK-105``) and Phase 2 (``TASK-201``..``TASK-204``) roadmaps, ``ADR-002``, D2 architecture and roadmap diagrams compiled to SVG, and visual branding assets ``assets/banner.svg`` and ``assets/icon.svg``.

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
