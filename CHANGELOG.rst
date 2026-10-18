=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

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
