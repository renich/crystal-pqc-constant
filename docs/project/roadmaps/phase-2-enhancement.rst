====================
Phase 2: Enhancement
====================

Future Objectives
-----------------

Planned post-``v0.1.0`` enhancements for downstream ecosystem integration:

* **Milestone 2.1: Hybrid Key Exchange Combiners**:
  Standardized hybrid combiners pairing ``X25519`` (from ``crystal-ecc-constant``) with ``ML-KEM-768`` and ``Ed25519`` with ``ML-DSA-65``.
* **Milestone 2.2: Deterministic Seed Derivation**:
  Support FIPS 203 ``d||z`` and FIPS 204 ``xi`` seed-based key derivation parameters via ``OSSL_PARAM`` builders.
