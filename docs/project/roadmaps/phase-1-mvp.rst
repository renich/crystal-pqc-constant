============
Phase 1: MVP
============

Timeline and Objectives
-----------------------

Deliver the production-complete ``v0.1.0`` release of ``crystal-pqc-constant`` implementing NIST FIPS 203 ``ML-KEM`` and FIPS 204 ``ML-DSA`` backed by OpenSSL 3.5+ and ``libsodium`` guarded memory.

Milestones and Deliverables
---------------------------

* **Milestone 1.1: Core Cryptographic Runtime**:

  - [x] ``LibSodium``, ``Sodium``, and ``SecureBuffer`` guarded memory primitives.
  - [x] ``LibCryptoPQC`` and ``EvpKeyHelper`` OpenSSL 3.5+ ``EVP_PKEY`` bindings.
  - [x] ``KEMVariant``, ``SharedSecret``, and ``MLKEMKeyPair`` across ``ML-KEM-512``, ``ML-KEM-768``, and ``ML-KEM-1024``.
  - [x] ``DSAVariant`` and ``MLDSAKeyPair`` across ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``.

* **Milestone 1.2: Quality Gates and Documentation**:

  - [x] Spec suite covering all variants, implicit rejection, disposal semantics, and concurrent fibers.
  - [x] Zero-warning ``ameba``, ``flaw``, ``crstlint``, and ``rstcheck`` compliance.
  - [x] Sphinx ``dirhtml`` documentation portal and GitLab CI pipeline.
