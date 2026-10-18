=====================
Architecture Overview
=====================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, and ``[FUNC-005]``.

Library Layout and Namespaces
-----------------------------

The library source is organized under the ``Crystal::Pqc::Constant`` namespace:

* **src/crystal-pqc-constant.cr**: Shard entrypoint requiring all submodules.
* **src/crystal-pqc-constant/version.cr**: Semantic version string ``VERSION = "0.1.0"``.
* **src/crystal-pqc-constant/errors.cr**: Domain exception hierarchy rooted at ``PQCError``.
* **src/crystal-pqc-constant/sodium.cr**: ``LibSodium`` C bindings, ``Sodium`` constant-time helpers, and ``SecureBuffer`` guarded memory management.
* **src/crystal-pqc-constant/lib_crypto_pqc.cr**: OpenSSL 3.5+ ``EVP_PKEY`` and ``EVP_MD_CTX`` bindings plus ``EvpKeyHelper``.
* **src/crystal-pqc-constant/ml_kem.cr**: ``KEMVariant``, ``SharedSecret``, and ``MLKEMKeyPair`` (FIPS 203).
* **src/crystal-pqc-constant/ml_dsa.cr**: ``DSAVariant`` and ``MLDSAKeyPair`` (FIPS 204).

Guarded Memory and Allocation Profile
-------------------------------------

Private decapsulation and signing keys are never retained on the garbage-collected Crystal heap. During key generation, temporary extraction buffers are immediately copied into ``sodium_malloc`` guarded pages, marked read-only via ``sodium_mprotect_readonly``, and wiped from the stack/heap via ``sodium_memzero``.
