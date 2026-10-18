====================================================================
ADR-002: Phase 2 FIPS 204 Context Strings and NIST ACVP Seed Vectors
====================================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: EVALinux Cryptography Architecture Team

Context
-------

Phase 1 (``v0.1.0``) delivered NIST FIPS 203 ``ML-KEM`` and NIST FIPS 204 ``ML-DSA`` key generation, raw key serialization, encapsulation, decapsulation, detached signing, and verification backed by OpenSSL 3.5+ and ``libsodium`` guarded memory (``[FUNC-001]`` through ``[FUNC-005]``). To reach a complete cryptographic compliance posture in Phase 2 (``v0.1.1``), downstream FIDO2, WebAuthn, and PKI protocols require two additional capabilities mandated by NIST standards:

#. **NIST FIPS 204 Section 5.2 Domain-Separation Context Strings**: Pure ``ML-DSA`` signatures accept a protocol-specific ``context`` byte string of ``0..255`` bytes (defaulting to the empty string) to prevent cross-protocol signature replay between distinct application domains sharing a key pair.
#. **Deterministic Seed Expansion and NIST ACVP Known-Answer Tests**: FIPS 203 defines deterministic key generation from a 64-byte ``(d, z)`` seed and FIPS 204 defines deterministic key generation from a 32-byte ``xi`` seed. Supporting seed-based key generation enables automated verification against official NIST Automated Cryptographic Validation Protocol (ACVP) test vectors.

Decision
--------

#. **OpenSSL 3.5+ OSSL_PARAM Marshaling for Context Strings**: Fulfill ``[FUNC-006]`` and ``[TECH-006]`` by binding OpenSSL's ``OSSL_PARAM`` structure in ``LibCryptoPQC`` and passing ``OSSL_SIGNATURE_PARAM_CONTEXT_STRING`` (``"context-string"``) into ``EVP_DigestSignInit_ex`` and ``EVP_DigestVerifyInit_ex``. Signatures and verifications must default to ``context : Bytes = Bytes.empty`` for full backward compatibility with ``v0.1.0`` callers and raise ``SignatureError`` whenever ``context.size > 255``.
#. **Deterministic Seed Key Generation in Guarded Memory**: Fulfill ``[FUNC-007]`` and ``[TECH-007]`` by adding ``MLKEMKeyPair.from_seed`` (64-byte ``d || z`` seed) and ``MLDSAKeyPair.from_seed`` (32-byte ``xi`` seed) using ``EVP_PKEY_keygen_init``, ``EVP_PKEY_CTX_set_params`` with ``OSSL_PKEY_PARAM_ML_KEM_SEED``/``OSSL_PKEY_PARAM_ML_DSA_SEED`` (``"seed"``), and ``EVP_PKEY_keygen``, immediately transferring the derived private key into ``SecureBuffer`` and wiping all intermediate seed buffers via ``Sodium.memzero`` in ``ensure``.
#. **NIST ACVP KAT Verification Suite**: Fulfill ``[FUNC-007]`` and ``[TECH-007]`` by adding deterministic Known-Answer Test specifications across all six parameter sets (``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``, ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``).

Consequences
------------

* **Positive**: Achieves 100% NIST FIPS 203 and FIPS 204 functional coverage, prevents cross-protocol ``ML-DSA`` signature replay, preserves zero external Crystal shard dependencies, and provides deterministic NIST ACVP KAT verification.
* **Negative**: Requires careful ``OSSL_PARAM`` struct alignment across 64-bit POSIX targets in ``LibCryptoPQC``.
