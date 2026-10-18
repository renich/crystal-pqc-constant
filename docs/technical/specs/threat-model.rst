============
Threat Model
============

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-006]``, and ``[FUNC-007]``.

[TECH-005] Adversary Capabilities and Cryptographic Mitigations
---------------------------------------------------------------

``crystal-pqc-constant`` defends against the following adversary classes:

* **Quantum Cryptanalysis and Harvest-Now-Decrypt-Later**: Mitigated by NIST FIPS 203 ``ML-KEM`` (Module-Learning-With-Errors key encapsulation) and NIST FIPS 204 ``ML-DSA`` (Module-Lattice digital signatures) across NIST security categories 1, 2, 3, and 5.
* **Adaptive Chosen-Ciphertext Attacks on ML-KEM**: Mitigated by FIPS 203 implicit rejection inside OpenSSL 3.5+ ``EVP_PKEY_decapsulate``. Tampered ciphertexts of valid byte length produce a deterministic pseudorandom 32-byte secret derived from the secret seed ``z`` and the ciphertext without branching or leaking failure timing.
* **Timing Side-Channel Leakage**: Mitigated by delegating polynomial arithmetic to OpenSSL 3.5+ constant-time providers and executing all secret and public-key equality checks through ``Sodium.constant_time_equal?`` backed by ``sodium_memcmp``.
* **Heap Inspection, GC Copying, and Swap Leakage**: Mitigated by pinning all long-lived secret keys and 32-byte shared secrets inside ``sodium_malloc`` allocations surrounded by guard pages, marking pages read-only at rest via ``sodium_mprotect_readonly``, and wiping buffers via ``sodium_memzero`` inside ``ensure`` blocks before freeing.
* **Mismatched Keypair Injection**: Mitigated by ``EvpKeyHelper.validate_raw_keypair``, which derives the canonical public key from the imported secret key via OpenSSL 3.5+ ``EVP_PKEY`` and verifies constant-time equality with the supplied public key slice before instantiating a key pair.
* **Cross-Protocol Signature Replay**: Mitigated in Phase 2 ``v0.2.0`` by NIST FIPS 204 domain-separation ``context`` strings (``0..255`` bytes) bound into the ``ML-DSA`` message representative via ``OSSL_SIGNATURE_PARAM_CONTEXT_STRING`` (``[FUNC-006]``, ``[TECH-006]``).
* **Provider Implementation Drift**: Mitigated in Phase 2 ``v0.2.0`` by deterministic seed expansion and NIST ACVP Known-Answer Test verification across all six parameter sets (``[FUNC-007]``, ``[TECH-007]``).
