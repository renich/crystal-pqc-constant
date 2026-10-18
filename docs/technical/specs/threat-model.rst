============
Threat Model
============

Adversary Capabilities and Mitigations
--------------------------------------

* **Quantum Cryptanalysis**: Mitigated by NIST FIPS 203 ``ML-KEM`` and FIPS 204 ``ML-DSA`` module-lattice constructions.
* **Chosen-Ciphertext Attacks on ML-KEM**: Mitigated by FIPS 203 implicit rejection inside OpenSSL 3.5+ ``EVP_PKEY_decapsulate``, which returns a deterministic pseudorandom secret when a ciphertext is modified without leaking failure timing.
* **Timing Side-Channel Leaks**: Secret comparisons and shared-secret equality checks use ``Sodium.constant_time_equal?`` backed by ``sodium_memcmp``.
* **Heap Inspection and Swap Leakage**: Long-lived secret keys and shared secrets reside in ``sodium_malloc`` allocations surrounded by canary guard pages, locked into physical RAM where supported by OS limits, marked ``PROT_READ`` at rest via ``sodium_mprotect_readonly``, and wiped via ``sodium_memzero`` prior to release.
* **Mismatched Key Injection**: ``from_raw_keys`` validates both raw key sizes and derives the public key from the secret key via OpenSSL ``EVP_PKEY`` to verify constant-time equality before constructing a key pair.
