===============================================================
ADR-001: OpenSSL 3.5+ EVP_PKEY with Libsodium Guarded Key Store
===============================================================

:Status: Accepted
:Date: 2026-10-18
:Deciders: EVALinux Cryptography Architecture Team

Context
-------

NIST standardized ``ML-KEM`` (FIPS 203) and ``ML-DSA`` (FIPS 204) for post-quantum key encapsulation and digital signatures. Beginning with OpenSSL 3.5, ``libcrypto`` ships native, constant-time, provider-backed implementations of ``ML-KEM-512``, ``ML-KEM-768``, ``ML-KEM-1024``, ``ML-DSA-44``, ``ML-DSA-65``, and ``ML-DSA-87``. However, retaining raw secret keys in garbage-collected Crystal ``Bytes`` slices or long-lived ``EVP_PKEY`` heap structs risks unintended memory retention.

Decision
--------

#. **Zero External Shard Dependencies**: Bind directly to ``libcrypto`` (OpenSSL 3.5+) and ``libsodium`` using Crystal ``lib`` FFI declarations.
#. **Guarded Secret Key Storage**: Extract raw secret key bytes upon generation, immediately wipe intermediate buffers with ``sodium_memzero``, and store secret keys exclusively inside ``SecureBuffer`` backed by ``sodium_malloc`` and ``sodium_mprotect_readonly``.
#. **Ephemeral EVP_PKEY Reconstruction**: Reconstruct ``EVP_PKEY`` handles only inside ``@secret_buffer.with_slice`` critical sections for decapsulation and signing, freeing the ``EVP_PKEY`` handle in ``ensure`` blocks.
#. **Single-Use SharedSecret Consumption**: Wrap 32-byte ``ML-KEM`` shared secrets in ``SharedSecret``, whose ``#consume`` method yields a temporary slice and guarantees deterministic zeroization and disposal in ``ensure``.

Consequences
------------

* **Positive**: Zero third-party Crystal shard dependencies, FIPS 203/204 interoperability via OpenSSL 3.5+, hardware-page protection for resting secret keys, and deterministic secret zeroization.
* **Negative**: Requires OpenSSL 3.5 or newer and ``libsodium`` installed on the target host.
