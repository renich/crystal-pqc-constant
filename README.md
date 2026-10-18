# crystal-pqc-constant

Post-Quantum Cryptography (**NIST FIPS 203 `ML-KEM`** and **NIST FIPS 204 `ML-DSA`**) for Crystal, combining OpenSSL 3.5+ native `EVP_PKEY` providers with `libsodium` guarded memory (`sodium_malloc` + `sodium_mprotect_readonly`).

## Overview

`crystal-pqc-constant` (`Crystal::Pqc::Constant`) is a standalone, zero-dependency Crystal shard providing production-grade post-quantum key encapsulation and digital signatures:

1. **NIST FIPS 203 (`ML-KEM`) — Module-Lattice-Based Key-Encapsulation Mechanism**:
   - Supports `ML-KEM-512` (NIST Category 1), `ML-KEM-768` (NIST Category 3, default), and `ML-KEM-1024` (NIST Category 5).
   - Preserves FIPS 203 implicit rejection on decapsulation of modified ciphertexts and wraps the resulting 32-byte shared secret in a single-use `SharedSecret` backed by `libsodium` guarded memory.
2. **NIST FIPS 204 (`ML-DSA`) — Module-Lattice-Based Digital Signature Algorithm**:
   - Supports `ML-DSA-44` (NIST Category 2), `ML-DSA-65` (NIST Category 3, default), and `ML-DSA-87` (NIST Category 5).
   - Provides detached signing and verification via OpenSSL 3.5+ `EVP_DigestSign` and `EVP_DigestVerify`.
3. **Guarded Memory Isolation (`libsodium`)**:
   - Private keys and shared secrets are never left on the garbage-collected Crystal heap.
   - `SecureBuffer` allocates pages via `sodium_malloc`, copies key material in, locks the page permissions to read-only via `sodium_mprotect_readonly`, and synchronizes access with `Sync::Mutex`.
   - Calling `#dispose` (or `SharedSecret#consume`) restores read-write access, zeroes the pages with `sodium_memzero`, and releases the allocation via `sodium_free`.

## Parameter Matrix

### NIST FIPS 203 (`ML-KEM`)

| Variant | OpenSSL Name | Public Key (B) | Secret Key (B) | Ciphertext (B) | Shared Secret (B) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `KEMVariant::MLKEM512` | `ML-KEM-512` | 800 | 1632 | 768 | 32 |
| `KEMVariant::MLKEM768` | `ML-KEM-768` | 1184 | 2400 | 1088 | 32 |
| `KEMVariant::MLKEM1024` | `ML-KEM-1024` | 1568 | 3168 | 1568 | 32 |

### NIST FIPS 204 (`ML-DSA`)

| Variant | OpenSSL Name | Public Key (B) | Secret Key (B) | Signature (B) |
| :--- | :--- | :---: | :---: | :---: |
| `DSAVariant::MLDSA44` | `ML-DSA-44` | 1312 | 2560 | 2420 |
| `DSAVariant::MLDSA65` | `ML-DSA-65` | 1952 | 4032 | 3309 |
| `DSAVariant::MLDSA87` | `ML-DSA-87` | 2592 | 4896 | 4627 |

## Installation

Ensure OpenSSL 3.5+ (`openssl-devel` / `openssl-dev`) and `libsodium` (`libsodium-devel` / `libsodium-dev`) are installed on your system, then add `crystal-pqc-constant` to your `shard.yml`:

```yaml
dependencies:
  crystal-pqc-constant:
    gitlab: renich/crystal-pqc-constant
    version: ~> 0.1.0
```

## Usage

### ML-KEM Key Encapsulation

```crystal
require "crystal-pqc-constant"

alice = Crystal::Pqc::Constant::MLKEMKeyPair.generate(
  Crystal::Pqc::Constant::KEMVariant::MLKEM768
)
begin
  enc = Crystal::Pqc::Constant::MLKEMKeyPair.encapsulate(alice.public_key)
  dec_secret = alice.decapsulate(enc[:ciphertext])

  agreed = enc[:shared_secret].consume do |sender_secret|
    dec_secret.consume do |receiver_secret|
      Crystal::Pqc::Constant::Sodium.constant_time_equal?(sender_secret, receiver_secret)
    end
  end
  puts "Shared secret agreed: #{agreed}"
ensure
  alice.dispose
end
```

### ML-DSA Digital Signatures

```crystal
require "crystal-pqc-constant"

signer = Crystal::Pqc::Constant::MLDSAKeyPair.generate(
  Crystal::Pqc::Constant::DSAVariant::MLDSA65
)
begin
  message = "FIDO2 post-quantum assertion".to_slice
  signature = signer.sign(message)
  puts "Verified: #{signer.verify(message, signature)}"
ensure
  signer.dispose
end
```

## Development & Verification

```bash
shards install
make all
make doc-check
make docs
```

## License

- Source code: **GPL-3.0-or-later** (`LICENSE`)
- Documentation: **GFDL-1.3-or-later** (`LICENSE-DOCS`)
