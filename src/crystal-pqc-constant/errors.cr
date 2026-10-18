module Crystal::Pqc::Constant
  # Base exception class for all Post-Quantum Cryptography failures.
  class PQCError < Exception
  end

  # Raised when attempting to use a key pair, shared secret, or secure buffer
  # after its underlying guarded memory has been wiped and disposed.
  class DisposedError < PQCError
  end

  # Raised when a public key, secret key, or key pair fails size or OpenSSL
  # key material validation.
  class InvalidKeyError < PQCError
  end

  # Raised when ML-KEM key encapsulation or decapsulation fails or receives a
  # malformed ciphertext length.
  class EncapsulationError < PQCError
  end

  # Raised when ML-DSA signature generation or verification initialization fails.
  class SignatureError < PQCError
  end
end
