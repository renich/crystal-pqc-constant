module Crystal::Pqc::Constant
  # Standardized parameter sets for NIST FIPS 203 (`ML-KEM`).
  enum KEMVariant
    MLKEM512
    MLKEM768
    MLKEM1024

    # Returns the canonical OpenSSL 3.5+ algorithm identifier for this variant.
    def algorithm_name : String
      {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}[value]
    end

    # Returns the FIPS 203 encapsulation key (public key) length in bytes.
    def public_key_size : Int32
      {800, 1184, 1568}[value]
    end

    # Returns the FIPS 203 decapsulation key (secret key) length in bytes.
    def secret_key_size : Int32
      {1632, 2400, 3168}[value]
    end

    # Returns the FIPS 203 ciphertext length in bytes.
    def ciphertext_size : Int32
      {768, 1088, 1568}[value]
    end

    # Returns the FIPS 203 shared secret length in bytes (always 32 bytes).
    def shared_secret_size : Int32
      32
    end
  end

  # Single-use wrapper around a 32-byte ML-KEM shared secret in `libsodium` guarded memory.
  class SharedSecret
    # Canonical byte length of an ML-KEM shared secret.
    BYTE_SIZE = 32

    @buffer : SecureBuffer

    # Initializes a `SharedSecret` by copying 32 bytes into guarded memory.
    def initialize(secret_bytes : Bytes) : Nil
      raise InvalidKeyError.new("Invalid SharedSecret size: #{secret_bytes.size}") if secret_bytes.size != BYTE_SIZE
      @buffer = SecureBuffer.new(secret_bytes)
    end

    # Yields a 32-byte slice of the shared secret and guarantees disposal in `ensure`.
    def consume(& : Bytes -> T) : T forall T
      temp = Bytes.new(BYTE_SIZE)
      begin
        @buffer.with_slice(&.copy_to(temp))
        yield temp
      ensure
        Sodium.memzero(temp)
        dispose
      end
    end

    # Wipes and frees the underlying guarded memory idempotently.
    def dispose : Nil
      @buffer.dispose
    end

    # Returns `true` if the shared secret has been consumed or explicitly disposed.
    def disposed? : Bool
      @buffer.disposed?
    end
  end

  # NIST FIPS 203 (`ML-KEM`) key pair with guarded secret key storage in `libsodium` memory.
  class MLKEMKeyPair
    # Canonical byte length of a FIPS 203 `(d, z)` deterministic seed.
    SEED_SIZE = 64

    # The `KEMVariant` parameter set for this key pair.
    getter variant : KEMVariant

    @public_key : Bytes
    @secret_buffer : SecureBuffer

    private def initialize(@public_key : Bytes, secret_key : Bytes, @variant : KEMVariant) : Nil
      @secret_buffer = SecureBuffer.new(secret_key)
    end

    # Returns a defensive clone of the public encapsulation key bytes.
    def public_key : Bytes
      raise DisposedError.new("MLKEMKeyPair has already been disposed") if disposed?
      @public_key.dup
    end

    # Returns a defensive copy of the raw secret key bytes for serialization.
    def secret_key : Bytes
      @secret_buffer.with_slice(&.dup)
    end

    # Generates a fresh ML-KEM key pair using the OpenSSL 3.5+ provider.
    def self.generate(variant : KEMVariant = KEMVariant::MLKEM768) : self
      EvpKeyHelper.generate_raw_keypair(
        variant.algorithm_name, variant.public_key_size, variant.secret_key_size
      ) { |pub, priv| new(pub, priv, variant) }
    end

    # Deterministically derives an `MLKEMKeyPair` from a 64-byte `(d, z)` *seed*.
    def self.from_seed(seed : Bytes, variant : KEMVariant = KEMVariant::MLKEM768) : self
      raise InvalidKeyError.new("Invalid #{variant.algorithm_name} seed size: #{seed.size}") if seed.size != SEED_SIZE
      EvpKeyHelper.generate_raw_keypair_from_seed(
        variant.algorithm_name, seed, variant.public_key_size, variant.secret_key_size
      ) { |pub, priv| new(pub, priv, variant) }
    end

    # Constructs an `MLKEMKeyPair` from raw public and secret key byte slices.
    def self.from_raw_keys(public_key : Bytes, secret_key : Bytes, variant : KEMVariant = KEMVariant::MLKEM768) : self
      Sodium.init
      EvpKeyHelper.validate_raw_keypair(
        variant.algorithm_name, public_key, secret_key, variant.public_key_size, variant.secret_key_size
      )
      new(public_key.dup, secret_key, variant)
    end

    # Encapsulates a fresh 32-byte `SharedSecret` against *public_key*.
    def self.encapsulate(
      public_key : Bytes, variant : KEMVariant = KEMVariant::MLKEM768,
    ) : NamedTuple(ciphertext: Bytes, shared_secret: SharedSecret)
      Sodium.init
      if public_key.size != variant.public_key_size
        raise InvalidKeyError.new("Invalid #{variant.algorithm_name} public key size: #{public_key.size}")
      end
      pkey = EvpKeyHelper.load_public_key(variant.algorithm_name, public_key)
      begin
        perform_encapsulation(pkey, variant)
      ensure
        LibCryptoPQC.EVP_PKEY_free(pkey)
      end
    end

    # Encapsulates a fresh 32-byte `SharedSecret` using this key pair's public key.
    def encapsulate : NamedTuple(ciphertext: Bytes, shared_secret: SharedSecret)
      raise DisposedError.new("MLKEMKeyPair has already been disposed") if disposed?
      self.class.encapsulate(@public_key, @variant)
    end

    # Decapsulates *ciphertext* using the guarded secret key and returns a `SharedSecret`.
    def decapsulate(ciphertext : Bytes) : SharedSecret
      @secret_buffer.with_slice do |secret_slice|
        if ciphertext.size != @variant.ciphertext_size
          raise InvalidKeyError.new("Invalid #{@variant.algorithm_name} ciphertext size: #{ciphertext.size}")
        end
        pkey = EvpKeyHelper.load_private_key(@variant.algorithm_name, secret_slice)
        begin
          self.class.perform_decapsulation(pkey, ciphertext, @variant)
        ensure
          LibCryptoPQC.EVP_PKEY_free(pkey)
        end
      end
    end

    # Wipes and frees the guarded secret key buffer idempotently.
    def dispose : Nil
      @secret_buffer.dispose
    end

    # Returns `true` if the secret key buffer has been wiped and freed.
    def disposed? : Bool
      @secret_buffer.disposed?
    end

    protected def self.perform_encapsulation(
      pkey : LibCryptoPQC::EvpPkey, v : KEMVariant,
    ) : NamedTuple(ciphertext: Bytes, shared_secret: SharedSecret)
      ctx = LibCryptoPQC.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
      raise EncapsulationError.new("EVP_PKEY_CTX_new_from_pkey failed") if ctx.null?
      ct = Bytes.new(v.ciphertext_size)
      ss = Bytes.new(v.shared_secret_size)
      begin
        run_encapsulate_ctx(ctx, ct, ss)
        {ciphertext: ct, shared_secret: SharedSecret.new(ss)}
      ensure
        Sodium.memzero(ss)
        LibCryptoPQC.EVP_PKEY_CTX_free(ctx)
      end
    end

    private def self.run_encapsulate_ctx(ctx : LibCryptoPQC::EvpPkeyCtx, ct : Bytes, ss : Bytes) : Nil
      if LibCryptoPQC.EVP_PKEY_encapsulate_init(ctx, nil) <= 0
        raise EncapsulationError.new("EVP_PKEY_encapsulate_init failed")
      end
      ct_len = LibC::SizeT.new(ct.size)
      ss_len = LibC::SizeT.new(ss.size)
      rc = LibCryptoPQC.EVP_PKEY_encapsulate(ctx, ct.to_unsafe, pointerof(ct_len), ss.to_unsafe, pointerof(ss_len))
      return unless rc <= 0 || ct_len.to_i32 != ct.size || ss_len.to_i32 != ss.size
      raise EncapsulationError.new("EVP_PKEY_encapsulate failed")
    end

    protected def self.perform_decapsulation(pkey : LibCryptoPQC::EvpPkey, ct : Bytes, v : KEMVariant) : SharedSecret
      ctx = LibCryptoPQC.EVP_PKEY_CTX_new_from_pkey(nil, pkey, nil)
      raise EncapsulationError.new("EVP_PKEY_CTX_new_from_pkey failed") if ctx.null?
      ss = Bytes.new(v.shared_secret_size)
      begin
        run_decapsulate_ctx(ctx, ss, ct)
        SharedSecret.new(ss)
      ensure
        Sodium.memzero(ss)
        LibCryptoPQC.EVP_PKEY_CTX_free(ctx)
      end
    end

    private def self.run_decapsulate_ctx(ctx : LibCryptoPQC::EvpPkeyCtx, ss : Bytes, ct : Bytes) : Nil
      if LibCryptoPQC.EVP_PKEY_decapsulate_init(ctx, nil) <= 0
        raise EncapsulationError.new("EVP_PKEY_decapsulate_init failed")
      end
      ss_len = LibC::SizeT.new(ss.size)
      rc = LibCryptoPQC.EVP_PKEY_decapsulate(ctx, ss.to_unsafe, pointerof(ss_len), ct.to_unsafe, ct.size)
      raise EncapsulationError.new("EVP_PKEY_decapsulate failed") if rc <= 0 || ss_len.to_i32 != ss.size
    end
  end
end
