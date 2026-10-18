module Crystal::Pqc::Constant
  # Standardized parameter sets for NIST FIPS 204 Module-Lattice-Based
  # Digital Signature Algorithm (`ML-DSA`).
  enum DSAVariant
    MLDSA44
    MLDSA65
    MLDSA87

    # Returns the canonical OpenSSL 3.5+ algorithm identifier for this variant.
    def algorithm_name : String
      {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}[value]
    end

    # Returns the FIPS 204 verification key (public key) length in bytes.
    def public_key_size : Int32
      {1312, 1952, 2592}[value]
    end

    # Returns the FIPS 204 signing key (secret key) length in bytes.
    def secret_key_size : Int32
      {2560, 4032, 4896}[value]
    end

    # Returns the FIPS 204 detached signature length in bytes.
    def signature_size : Int32
      {2420, 3309, 4627}[value]
    end
  end

  # NIST FIPS 204 (`ML-DSA`) key pair managing a public verification key and
  # a guarded signing secret key in `libsodium` secure memory.
  class MLDSAKeyPair
    # Canonical byte length of a FIPS 204 `xi` deterministic seed.
    SEED_SIZE = 32

    # Maximum byte length of a FIPS 204 domain-separation context string.
    MAX_CONTEXT_SIZE = 255

    # The `DSAVariant` parameter set for this key pair.
    getter variant : DSAVariant

    @public_key : Bytes
    @secret_buffer : SecureBuffer

    private def initialize(@public_key : Bytes, secret_key : Bytes, @variant : DSAVariant) : Nil
      @secret_buffer = SecureBuffer.new(secret_key)
    end

    # Returns a defensive clone of the public verification key bytes.
    def public_key : Bytes
      raise DisposedError.new("MLDSAKeyPair has already been disposed") if disposed?

      @public_key.dup
    end

    # Returns a defensive copy of the raw secret key bytes for serialization.
    def secret_key : Bytes
      @secret_buffer.with_slice(&.dup)
    end

    # Generates a fresh ML-DSA key pair using the OpenSSL 3.5+ provider.
    def self.generate(variant : DSAVariant = DSAVariant::MLDSA65) : self
      EvpKeyHelper.generate_raw_keypair(
        variant.algorithm_name, variant.public_key_size, variant.secret_key_size
      ) do |pub, priv|
        new(pub, priv, variant)
      end
    end

    # Deterministically derives an `MLDSAKeyPair` from a 32-byte `xi` *seed*.
    def self.from_seed(seed : Bytes, variant : DSAVariant = DSAVariant::MLDSA65) : self
      if seed.size != SEED_SIZE
        raise InvalidKeyError.new("Invalid #{variant.algorithm_name} seed size: #{seed.size}")
      end
      EvpKeyHelper.generate_raw_keypair_from_seed(
        variant.algorithm_name, seed, variant.public_key_size, variant.secret_key_size
      ) { |pub, priv| new(pub, priv, variant) }
    end

    # Constructs an `MLDSAKeyPair` from raw public and secret key byte slices.
    def self.from_raw_keys(
      public_key : Bytes,
      secret_key : Bytes,
      variant : DSAVariant = DSAVariant::MLDSA65,
    ) : self
      Sodium.init
      EvpKeyHelper.validate_raw_keypair(
        variant.algorithm_name, public_key, secret_key, variant.public_key_size, variant.secret_key_size
      )
      new(public_key.dup, secret_key, variant)
    end

    # Signs *message* with an optional FIPS 204 domain-separation *context*
    # (`0..255` bytes) using the guarded secret key and returns the detached signature.
    def sign(message : Bytes, context : Bytes = Bytes.empty) : Bytes
      self.class.validate_context!(context)
      @secret_buffer.with_slice do |secret_slice|
        pkey = EvpKeyHelper.load_private_key(@variant.algorithm_name, secret_slice)
        begin
          self.class.perform_sign(pkey, message, @variant, context)
        ensure
          LibCryptoPQC.EVP_PKEY_free(pkey)
        end
      end
    end

    # Verifies *signature* against *message* and optional *context* (`0..255` bytes)
    # using this key pair's public key.
    def verify(message : Bytes, signature : Bytes, context : Bytes = Bytes.empty) : Bool
      raise DisposedError.new("MLDSAKeyPair has already been disposed") if disposed?

      self.class.verify(@public_key, message, signature, @variant, context: context)
    end

    # Verifies *signature* against *message* and optional *context* (`0..255` bytes)
    # using a raw *public_key* slice.
    def self.verify(
      public_key : Bytes,
      message : Bytes,
      signature : Bytes,
      variant : DSAVariant = DSAVariant::MLDSA65,
      context : Bytes = Bytes.empty,
    ) : Bool
      Sodium.init
      validate_context!(context)
      if public_key.size != variant.public_key_size
        raise InvalidKeyError.new("Invalid #{variant.algorithm_name} public key size: #{public_key.size}")
      end
      return false if signature.size != variant.signature_size

      pkey = EvpKeyHelper.load_public_key(variant.algorithm_name, public_key)
      begin
        perform_verify(pkey, message, signature, context)
      ensure
        LibCryptoPQC.EVP_PKEY_free(pkey)
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

    protected def self.validate_context!(context : Bytes) : Nil
      return unless context.size > MAX_CONTEXT_SIZE

      raise SignatureError.new("Invalid ML-DSA context size: #{context.size} (max #{MAX_CONTEXT_SIZE})")
    end

    protected def self.perform_sign(
      pkey : LibCryptoPQC::EvpPkey,
      message : Bytes,
      variant : DSAVariant,
      context : Bytes,
    ) : Bytes
      md_ctx = LibCrypto.evp_md_ctx_new
      raise SignatureError.new("EVP_MD_CTX_new failed") if md_ctx.null?

      sig = Bytes.new(variant.signature_size)
      begin
        run_digest_sign(md_ctx, pkey, sig, message, context)
        sig
      ensure
        LibCrypto.evp_md_ctx_free(md_ctx)
      end
    end

    private def self.run_digest_sign(
      md_ctx : LibCryptoPQC::EvpMdCtx,
      pkey : LibCryptoPQC::EvpPkey,
      sig : Bytes,
      message : Bytes,
      context : Bytes,
    ) : Nil
      params = EvpKeyHelper.build_octet_param_array("context-string", context)
      param_ptr = context.empty? ? Pointer(LibCryptoPQC::OsslParamData).null : params.to_unsafe
      if LibCryptoPQC.EVP_DigestSignInit_ex(md_ctx, nil, nil, nil, nil, pkey, param_ptr) <= 0
        raise SignatureError.new("EVP_DigestSignInit_ex failed")
      end
      sig_len = LibC::SizeT.new(sig.size)
      rc = LibCryptoPQC.EVP_DigestSign(md_ctx, sig.to_unsafe, pointerof(sig_len), message.to_unsafe, message.size)
      raise SignatureError.new("EVP_DigestSign failed") if rc <= 0 || sig_len.to_i32 != sig.size
    end

    protected def self.perform_verify(
      pkey : LibCryptoPQC::EvpPkey,
      message : Bytes,
      signature : Bytes,
      context : Bytes,
    ) : Bool
      md_ctx = LibCrypto.evp_md_ctx_new
      raise SignatureError.new("EVP_MD_CTX_new failed") if md_ctx.null?

      begin
        params = EvpKeyHelper.build_octet_param_array("context-string", context)
        param_ptr = context.empty? ? Pointer(LibCryptoPQC::OsslParamData).null : params.to_unsafe
        if LibCryptoPQC.EVP_DigestVerifyInit_ex(md_ctx, nil, nil, nil, nil, pkey, param_ptr) <= 0
          raise SignatureError.new("EVP_DigestVerifyInit_ex failed")
        end
        LibCryptoPQC.EVP_DigestVerify(md_ctx, signature.to_unsafe, signature.size, message.to_unsafe, message.size) == 1
      ensure
        LibCrypto.evp_md_ctx_free(md_ctx)
      end
    end
  end
end
