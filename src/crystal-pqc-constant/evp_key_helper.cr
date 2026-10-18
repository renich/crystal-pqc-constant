module Crystal::Pqc::Constant
  # Internal helper routines for OpenSSL 3.5+ `EVP_PKEY` lifecycle management,
  # `OSSL_PARAM` construction, parameter extraction, and raw key validation.
  module EvpKeyHelper
    # Builds a two-element null-terminated `OsslParamData` array for an octet-string parameter.
    def self.build_octet_param_array(
      key : String,
      slice : Bytes,
    ) : StaticArray(LibCryptoPQC::OsslParamData, 2)
      params = StaticArray(LibCryptoPQC::OsslParamData, 2).new(LibCryptoPQC::OsslParamData.new)
      entry = LibCryptoPQC::OsslParamData.new
      entry.key = key.to_unsafe
      entry.data_type = LibCryptoPQC::OSSL_PARAM_OCTET_STRING
      entry.data = slice.to_unsafe.as(Void*)
      entry.data_size = LibC::SizeT.new(slice.size)
      entry.return_size = LibC::SizeT.new(0)
      params[0] = entry
      params
    end

    # Generates a fresh OpenSSL keypair for *algorithm*, yields `(pub, priv)`,
    # and deterministically wipes `priv` and frees the `EVP_PKEY` handle.
    def self.generate_raw_keypair(
      algorithm : String,
      pub_size : Int32,
      sec_size : Int32,
      & : (Bytes, Bytes) -> T
    ) : T forall T
      Sodium.init
      with_extracted_keypair(generate_pkey(algorithm), pub_size, sec_size) do |pub, priv|
        yield pub, priv
      end
    end

    # Generates a deterministic OpenSSL keypair for *algorithm* from *seed*,
    # yields `(pub, priv)`, and wipes temporary seed and private key buffers.
    def self.generate_raw_keypair_from_seed(
      algorithm : String,
      seed : Bytes,
      pub_size : Int32,
      sec_size : Int32,
      & : (Bytes, Bytes) -> T
    ) : T forall T
      Sodium.init
      seed_copy = seed.dup
      begin
        with_extracted_keypair(generate_pkey(algorithm, seed_copy), pub_size, sec_size) do |pub, priv|
          yield pub, priv
        end
      ensure
        Sodium.memzero(seed_copy)
      end
    end

    # Generates a fresh OpenSSL `EVP_PKEY` handle for *algorithm*.
    def self.generate_pkey(algorithm : String, seed : Bytes? = nil) : LibCryptoPQC::EvpPkey
      ctx = LibCryptoPQC.EVP_PKEY_CTX_new_from_name(nil, algorithm, nil)
      raise InvalidKeyError.new("Failed to create EVP_PKEY_CTX for #{algorithm}") if ctx.null?

      begin
        run_keygen_ctx(ctx, algorithm, seed)
      ensure
        LibCryptoPQC.EVP_PKEY_CTX_free(ctx)
      end
    end

    # Extracts an octet-string parameter of *expected_size* bytes from *pkey*.
    def self.extract_octet_param(
      pkey : LibCryptoPQC::EvpPkey,
      param_name : String,
      expected_size : Int32,
    ) : Bytes
      buf = Bytes.new(expected_size)
      out_len = LibC::SizeT.new(0)
      rc = LibCryptoPQC.EVP_PKEY_get_octet_string_param(
        pkey, param_name, buf.to_unsafe, buf.size, pointerof(out_len)
      )
      if rc != 1 || out_len.to_i32 != expected_size
        Sodium.memzero(buf)
        raise InvalidKeyError.new("Failed to extract OpenSSL parameter '#{param_name}'")
      end
      buf
    end

    # Loads a raw public key slice into an OpenSSL `EVP_PKEY` handle.
    def self.load_public_key(algorithm : String, public_key : Bytes) : LibCryptoPQC::EvpPkey
      pkey = LibCryptoPQC.EVP_PKEY_new_raw_public_key_ex(
        nil, algorithm, nil, public_key.to_unsafe, public_key.size
      )
      raise InvalidKeyError.new("Invalid #{algorithm} public key material") if pkey.null?
      pkey
    end

    # Loads a raw private key slice into an OpenSSL `EVP_PKEY` handle.
    def self.load_private_key(algorithm : String, secret_key : Bytes) : LibCryptoPQC::EvpPkey
      pkey = LibCryptoPQC.EVP_PKEY_new_raw_private_key_ex(
        nil, algorithm, nil, secret_key.to_unsafe, secret_key.size
      )
      raise InvalidKeyError.new("Invalid #{algorithm} secret key material") if pkey.null?
      pkey
    end

    # Validates raw public and secret key lengths and verifies keypair consistency.
    def self.validate_raw_keypair(
      algorithm : String,
      public_key : Bytes,
      secret_key : Bytes,
      expected_pub_size : Int32,
      expected_sec_size : Int32,
    ) : Nil
      if public_key.size != expected_pub_size
        raise InvalidKeyError.new("Invalid #{algorithm} public key size: #{public_key.size}")
      end
      if secret_key.size != expected_sec_size
        raise InvalidKeyError.new("Invalid #{algorithm} secret key size: #{secret_key.size}")
      end
      verify_keypair_match(algorithm, public_key, secret_key, expected_pub_size)
    end

    protected def self.with_extracted_keypair(
      pkey : LibCryptoPQC::EvpPkey,
      pub_size : Int32,
      sec_size : Int32,
      & : (Bytes, Bytes) -> T
    ) : T forall T
      begin
        pub = extract_octet_param(pkey, "pub", pub_size)
        priv = extract_octet_param(pkey, "priv", sec_size)
        begin
          yield pub, priv
        ensure
          Sodium.memzero(priv)
        end
      ensure
        LibCryptoPQC.EVP_PKEY_free(pkey)
      end
    end

    private def self.run_keygen_ctx(
      ctx : LibCryptoPQC::EvpPkeyCtx,
      algorithm : String,
      seed : Bytes?,
    ) : LibCryptoPQC::EvpPkey
      if LibCryptoPQC.EVP_PKEY_keygen_init(ctx) <= 0
        raise InvalidKeyError.new("EVP_PKEY_keygen_init failed for #{algorithm}")
      end
      if seed_bytes = seed
        params = build_octet_param_array("seed", seed_bytes)
        if LibCryptoPQC.EVP_PKEY_CTX_set_params(ctx, params.to_unsafe) <= 0
          raise InvalidKeyError.new("EVP_PKEY_CTX_set_params(seed) failed for #{algorithm}")
        end
      end
      pkey = Pointer(Void).null
      if LibCryptoPQC.EVP_PKEY_keygen(ctx, pointerof(pkey)) <= 0 || pkey.null?
        raise InvalidKeyError.new("EVP_PKEY_keygen failed for #{algorithm}")
      end
      pkey
    end

    private def self.verify_keypair_match(
      algorithm : String,
      public_key : Bytes,
      secret_key : Bytes,
      expected_pub_size : Int32,
    ) : Nil
      pub_pkey = load_public_key(algorithm, public_key)
      LibCryptoPQC.EVP_PKEY_free(pub_pkey)

      priv_pkey = load_private_key(algorithm, secret_key)
      begin
        derived_pub = extract_octet_param(priv_pkey, "pub", expected_pub_size)
        unless Sodium.constant_time_equal?(derived_pub, public_key)
          raise InvalidKeyError.new("Public key does not match secret key for #{algorithm}")
        end
      ensure
        LibCryptoPQC.EVP_PKEY_free(priv_pkey)
      end
    end
  end
end
