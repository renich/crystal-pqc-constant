require "openssl"

module Crystal::Pqc::Constant
  # Low-level C ABI bindings to OpenSSL 3.5+ `libcrypto` `EVP_PKEY` and
  # `EVP_MD_CTX` functions for NIST FIPS 203 (`ML-KEM`) and FIPS 204 (`ML-DSA`).
  @[Link("crypto")]
  lib LibCryptoPQC
    alias EvpPkey = Void*
    alias EvpPkeyCtx = Void*
    alias EvpMdCtx = LibCrypto::EVP_MD_CTX
    alias OsslLibCtx = Void*
    alias OsslParam = Void*

    fun EVP_PKEY_CTX_new_from_name(libctx : OsslLibCtx, name : LibC::Char*, propquery : LibC::Char*) : EvpPkeyCtx
    fun EVP_PKEY_CTX_new_from_pkey(libctx : OsslLibCtx, pkey : EvpPkey, propquery : LibC::Char*) : EvpPkeyCtx
    fun EVP_PKEY_CTX_free(ctx : EvpPkeyCtx) : Void
    fun EVP_PKEY_free(pkey : EvpPkey) : Void

    fun EVP_PKEY_keygen_init(ctx : EvpPkeyCtx) : LibC::Int
    fun EVP_PKEY_keygen(ctx : EvpPkeyCtx, ppkey : EvpPkey*) : LibC::Int

    fun EVP_PKEY_get_octet_string_param(
      pkey : EvpPkey, key_name : LibC::Char*, buf : UInt8*, max_buf_sz : LibC::SizeT, out_sz : LibC::SizeT*,
    ) : LibC::Int

    fun EVP_PKEY_new_raw_public_key_ex(
      libctx : OsslLibCtx, keytype : LibC::Char*, propq : LibC::Char*, pub : UInt8*, len : LibC::SizeT,
    ) : EvpPkey

    fun EVP_PKEY_new_raw_private_key_ex(
      libctx : OsslLibCtx, keytype : LibC::Char*, propq : LibC::Char*, priv : UInt8*, len : LibC::SizeT,
    ) : EvpPkey

    fun EVP_PKEY_encapsulate_init(ctx : EvpPkeyCtx, params : OsslParam) : LibC::Int

    fun EVP_PKEY_encapsulate(
      ctx : EvpPkeyCtx, wrappedkey : UInt8*, wrappedkeylen : LibC::SizeT*, genkey : UInt8*, genkeylen : LibC::SizeT*,
    ) : LibC::Int

    fun EVP_PKEY_decapsulate_init(ctx : EvpPkeyCtx, params : OsslParam) : LibC::Int

    fun EVP_PKEY_decapsulate(
      ctx : EvpPkeyCtx, unwrapped : UInt8*, unwrappedlen : LibC::SizeT*, wrapped : UInt8*, wrappedlen : LibC::SizeT,
    ) : LibC::Int

    fun EVP_DigestSignInit_ex(
      ctx : EvpMdCtx,
      pctx : EvpPkeyCtx*,
      mdname : LibC::Char*,
      libctx : OsslLibCtx,
      props : LibC::Char*,
      pkey : EvpPkey,
      params : OsslParam,
    ) : LibC::Int

    fun EVP_DigestSign(
      ctx : EvpMdCtx, sigret : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int

    fun EVP_DigestVerifyInit_ex(
      ctx : EvpMdCtx,
      pctx : EvpPkeyCtx*,
      mdname : LibC::Char*,
      libctx : OsslLibCtx,
      props : LibC::Char*,
      pkey : EvpPkey,
      params : OsslParam,
    ) : LibC::Int

    fun EVP_DigestVerify(
      ctx : EvpMdCtx, sigret : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int
  end

  # Internal helper routines for OpenSSL 3.5+ `EVP_PKEY` lifecycle management,
  # parameter extraction, and raw key validation.
  module EvpKeyHelper
    # Generates a fresh OpenSSL keypair for *algorithm*, yields `(pub, priv)`,
    # and deterministically wipes `priv` and frees the `EVP_PKEY` handle.
    def self.generate_raw_keypair(
      algorithm : String,
      pub_size : Int32,
      sec_size : Int32,
      & : (Bytes, Bytes) -> T
    ) : T forall T
      Sodium.init
      pkey = generate_pkey(algorithm)
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

    # Generates a fresh OpenSSL `EVP_PKEY` handle for *algorithm*.
    def self.generate_pkey(algorithm : String) : LibCryptoPQC::EvpPkey
      ctx = LibCryptoPQC.EVP_PKEY_CTX_new_from_name(nil, algorithm, nil)
      raise InvalidKeyError.new("Failed to create EVP_PKEY_CTX for #{algorithm}") if ctx.null?

      begin
        if LibCryptoPQC.EVP_PKEY_keygen_init(ctx) <= 0
          raise InvalidKeyError.new("EVP_PKEY_keygen_init failed for #{algorithm}")
        end

        pkey = Pointer(Void).null
        if LibCryptoPQC.EVP_PKEY_keygen(ctx, pointerof(pkey)) <= 0 || pkey.null?
          raise InvalidKeyError.new("EVP_PKEY_keygen failed for #{algorithm}")
        end
        pkey
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
        raise InvalidKeyError.new(
          "Invalid #{algorithm} public key size: expected #{expected_pub_size}, got #{public_key.size}"
        )
      end
      if secret_key.size != expected_sec_size
        raise InvalidKeyError.new(
          "Invalid #{algorithm} secret key size: expected #{expected_sec_size}, got #{secret_key.size}"
        )
      end
      verify_keypair_match(algorithm, public_key, secret_key, expected_pub_size)
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
