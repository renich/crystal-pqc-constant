require "openssl"

module Crystal::Pqc::Constant
  # Low-level C ABI bindings to OpenSSL 3.5+ `libcrypto` `EVP_PKEY` and
  # `EVP_MD_CTX` functions for NIST FIPS 203 (`ML-KEM`) and FIPS 204 (`ML-DSA`).
  @[Link("crypto")]
  lib LibCryptoPQC
    # OpenSSL `OSSL_PARAM_OCTET_STRING` parameter data type identifier.
    OSSL_PARAM_OCTET_STRING = 5_u32

    # C ABI layout matching OpenSSL's `struct ossl_param_st`.
    struct OsslParamData
      key : LibC::Char*
      data_type : LibC::UInt
      data : Void*
      data_size : LibC::SizeT
      return_size : LibC::SizeT
    end

    # Opaque handle to an OpenSSL `EVP_PKEY` key structure.
    alias EvpPkey = Void*

    # Opaque handle to an OpenSSL `EVP_PKEY_CTX` key operation context.
    alias EvpPkeyCtx = Void*

    # Opaque handle to an OpenSSL `EVP_MD_CTX` digest/signature context.
    alias EvpMdCtx = LibCrypto::EVP_MD_CTX

    # Opaque handle to an OpenSSL `OSSL_LIB_CTX` library context.
    alias OsslLibCtx = Void*

    # Pointer to a null-terminated `OsslParamData` (`OSSL_PARAM`) array.
    alias OsslParam = OsslParamData*

    fun EVP_PKEY_CTX_new_from_name(libctx : OsslLibCtx, name : LibC::Char*, propquery : LibC::Char*) : EvpPkeyCtx
    fun EVP_PKEY_CTX_new_from_pkey(libctx : OsslLibCtx, pkey : EvpPkey, propquery : LibC::Char*) : EvpPkeyCtx
    fun EVP_PKEY_CTX_free(ctx : EvpPkeyCtx) : Void
    fun EVP_PKEY_free(pkey : EvpPkey) : Void

    fun EVP_PKEY_keygen_init(ctx : EvpPkeyCtx) : LibC::Int
    fun EVP_PKEY_CTX_set_params(ctx : EvpPkeyCtx, params : OsslParam) : LibC::Int
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
      ctx : EvpMdCtx, pctx : EvpPkeyCtx*, mdname : LibC::Char*, libctx : OsslLibCtx,
      props : LibC::Char*, pkey : EvpPkey, params : OsslParam,
    ) : LibC::Int

    fun EVP_DigestSign(
      ctx : EvpMdCtx, sigret : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int

    fun EVP_DigestVerifyInit_ex(
      ctx : EvpMdCtx, pctx : EvpPkeyCtx*, mdname : LibC::Char*, libctx : OsslLibCtx,
      props : LibC::Char*, pkey : EvpPkey, params : OsslParam,
    ) : LibC::Int

    fun EVP_DigestVerify(
      ctx : EvpMdCtx, sigret : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int
  end
end
