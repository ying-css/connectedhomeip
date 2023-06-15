/*
*
* Copyright (c) 2023 Project CHIP Authors
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/**
* @file
* HSM based implementation of CHIP crypto primitives
* Based on configurations in CHIPCryptoPALHsm_config.h file,
* chip crypto apis use either HSM or rollback to software implementation.
*/

#include "CHIPCryptoPALHsm_trustm_utils.h"
#include <lib/core/CHIPEncoding.h>
#include "optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga_lib_types.h"
#include "optiga_lib_common.h"

#define NIST256_HEADER_OFFSET 26

/* Used for CSR generation */
// Organisation info.
#define SUBJECT_STR "CSR"
#define ASN1_BIT_STRING 0x03
#define ASN1_NULL 0x05
#define ASN1_OID 0x06
#define ASN1_SEQUENCE 0x10
#define ASN1_SET 0x11
#define ASN1_UTF8_STRING 0x0C
#define ASN1_CONSTRUCTED 0x20
#define ASN1_CONTEXT_SPECIFIC 0x80

const uint8_t kTlvHeader = 2;

#if ENABLE_HSM_GENERATE_EC_KEY
namespace chip {
namespace Crypto {

// ToDo: Add later
P256KeypairHSM::~P256KeypairHSM(){
    if (keyid != 0)
    {
        if (!provisioned_key)
        {
            //ToDo: Add the method for key delete
            // trustm_delete_key(keyid);
        }
        else
        {
            ChipLogDetail(Crypto, "Provisioned key! Not deleting key in HSM");
        }
    }

}
CHIP_ERROR P256KeypairHSM::Initialize()
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;
    uint8_t pubkey[128]    = {
        0,
    };
    uint16_t  pubKeyLen   = sizeof(pubkey);

    if (keyid == 0)
    {
        ChipLogDetail(Crypto, "Keyid not set !. Set key id using 'SetKeyId' member class !");
        return CHIP_ERROR_INTERNAL;
    }

    // Trust M init
    trustm_Open();
    if (provisioned_key == false)
    {
        // Trust M ECC 256 Key Gen
        ChipLogDetail(Crypto, "Generating NIST256 key in Trust M !");
        return_status = trustm_ecc_keygen(0xE0F2, 0x31, OPTIGA_ECC_CURVE_NIST_P_256, pubkey,(uint16_t)pubKeyLen); 
        VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL);
    }
    else
    {
        //Read out the public Key stored
        ChipLogDetail(Crypto, "Provisioned_key - %lx !", keyid);
        trustmGetKey(0xF1D8,pubkey,&pubKeyLen); 

        //VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL);
        {
            /* Set the public key */
            P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());
            VerifyOrReturnError((size_t)pubKeyLen > NIST256_HEADER_OFFSET, CHIP_ERROR_INTERNAL);
            VerifyOrReturnError(((size_t)pubKeyLen - NIST256_HEADER_OFFSET) <= kP256_PublicKey_Length, CHIP_ERROR_INTERNAL);
            memcpy((void *) Uint8::to_const_uchar(public_key), pubkey, pubKeyLen);
            public_key.SetPublicKeyId(keyid);
        }
    } 
    error = CHIP_NO_ERROR;
    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}
CHIP_ERROR P256KeypairHSM::ECDSA_sign_msg(const uint8_t * msg, size_t msg_length, P256ECDSASignature & out_signature) const
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;

    uint8_t signature_trustm[kMax_ECDSA_Signature_Length_Der] = {0};
    uint16_t signature_trustm_len = (uint16_t) kMax_ECDSA_Signature_Length_Der;
    uint8_t digest[32];
    uint8_t digest_length =sizeof(digest);
    memset(&digest[0], 0, sizeof(digest));
    MutableByteSpan out_raw_sig_span(out_signature.Bytes(), out_signature.Capacity());
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;

    VerifyOrReturnError(msg != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(msg_length > 0, CHIP_ERROR_INVALID_ARGUMENT);
    //VerifyOrReturnError(out_signature != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    // Trust M Init
    trustm_Open();
    //Hash to get the digest
    Hash_SHA256(msg, msg_length, &digest[0]);
    // Api call to calculate the signature
    return_status = trustm_ecdsa_sign(OPTIGA_KEY_ID_E0F3, digest, digest_length, 
                        signature_trustm, &signature_trustm_len);
    
    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL) ;
    
    error = EcdsaAsn1SignatureToRaw(kP256_FE_Length, ByteSpan{ signature_trustm, signature_trustm_len }, out_raw_sig_span);

    ChipLogError(NotSpecified, "EcdsaAsn1SignatureToRaw %" CHIP_ERROR_FORMAT, error.Format());

    SuccessOrExit(error);

    SuccessOrExit(out_signature.SetLength(2 * kP256_FE_Length));
    
    error = CHIP_NO_ERROR;

    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}

CHIP_ERROR P256KeypairHSM::ECDH_derive_secret(const P256PublicKey & remote_public_key, P256ECDHDerivedSecret & out_secret) const
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;
    size_t secret_length = (out_secret.Length() == 0) ? out_secret.Capacity() : out_secret.Length();

    //VerifyOrReturnError(keyid != kKeyId_NotInitialized, CHIP_ERROR_HSM);
    ChipLogDetail(Crypto, "ECDH_derive_secret: Using TrustM for ECDH !");
    trustm_Open();

    const uint8_t * const pubKey = Uint8::to_const_uchar(remote_public_key);
    const size_t pubKeyLen       = remote_public_key.Length();
    return_status = trustm_ecdh_derive_secret(OPTIGA_KEY_ID_E0F3, (uint8_t *)pubKey, (uint16_t)pubKeyLen, 
                        out_secret.Bytes(), (uint8_t)secret_length);
 
    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL) ;

    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return out_secret.SetLength(secret_length);
}

CHIP_ERROR P256PublicKeyHSM::ECDSA_validate_hash_signature(const uint8_t * hash, size_t hash_length,
                                                           const P256ECDSASignature & signature) const
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;
    uint8_t signature_trustm[kMax_ECDSA_Signature_Length_Der] = {0};
    size_t signature_trustm_len = sizeof(signature_trustm);
    MutableByteSpan out_der_sig_span(signature_trustm, signature_trustm_len);

    VerifyOrReturnError(hash != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(hash_length > 0, CHIP_ERROR_INVALID_ARGUMENT);
    ChipLogDetail(Crypto, "ECDSA_validate_hash_signature: Using TrustM for TrustM verify (hash) !");

    // Trust M init
    trustm_Open();
    error = EcdsaRawSignatureToAsn1(kP256_FE_Length, ByteSpan{ Uint8::to_const_uchar(signature.ConstBytes()), signature.Length() },
                                    out_der_sig_span);
    SuccessOrExit(error);

    /* Set the public key */
    // P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());
    signature_trustm_len = out_der_sig_span.size();
    // ECC verify
    return_status = trustm_ecdsa_verify((uint8_t *)hash, (uint8_t)hash_length, (uint8_t *) signature_trustm,
                        (uint16_t)signature_trustm_len, (uint8_t *) bytes, (uint8_t)kP256_PublicKey_Length);

    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL);
                         
    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}
static void add_tlv(uint8_t * buf, size_t buf_index, uint8_t tag, size_t len, uint8_t * val)
{
    buf[buf_index++] = (uint8_t) tag;
    buf[buf_index++] = (uint8_t) len;
    if (len > 0 && val != NULL)
    {
        memcpy(&buf[buf_index], val, len);
        buf_index = buf_index + len;
    }
}
CHIP_ERROR P256KeypairHSM::NewCertificateSigningRequest(uint8_t * csr, size_t & csr_length) const
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;

    uint8_t data_to_hash[128] = { 0 };
    size_t data_to_hash_len   = sizeof(data_to_hash);
    uint8_t pubkey[128]       = { 0 };
    size_t pubKeyLen          = 0;
    uint8_t digest[32]          = { 0 };
    size_t digest_length        = sizeof(digest);
    uint8_t signature_trustm[128]    = { 0 };
    size_t signature_len      = sizeof(signature_trustm);

    size_t csr_index    = 0;
    size_t buffer_index = data_to_hash_len;

    // Dummy value
    uint8_t organisation_oid[3] = { 0x55, 0x02, 0x03 };

    // Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    uint8_t version[3]       = { 0x02, 0x01, 0x00 };
    uint8_t signature_oid[8] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    uint8_t nist256_header[] = {0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00};

    ChipLogDetail(Crypto, "NewCertificateSigningRequest: Using Trust M for CSR Creating!");

    // No extensions are copied
    buffer_index -= kTlvHeader;
    add_tlv(data_to_hash, buffer_index, (ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC), 0, NULL);

    // Copy public key (with header)
    {
        P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());

        VerifyOrExit((sizeof(nist256_header) + public_key.Length()) <= sizeof(pubkey), error = CHIP_ERROR_INTERNAL);

        memcpy(pubkey, nist256_header, sizeof(nist256_header));
        pubKeyLen = pubKeyLen + sizeof(nist256_header);

        memcpy((pubkey + pubKeyLen), Uint8::to_uchar(public_key), public_key.Length());
        pubKeyLen = pubKeyLen + public_key.Length();
    }

    buffer_index -= pubKeyLen;
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    memcpy((void *) &data_to_hash[buffer_index], pubkey, pubKeyLen);

    // Copy subject (in the current implementation only organisation name info is added) and organisation OID
    buffer_index -= (kTlvHeader + sizeof(SUBJECT_STR) - 1);
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, ASN1_UTF8_STRING, sizeof(SUBJECT_STR) - 1, (uint8_t *) SUBJECT_STR);

    buffer_index -= (kTlvHeader + sizeof(organisation_oid));
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, ASN1_OID, sizeof(organisation_oid), organisation_oid);

    // Add length
    buffer_index -= kTlvHeader;
    // Subject TLV ==> 1 + 1 + len(subject)
    // Org OID TLV ==> 1 + 1 + len(organisation_oid)
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, (ASN1_CONSTRUCTED | ASN1_SEQUENCE),
            ((2 * kTlvHeader) + (sizeof(SUBJECT_STR) - 1) + sizeof(organisation_oid)), NULL);

    buffer_index -= kTlvHeader;
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, (ASN1_CONSTRUCTED | ASN1_SET),
            ((3 * kTlvHeader) + (sizeof(SUBJECT_STR) - 1) + sizeof(organisation_oid)), NULL);

    buffer_index -= kTlvHeader;
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, (ASN1_CONSTRUCTED | ASN1_SEQUENCE),
            ((4 * kTlvHeader) + (sizeof(SUBJECT_STR) - 1) + sizeof(organisation_oid)), NULL);

    buffer_index -= 3;
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    memcpy((void *) &data_to_hash[buffer_index], version, sizeof(version));

    buffer_index -= kTlvHeader;
    VerifyOrExit(buffer_index > 0, error = CHIP_ERROR_INTERNAL);
    add_tlv(data_to_hash, buffer_index, (ASN1_CONSTRUCTED | ASN1_SEQUENCE), (data_to_hash_len - buffer_index - kTlvHeader), NULL);

    // TLV data is created by copying from backwards. move it to start of buffer.
    data_to_hash_len = (data_to_hash_len - buffer_index);
    memmove(data_to_hash, (data_to_hash + buffer_index), data_to_hash_len);

    /* Create hash of `data_to_hash` buffer */
    // Trust M Init
    trustm_Open();
    //Hash to get the digest
    memset(&digest[0], 0, sizeof(digest));
    Hash_SHA256(data_to_hash, data_to_hash_len, &digest[0]);

    // Sign on hash
    return_status = trustm_ecdsa_sign(OPTIGA_KEY_ID_E0F3, digest, (uint8_t)digest_length, 
                        signature_trustm, (uint16_t*)(&signature_len));

    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL) ;
    VerifyOrExit((csr_index + 3) <= csr_length, error = CHIP_ERROR_INTERNAL);
    csr[csr_index++] = (ASN1_CONSTRUCTED | ASN1_SEQUENCE);
    if ((data_to_hash_len + 14 + kTlvHeader + signature_len) >= 0x80)
    {
        csr[csr_index++] = 0x81;
    }
    csr[csr_index++] = (uint8_t)(data_to_hash_len + 14 + kTlvHeader + signature_len);

    VerifyOrExit((csr_index + data_to_hash_len) <= csr_length, error = CHIP_ERROR_INTERNAL);
    memcpy((csr + csr_index), data_to_hash, data_to_hash_len);
    csr_index = csr_index + data_to_hash_len;

    // ECDSA SHA256 Signature OID TLV ==> 1 + 1 + len(signature_oid) (8)
    // ASN_NULL ==> 1 + 1
    VerifyOrExit((csr_index + kTlvHeader) <= csr_length, error = CHIP_ERROR_INTERNAL);
    add_tlv(csr, csr_index, (ASN1_CONSTRUCTED | ASN1_SEQUENCE), 0x0C, NULL);
    csr_index = csr_index + kTlvHeader;

    VerifyOrExit((csr_index + sizeof(signature_oid) + kTlvHeader) <= csr_length, error = CHIP_ERROR_INTERNAL);
    add_tlv(csr, csr_index, ASN1_OID, sizeof(signature_oid), signature_oid);
    csr_index = csr_index + kTlvHeader + sizeof(signature_oid);

    VerifyOrExit((csr_index + kTlvHeader) <= csr_length, error = CHIP_ERROR_INTERNAL);
    add_tlv(csr, csr_index, ASN1_NULL, 0x00, NULL);
    csr_index = csr_index + kTlvHeader;

    VerifyOrExit((csr_index + kTlvHeader) <= csr_length, error = CHIP_ERROR_INTERNAL);
    csr[csr_index++] = ASN1_BIT_STRING;
    csr[csr_index++] = (uint8_t)((signature_trustm[0] != 0) ? (signature_len + 1) : (signature_len));

    if (signature_trustm[0] != 0)
    {
        VerifyOrExit(csr_index <= csr_length, error = CHIP_ERROR_INTERNAL);
        csr[csr_index++] = 0x00;
        // Increament total count by 1
        csr[2]++;
    }
    VerifyOrExit((csr_index + signature_len) <= csr_length, error = CHIP_ERROR_INTERNAL);
    memcpy(&csr[csr_index], signature_trustm, signature_len);

    csr_length = (csr_index + signature_len);

    error = CHIP_NO_ERROR;
    
    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}
CHIP_ERROR P256KeypairHSM::Serialize(P256SerializedKeypair & output) const
{
    const size_t len = output.Length() == 0 ? output.Capacity() : output.Length();
    Encoding::BufferWriter bbuf(output.Bytes(), len);
    uint8_t privkey[kP256_PrivateKey_Length] = {
        0,
    };

    {
        /* Set the public key */
        P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());
        bbuf.Put(Uint8::to_uchar(public_key), public_key.Length());
    }

    VerifyOrReturnError(bbuf.Available() == sizeof(privkey), CHIP_ERROR_INTERNAL);
    VerifyOrReturnError(sizeof(privkey) >= 4, CHIP_ERROR_INTERNAL);

    {
        /* When HSM is used for ECC key generation, store key info in private key buffer */
        Encoding::LittleEndian::BufferWriter privkey_bbuf(privkey, sizeof(privkey));
        privkey_bbuf.Put32(keyid);
    }

    bbuf.Put(privkey, sizeof(privkey));
    VerifyOrReturnError(bbuf.Fit(), CHIP_ERROR_BUFFER_TOO_SMALL);

    output.SetLength(bbuf.Needed());

    return CHIP_NO_ERROR;
}

CHIP_ERROR P256KeypairHSM::Deserialize(P256SerializedKeypair & input)
{
    /* Set the public key */
    P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());
    Encoding::BufferWriter bbuf((uint8_t *) Uint8::to_const_uchar(public_key), public_key.Length());

    VerifyOrReturnError(input.Length() == public_key.Length() + kP256_PrivateKey_Length, CHIP_ERROR_INVALID_ARGUMENT);
    bbuf.Put(input.ConstBytes(), public_key.Length());

    /* Set private key info */
    VerifyOrReturnError(bbuf.Fit(), CHIP_ERROR_NO_MEMORY);
    {
        /* When HSM is used for ECC key generation, key info in stored in private key buffer */
        const uint8_t * privkey = input.ConstBytes() + public_key.Length();
        keyid                   = Encoding::LittleEndian::Get32(privkey);
        public_key.SetPublicKeyId(keyid);
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR P256PublicKeyHSM::ECDSA_validate_msg_signature(const uint8_t * msg, size_t msg_length,
                                                          const P256ECDSASignature & signature) const
{
    CHIP_ERROR error = CHIP_ERROR_INTERNAL;
    uint8_t signature_trustm[kMax_ECDSA_Signature_Length_Der] = {0};
    size_t signature_trustm_len = sizeof(signature_trustm);
    uint8_t digest[32];
    uint8_t digest_length =sizeof(digest);
    MutableByteSpan out_der_sig_span(signature_trustm, signature_trustm_len);
    optiga_lib_status_t return_status = OPTIGA_LIB_BUSY;

    VerifyOrReturnError(msg != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(msg_length > 0, CHIP_ERROR_INVALID_ARGUMENT);

    ChipLogDetail(Crypto, "ECDSA_validate_msg_signature: Using TrustM for TrustM verify (msg) !");

    // Trust M init
    trustm_Open();

    error = EcdsaRawSignatureToAsn1(kP256_FE_Length, ByteSpan{ Uint8::to_const_uchar(signature.ConstBytes()), signature.Length() },
                                    out_der_sig_span);
    SuccessOrExit(error);

    /* Set the public key */
    // P256PublicKeyHSM & public_key = const_cast<P256PublicKeyHSM &>(Pubkey());
    signature_trustm_len = out_der_sig_span.size();
    //Hash to get the digest
    memset(&digest[0], 0, sizeof(digest));
    Hash_SHA256(msg, msg_length, &digest[0]);
    // ECC verify
    return_status = trustm_ecdsa_verify(digest, digest_length, (uint8_t *) signature_trustm,
                        (uint16_t)signature_trustm_len, (uint8_t *) bytes, (uint8_t)kP256_PublicKey_Length);

    VerifyOrExit(return_status == OPTIGA_LIB_SUCCESS, error = CHIP_ERROR_INTERNAL);
                         
    exit:
        if (error != CHIP_NO_ERROR)
        {
            trustm_close();
        }
        return error;
}

} // namespace Crypto
} // namespace chip

#endif //#if ENABLE_HSM_GENERATE_EC_KEY
