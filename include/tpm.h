#ifndef TPM_H_
#define TPM_H_
#include "tss2_tpm2_types.h"

/**
 * Makes RSA Storage Primary Template
 *
 * This function creates a template for a storage primary RSA key with specific
 * attributes and parameters suitable for secure storage operations.
 *
 * @return A TPM2B_PUBLIC structure representing the RSA storage primary
 * template.
 */
static TPM2B_PUBLIC MakeRSAStoragePrimaryTemplate() {
  // Create a template for a storage primary RSA key
  TPM2B_PUBLIC inPublic{};
  inPublic.publicArea.type = TPM2_ALG_RSA;
  inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;

  // Restricted decrypt primary (storage key)
  inPublic.publicArea.objectAttributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;

  inPublic.publicArea.authPolicy.size = 0;

  // Symmetric inner wrapper for restricted decrypt keys
  inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
  inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
  inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;

  // No signing scheme on a storage key
  inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;

  inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
  inPublic.publicArea.parameters.rsaDetail.exponent = 0;
  inPublic.publicArea.unique.rsa.size = 0;
  return inPublic;
}

#endif // TPM_H_
