#ifndef TPM_H_
#define TPM_H_
#include "tss2_tpm2_types.h"
#include "ui.h"
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

/**
 * The TCTI or "Transmission Interface" is the communication mechanism with the
 * TPM.
 *
 * This structure manages the TCTI context and ensures it is properly
 * finalized upon destruction.
 *
 * https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/tcti.md
 */
struct TctiCtx {
  TSS2_TCTI_CONTEXT *ctx = nullptr; ///< Pointer to the TCTI context
  ~TctiCtx() {
    if (ctx) {
      Tss2_TctiLdr_Finalize(&ctx);
      ok("TCTI Deinitialized");
    }
  }
};

/**
 * ESYS Context
 *
 * This structure manages the ESYS context and ensures it is properly
 * finalized upon destruction.
 *
 * https://tpm2-tss.readthedocs.io/en/latest/group___e_s_y_s___c_o_n_t_e_x_t.html
 */
struct EsysCtx {
  ESYS_CONTEXT *ctx = nullptr; ///< Pointer to the ESYS context
  ~EsysCtx() {
    if (ctx) {
      Esys_Finalize(&ctx);
      ok("ESYS Deinitialized");
    }
  }
};

/**
 * Checks the TPM2 return code and reports if an error occurred.
 *
 * @param rc The return code to check.
 * @param what Contextual information about where the error occurred.
 * @return True if the return code indicates success, false otherwise.
 */
static bool CheckRC(TSS2_RC rc, const char *what) {
  if (rc != TSS2_RC_SUCCESS) {
    const char *decoded = Tss2_RC_Decode(rc);
    fail(std::string(what) + (decoded ? decoded : "unknown"));
    return false;
  }
  return true;
}

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

/**
 * Connects to the TPM using TCTI and ESYS contexts.
 *
 * @param args The command line arguments.
 * @param tctiConf The TCTI configuration string.
 * @param tcti The TctiCtx structure to initialize.
 * @param esys The EsysCtx structure to initialize.
 * @return True if connection is successful, false otherwise.
 */
bool ConnectTPM(Args &args, std::string tctiConf, TctiCtx &tcti, EsysCtx &esys);

/**
 * Connects to the TPM and performs a startup operation.
 *
 * @param args The command line arguments.
 * @param esys The EsysCtx structure to initialize.
 * @return True if TPM startup is successful, false otherwise.
 */
bool TPMStartup(Args &args, EsysCtx &esys);

/**
 * Creates a primary key in the TPM under the Owner Hierarchy.
 *
 * @param args The command line arguments.
 * @param esys The EsysCtx structure to use for the operation.
 * @param primaryHandle The handle of the created primary key.
 * @return True if key creation is successful, false otherwise.
 */
bool TPMCreatePrimary(Args &args, EsysCtx &esys, ESYS_TR &primaryHandle);

#endif // TPM_H_
