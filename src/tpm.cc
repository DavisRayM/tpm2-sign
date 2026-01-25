#include "tpm.h"
#include "tss2_tpm2_types.h"
#include "ui.h"
#include <cstring>

bool TPMStartAuth(Args &args, EsysCtx &esys, ESYS_TR &sessionHandle) {
  TPM2B_AUTH ownerAuth{};
  ownerAuth.size = 0;
  if (!CheckRC(Esys_TR_SetAuth(esys.ctx, ESYS_TR_RH_OWNER, &ownerAuth),
               "SetAuth"))
    return false;
  ok("Owner Hierarchy Auth Set (empty)");

  TPM2B_NONCE nonceCaller{};
  {
    TPM2B_DIGEST *rnd = nullptr;
    if (!CheckRC(Esys_GetRandom(esys.ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, 17, &rnd),
                 "GetRandom"))
      return false;

    nonceCaller.size = rnd->size;
    std::memcpy(nonceCaller.buffer, rnd->buffer, rnd->size);
    Esys_Free(rnd);

    ok("Generated nonceCaller (16 bytes) using TPM RNG");
  }

  TPMT_SYM_DEF symmetric{};
  symmetric.algorithm = TPM2_ALG_NULL;

  sessionHandle = ESYS_TR_NONE;
  if (!CheckRC(Esys_StartAuthSession(esys.ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &nonceCaller, TPM2_SE_HMAC, &symmetric,
                                     TPM2_ALG_SHA256, &sessionHandle),
               "StartAuthSession"))
    return false;

  ok("HMAC Session Started");

  TPMA_SESSION sessAttrs = TPMA_SESSION_CONTINUESESSION;
  TPMA_SESSION sessAttrsMask = TPMA_SESSION_CONTINUESESSION;

  if (!CheckRC(Esys_TRSess_SetAttributes(esys.ctx, sessionHandle, sessAttrs,
                                         sessAttrsMask),
               "Session Set Attributes"))
    return false;

  {
    std::ostringstream h;
    h << "0x" << std::hex << sessionHandle << std::dec;
    kv("Session Handle: ", h.str());
  }
  kv("Auth Hash: ", "SHA256");
  kv("Symmetric", "NULL (no param encryption yet)");
  kv("Attrs", "continueSession");

  return true;
}

bool TPMCreatePrimary(Args &args, EsysCtx &esys, ESYS_TR &primaryHandle,
                      ESYS_TR sessionHandle) {
  TPM2B_SENSITIVE_CREATE inSensitive{};
  inSensitive.size = 0;
  inSensitive.sensitive.userAuth.size = 0;
  inSensitive.sensitive.data.size = 0;

  TPM2B_PUBLIC inPublic = MakeRSAStoragePrimaryTemplate();

  TPM2B_DATA outsideInfo{};
  outsideInfo.size = 0;

  TPML_PCR_SELECTION creationPCR{};
  creationPCR.count = 0;

  primaryHandle = ESYS_TR_NONE;
  TPM2B_PUBLIC *outPublic = nullptr;
  TPM2B_CREATION_DATA *creationData = nullptr;
  TPM2B_DIGEST *creationHash = nullptr;
  TPMT_TK_CREATION *creationTicket = nullptr;

  if (!CheckRC(Esys_CreatePrimary(esys.ctx, ESYS_TR_RH_OWNER, sessionHandle,
                                  ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive,
                                  &inPublic, &outsideInfo, &creationPCR,
                                  &primaryHandle, &outPublic, &creationData,
                                  &creationHash, &creationTicket),
               "CreatePrimary"))
    return false;

  ok("TPM2_CC_CreatePrimary Sucess");
  {
    std::ostringstream h;
    h << "0x" << std::hex << primaryHandle << std::dec;
    kv("Primary Handle: ", h.str());
  }
  if (outPublic) {
    kv("type", TPMAlgToString(outPublic->publicArea.type));
    kv("nameAlg", TPMAlgToString(outPublic->publicArea.nameAlg));
    kv("attributes",
       TPMAObjectToString(outPublic->publicArea.objectAttributes));

    if (outPublic->publicArea.type == TPM2_ALG_RSA) {
      kv("RSA bits",
         std::to_string(outPublic->publicArea.parameters.rsaDetail.keyBits));
      kv("RSA exponent",
         std::to_string(outPublic->publicArea.parameters.rsaDetail.exponent));
    }
  }

  Esys_Free(outPublic);
  Esys_Free(creationData);
  Esys_Free(creationHash);
  Esys_Free(creationTicket);
  return true;
}

bool TPMStartup(Args &args, EsysCtx &esys) {
  TSS2_RC s_rc = Esys_Startup(esys.ctx, TPM2_SU_CLEAR);
  if (s_rc == TSS2_RC_SUCCESS) {
    ok("TPM Startup(SU_CLEAR) Success");
    return true;
  } else {
    warn(std::string("Startup returned: ") + Tss2_RC_Decode(s_rc));
    kv("note", "Often means 'already started'. Continuing...");
    return false;
  }
}

bool ConnectTPM(Args &args, std::string tctiConf, TctiCtx &tcti,
                EsysCtx &esys) {
  if (!CheckRC(Tss2_TctiLdr_Initialize(tctiConf.c_str(), &tcti.ctx),
               "Init Ttcti"))
    return false;
  ok("Tcti Context Initialized");

  if (!CheckRC(Esys_Initialize(&esys.ctx, tcti.ctx, nullptr), "Init Esys"))
    return false;
  ok("Esys Context Initialized");
  return true;
}
