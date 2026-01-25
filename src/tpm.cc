#include "tpm.h"
#include "ui.h"

bool TPMCreatePrimary(Args &args, EsysCtx &esys, ESYS_TR &primaryHandle) {
  TPM2B_AUTH ownerAuth{};
  ownerAuth.size = 0;
  if (!CheckRC(Esys_TR_SetAuth(esys.ctx, ESYS_TR_RH_OWNER, &ownerAuth),
               "SetAuth"))
    return false;
  ok("Owner Hierarchy Auth Set (empty)");

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

  if (!CheckRC(Esys_CreatePrimary(esys.ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
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
