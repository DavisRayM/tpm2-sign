#ifndef UI_H
#define UI_H

#include "tss2_tpm2_types.h"
#include <iostream>
#include <sstream>
#include <string>

// ANSI colors (works on most terminals; safe-ish fallback if unsupported)
constexpr const char *RESET = "\x1b[0m";
constexpr const char *BOLD = "\x1b[1m";
constexpr const char *DIM = "\x1b[2m";
constexpr const char *RED = "\x1b[31m";
constexpr const char *GREEN = "\x1b[32m";
constexpr const char *YELLOW = "\x1b[33m";
constexpr const char *CYAN = "\x1b[36m";

inline void header(int step, int total, const std::string &title) {
  std::cout << "\n"
            << BOLD << CYAN << "==[ STEP " << step << "/" << total
            << " ]== " << title << RESET << "\n";
}

inline void ok(const std::string &msg) {
  std::cout << GREEN << "[ OK ] " << RESET << msg << "\n";
}

inline void warn(const std::string &msg) {
  std::cout << YELLOW << "[WARN] " << RESET << msg << "\n";
}

inline void fail(const std::string &msg) {
  std::cout << RED << "[FAIL] " << RESET << msg << "\n";
}

inline void kv(const std::string &k, const std::string &v) {
  std::cout << "  " << DIM << k << RESET << ": " << v << "\n";
}

inline std::string TPMAlgToString(TPM2_ALG_ID alg) {
  switch (alg) {
  case TPM2_ALG_RSA:
    return "RSA";
  case TPM2_ALG_ECC:
    return "ECC";
  case TPM2_ALG_SHA1:
    return "SHA1";
  case TPM2_ALG_SHA256:
    return "SHA256";
  case TPM2_ALG_SHA384:
    return "SHA384";
  case TPM2_ALG_SHA512:
    return "SHA512";
  case TPM2_ALG_NULL:
    return "NULL";
  case TPM2_ALG_AES:
    return "AES";
  case TPM2_ALG_CFB:
    return "CFB";
  case TPM2_ALG_RSASSA:
    return "RSASSA";
  default:
    std::ostringstream oss;
    oss << "ALG(0x" << std::hex << alg << std::dec << ")";
    return oss.str();
  }
}

inline std::string TPMAObjectToString(TPMA_OBJECT attrs) {
  struct BitName {
    TPMA_OBJECT bit;
    const char *name;
  };
  const BitName bits[] = {
      {TPMA_OBJECT_FIXEDTPM, "fixedTPM"},
      {TPMA_OBJECT_FIXEDPARENT, "fixedParent"},
      {TPMA_OBJECT_SENSITIVEDATAORIGIN, "sensitiveDataOrigin"},
      {TPMA_OBJECT_USERWITHAUTH, "userWithAuth"},
      {TPMA_OBJECT_ADMINWITHPOLICY, "adminWithPolicy"},
      {TPMA_OBJECT_NODA, "noDA"},
      {TPMA_OBJECT_ENCRYPTEDDUPLICATION, "encryptedDuplication"},
      {TPMA_OBJECT_RESTRICTED, "restricted"},
      {TPMA_OBJECT_DECRYPT, "decrypt"},
      {TPMA_OBJECT_SIGN_ENCRYPT, "sign"},
  };

  std::ostringstream oss;
  bool first = true;
  for (const auto &b : bits) {
    if (attrs & b.bit) {
      if (!first)
        oss << " | ";
      oss << b.name;
      first = false;
    }
  }
  if (first)
    return "(none)";
  return oss.str();
}

#endif // UI_H
