#include "ui.h"
#include <cstring>
#include <print>
#include <string>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

const int kTotalSteps = 8;

/**
 * Command-line arguments for the CLI
 */
struct Args {
  bool autoMode = false; ///< Flag indicating if auto mode is active
  std::string message;   ///< Message to be processed
};

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
 * Pauses the TUI until user inputs a character. If
 * `autoMode` is true, this function does nothing.
 *
 * @param autoMode Flag indicating if the program is in automatic mode.
 */
static void PauseIfNeeded(bool autoMode);

/**
 * Parses command line arguments and populates the Args structure.
 *
 * @param argc The number of command line arguments.
 * @param argv The command line arguments.
 * @param a The Args structure to populate.
 * @return True if arguments are parsed successfully, false otherwise.
 */
static bool ParseArgs(int argc, char *argv[], Args &a);

/**
 * Connects to the TPM using TCTI and ESYS contexts.
 *
 * @param args The command line arguments.
 * @param tctiConf The TCTI configuration string.
 * @param tcti The TctiCtx structure to initialize.
 * @param esys The EsysCtx structure to initialize.
 * @return True if connection is successful, false otherwise.
 */
static bool ConnectTPM(Args &args, std::string tctiConf, TctiCtx &tcti,
                       EsysCtx &esys);

/**
 * Checks the TPM2 return code and reports if an error occurred.
 *
 * @param rc The return code to check.
 * @param what Contextual information about where the error occurred.
 * @return True if the return code indicates success, false otherwise.
 */
static bool CheckRC(TSS2_RC rc, const char *what);

int main(int argc, char *argv[]) {
  Args args;
  if (!ParseArgs(argc, argv, args))
    return 1;

  const char *envTcti = std::getenv("TPM_TCTI");
  std::string tctiConf = envTcti ? envTcti : "device:/dev/tpmrm0";
  kv("TPM_TCTI", tctiConf);
  PauseIfNeeded(args.autoMode);

  TctiCtx tcti;
  EsysCtx esys;
  if (!ConnectTPM(args, tctiConf, tcti, esys))
    return 1;
  PauseIfNeeded(args.autoMode);

  return 0;
}

static bool ConnectTPM(Args &args, std::string tctiConf, TctiCtx &tcti,
                       EsysCtx &esys) {
  header(2, kTotalSteps, "Connect to TPM (TCTI + ESAPI)");
  if (!CheckRC(Tss2_TctiLdr_Initialize(tctiConf.c_str(), &tcti.ctx),
               "Init Ttcti"))
    return false;
  ok("Tcti Context Initialized");

  if (!CheckRC(Esys_Initialize(&esys.ctx, tcti.ctx, nullptr), "Init Esys"))
    return false;
  ok("Esys Context Initialized");
  return true;
}

static bool ParseArgs(int argc, char *argv[], Args &a) {
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--auto") == 0) {
      a.autoMode = true;
    } else if (a.message.empty()) {
      a.message = argv[i];
    }
  }

  if (a.message.empty()) {
    std::println(stderr, "Usage: {} [--auto] <message>", argv[0]);
    return false;
  }

  header(1, kTotalSteps, "Input & Configuration");
  kv("Auto Mode:", a.autoMode ? "Active" : "Inactive");
  kv("Message: ", "\"" + a.message + "\"");

  return true;
}

static void PauseIfNeeded(bool autoMode) {
  if (autoMode)
    return;

  std::print(stdout, "\n{}{}Press enter to continue...{}", BOLD, CYAN, RESET);
  std::string line;
  std::getline(std::cin, line);
}

static bool CheckRC(TSS2_RC rc, const char *what) {
  if (rc != TSS2_RC_SUCCESS) {
    const char *decoded = Tss2_RC_Decode(rc);
    fail(std::string(what) + (decoded ? decoded : "unknown"));
    return false;
  }
  return true;
}
