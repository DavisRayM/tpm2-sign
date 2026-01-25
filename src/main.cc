#include "tpm.h"
#include "ui.h"
#include <cstring>
#include <print>
#include <string>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

const int kTotalSteps = 8;

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

int main(int argc, char *argv[]) {
  Args args;
  if (!ParseArgs(argc, argv, args))
    return 1;

  const char *envTcti = std::getenv("TPM_TCTI");
  std::string tctiConf = envTcti ? envTcti : "device:/dev/tpmrm0";
  kv("TPM_TCTI", tctiConf);
  PauseIfNeeded(args.autoMode);

  header(2, kTotalSteps, "Connect to TPM (TCTI + ESAPI)");
  TctiCtx tcti;
  EsysCtx esys;
  if (!ConnectTPM(args, tctiConf, tcti, esys))
    return 1;
  PauseIfNeeded(args.autoMode);

  header(3, kTotalSteps, "TPM2_Startup (optiona)");
  bool _ = TPMStartup(args, esys);
  PauseIfNeeded(args.autoMode);

  header(4, kTotalSteps, "Start HMAC Auth Session");
  ESYS_TR sessionHandle;
  if (!TPMStartAuth(args, esys, sessionHandle))
    return 1;
  PauseIfNeeded(args.autoMode);

  header(5, kTotalSteps, "CreatePrimary authorized by HMAC session");
  ESYS_TR primaryHandle;
  if (!TPMCreatePrimary(args, esys, primaryHandle, sessionHandle))
    return 1;
  PauseIfNeeded(args.autoMode);

  header(6, kTotalSteps, "Cleanup (FlushContext)");
  if (!CheckRC(Esys_FlushContext(esys.ctx, primaryHandle),
               "Flust Context (Primary)"))
    return 1;

  if (!CheckRC(Esys_FlushContext(esys.ctx, sessionHandle),
               "Flust Context (Primary)"))
    return 1;
  ok("Flused Primary Handle");

  PauseIfNeeded(args.autoMode);

  return 0;
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
