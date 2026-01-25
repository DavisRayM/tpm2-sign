add_library(TpmSignLib INTERFACE)

target_sources(TpmSignLib
  INTERFACE
  FILE_SET publicHeaders
  TYPE HEADERS
  FILES
    ui.h
    tpm.h
)
