# ----------------------------------------
# Project Declaration
# ----------------------------------------
cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(TPMSign LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-tctildr tss2-rc)

find_package(OpenSSL REQUIRED)

# ----------------------------------------
# Executables
# ----------------------------------------
add_executable(tpm-sign)


# ----------------------------------------
# In-Depth target information
# ----------------------------------------
add_subdirectory(include)

target_sources(tpm-sign
  PRIVATE
    src/main.cc
)
target_include_directories(tpm-sign
  PRIVATE
    ${TSS2_INCLUDE_DIRS}
)

target_link_libraries(tpm-sign
  PRIVATE
    TpmSignLib
    ${TSS2_LIBRARIES}
    OpenSSL::Crypto
)

target_compile_options(tpm-sign
  PRIVATE
    ${TSS2_CFLAGS_OTHER}
)
