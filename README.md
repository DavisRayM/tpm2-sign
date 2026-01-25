# TPMSign

TPMSign is a small C++ demo tool that takes a user-supplied string and produces a TPM-backed RSA signature using a TPM 2.0 device.

It uses the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) ESAPI to:

1. Connect to the TPM via TCTI  
2. (Optionally) run `TPM2_Startup`  
3. Start an HMAC authorization session  
4. Create a primary RSA storage key in the Owner hierarchy  
5. Create and load an RSA signing child key under that primary  
6. Compute SHA-256 of your message  
7. Sign the digest using the child key  
8. Print the digest and signature in hex, then flush all TPM objects

> **Note:** You need access to a working TPM 2.0 implementation (hardware or software) and appropriate permissions to use it.

## Requirements

- CMake ≥ 3.23  
- A C++23-capable compiler (e.g., `g++ 13`, `clang++ 17`)  
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) with:
  - `tss2-esys`
  - `tss2-tctildr`
  - `tss2-rc`
- OpenSSL (for SHA-256)
- A TPM 2.0 device or simulator

On many Linux distributions you can install dependencies with something like:

```bash
# Example for Debian/Ubuntu (names may differ)
sudo apt install \
  g++ cmake pkg-config \
  libtss2-esys-dev libtss2-tctildr-dev libtss2-rc-dev \
  libssl-dev
```

## Building

```bash
git clone https://github.com/DavisRay/tpm-sign.git tpm-sign
cd tpm-sign

cmake -B build
cmake --build build
```

This produces the `tpm-sign` executable in `build/`.

## TPM Connection (TCTI)

TPMSign uses the TCTI loader interface (`tss2-tctildr`) and reads the configuration from the `TPM_TCTI` environment variable. If `TPM_TCTI` is not set, it defaults to:

```text
device:/dev/tpmrm0
```

Examples:

```bash
# Hardware TPM via resource manager (default)
export TPM_TCTI="device:/dev/tpmrm0"

# Direct access (not recommended if rm is present)
export TPM_TCTI="device:/dev/tpm0"

# Example for a socket-based TPM simulator
export TPM_TCTI="mssim:port=2321"
```

## Usage

```bash
./tpm-sign [--auto] <message>
```

- `<message>` – the string to sign
- `--auto`   – optional; if present, runs non-interactively (no “press enter” prompts)

### Examples

Interactive run:

```bash
./tpm-sign "Hello TPM"
```

Non-interactive (CI / scripting):

```bash
./tpm-sign --auto "Hello from CI"
```

You should see step-by-step output:

- Connection details (`TPM_TCTI`)
- ESYS/TCTI initialization
- HMAC session handle
- Primary/child key handles and attributes
- SHA-256 digest of your message (hex)
- Signature (hex)

## What the Tool Does (Key Details)

- **Primary key**:  
  - RSA 2048-bit, storage key  
  - `TPMA_OBJECT`: `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt`  
  - Symmetric inner wrapper: AES-128 CFB  
  - No signing scheme (storage-only)

- **Child key**:  
  - RSA 2048-bit signing key  
  - `TPMA_OBJECT`: `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign`  
  - No symmetric algorithm  
  - Signing scheme: `RSASSA` with `SHA256`

- **Authorization**:  
  - Owner hierarchy auth is assumed empty  
  - An HMAC session (SHA-256, no parameter encryption yet) authorizes:
    - `CreatePrimary`
    - `Create`
    - `Load`
    - `Sign`

- **Digest**:  
  - Computed with OpenSSL `SHA256()`  
  - Printed, then passed to `Esys_Sign` with `TPM2_ALG_RSASSA` / `TPM2_ALG_SHA256`

- **Cleanup**:  
  - Flushes child key, primary key, and session from the TPM  
  - ESYS and TCTI contexts are finalized when their RAII wrappers go out of scope

## Running with a TPM Simulator (Optional)

If you don’t have hardware TPM, you can use a software simulator (for example, IBM’s software TPM or the `swtpm` package). A typical flow:

```bash
# Example – run your TPM simulator here and note the port
export TPM_TCTI="mssim:host=127.0.0.1,port=2321"

./tpm-sign --auto "Simulated TPM signing"
```

Consult your simulator’s documentation for exact setup.

## Limitations & Notes

- Owner auth is fixed to empty (`""`).
- Only one key type is implemented:
  - RSA 2048-bit primary (storage)
  - RSA 2048-bit child (RSASSA-SHA256)
- No verification logic is included; you can copy the printed public parameters and signature and verify them with OpenSSL or another tool.
- Requires a functional TPM 2.0 stack and access permissions; under Linux this often means being in a group like `tss` or running with the appropriate privileges.
