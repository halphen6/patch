# PoC Directory Structure

This directory contains Proof of Concept (PoC) files for the ksmbd vulnerabilities.

## Patch Correspondence

| Directory | Patch File | Vulnerability | PoC File |
|-----------|------------|---------------|----------|
| `0001-ksmbd-fix-out-of-bounds-read-in-ksmbd_compare_user/` | `kernel/cifs/smb2ops.c` | Out-of-bounds compare_user operation | `poc_ksmbd_compare_user_oob.c` |
| `0002-ksmbd-reject-guest-sessions-when-signing-is-required/` | `kernel/cifs/smb2pdu.c` | Guest signing bypass | `poc_ksmbd_guest_signing_bypass.py` |
| `0003-smb-ksmbd-use-opener-creds-for-duplicate-extents/` | `kernel/fs/smb/server/smb2pdu.c` | Duplicate extents OOB | `ksmbd_dup_extents_poc.c` |
| `0004-ksmbd-require-read-attributes-for-more-QueryInfo-cla/` | `kernel/fs/smb/server/vfs.c` | Query info read attrs OOB | `poc_ksmbd_query_info_read_attrs.py` |

## Directory Contents

### 0001-ksmbd-fix-out-of-bounds-read-in-ksmbd_compare_user/
- `poc_ksmbd_compare_user_oob.c` - C program to trigger OOB in compare_user
- `ksmbd_compare_user_oob_operation.md` - Operation documentation

### 0002-ksmbd-reject-guest-sessions-when-signing-is-required/
- `poc_ksmbd_guest_signing_bypass.py` - Python script for guest signing bypass
- `README.md` - PoC description
- `VULN_ANALYSIS.md` - Vulnerability analysis
- `OPERATION_MANUAL.md` - Operation guide

### 0003-smb-ksmbd-use-opener-creds-for-duplicate-extents/
- `ksmbd_dup_extents_poc.c` - C program for dup_extents OOB
- `ksmbd_dup_extents_poc` - Compiled binary
- `trace_ksmbd_dup_extents.bt` - bpftrace script for tracing
- `README.md` - PoC description
- `OPERATIONS.md` - Operation guide

### 0004-ksmbd-require-read-attributes-for-more-QueryInfo-cla/
- `poc_ksmbd_query_info_read_attrs.py` - Python script for query_info OOB
- `README.md` - PoC description
- `VULN_ANALYSIS.md` - Vulnerability analysis
- `OPERATION_MANUAL.md` - Operation guide

## Building and Running

See individual directory README files for build and execution instructions.
