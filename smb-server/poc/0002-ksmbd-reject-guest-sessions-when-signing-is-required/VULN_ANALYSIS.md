# Vulnerability Analysis

## Result

The issue is present in the checked source tree.

Current tree location:

- `fs/smb/server/smb2pdu.c`
- relevant NTLM path around lines 1581-1643
- relevant Kerberos path around lines 1714-1742
- request/response signing around `server.c` lines 141-147 and 238-241
- SMB2/SMB3 signing helpers around `smb2pdu.c` lines 9200-9375

## NTLM trigger path

`ntlm_authenticate()` resolves the account before validating the NTLMSSP
authenticate blob:

```c
user = session_user(conn, req);
...
if (conn->binding == false && user_guest(sess->user)) {
	rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST_LE;
} else {
	rc = ksmbd_decode_ntlmssp_auth_blob(authblob, sz, conn, sess);
	...
}
```

For a guest-mapped account, the branch sets `SMB2_SESSION_FLAG_IS_GUEST_LE` and
does not call `ksmbd_decode_ntlmssp_auth_blob()`. That skips the NTLMv2
cryptographic verification done by `ksmbd_auth_ntlmv2()`.

The later signing decision excludes guest sessions:

```c
if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&
     (conn->sign || server_conf.enforced_signing)) ||
    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
	sess->sign = true;
```

With `rsp->SessionFlags == SMB2_SESSION_FLAG_IS_GUEST_LE`, mandatory server
signing from `conn->sign` or `server_conf.enforced_signing` is not applied.
Only a client that explicitly sets `SMB2_NEGOTIATE_SIGNING_REQUIRED` in
SESSION_SETUP would force `sess->sign`.

`smb2_sess_setup()` then marks the session valid after the authenticate helper
returns success:

```c
sess->state = SMB2_SESSION_VALID;
```

## Kerberos path

`krb5_authenticate()` contains the same signing predicate:

```c
if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&
    (conn->sign || server_conf.enforced_signing)) ||
    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
	sess->sign = true;
```

If the lower Kerberos authentication path maps to guest/null and returns a
guest session flag, the same server-enforced signing exclusion applies.

## Request and response signing behavior

Inbound verification is conditional on the request already carrying
`SMB2_FLAGS_SIGNED`:

```c
if ((rcv_hdr2->Flags & SMB2_FLAGS_SIGNED) &&
    command != SMB2_NEGOTIATE_HE &&
    command != SMB2_SESSION_SETUP_HE &&
    command != SMB2_OPLOCK_BREAK_HE)
	return true;
```

`server.c` only calls `check_sign_req()` when this predicate is true.
Unsigned follow-up requests in a guest session are therefore not rejected by the
generic signing gate.

Outbound signing is applied when `work->sess->sign` is true, for SMB 3.1.1 final
session setup responses, or when the request itself was signed:

```c
if (work->sess &&
    (work->sess->sign || smb3_11_final_sess_setup_resp(work) ||
     conn->ops->is_sign_req(work, command)))
	conn->ops->set_sign_rsp(work);
```

Because the vulnerable guest path leaves `sess->sign == false`, SMB 2.x/3.0
guest responses can remain unsigned even when the server configuration requires
signing.

## Expected fixed behavior

When server signing is required and authentication maps to guest/null, the
server should reject the session setup, for example with
`STATUS_LOGON_FAILURE`, instead of establishing an unsigned guest session.
