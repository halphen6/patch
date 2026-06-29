# patch-07: ksmbd guest mandatory-signing bypass probe

This package contains a source review note, a minimal Python PoC, and an
operation manual for checking the ksmbd issue described as:

`Guest/anonymous session bypasses server-enforced SMB2 signing`.

## Files

- `poc_ksmbd_guest_signing_bypass.py`: pure Python SMB2/NTLMSSP probe.
- `VULN_ANALYSIS.md`: code-path analysis against this source tree.
- `OPERATION_MANUAL.md`: lab setup and execution notes.

## Quick run

Run only against a ksmbd test server you own or are authorized to assess:

```sh
python3 poc_ksmbd_guest_signing_bypass.py 192.0.2.10 -u guest --share public
```

The PoC reports `VULNERABLE` only when all of these are true:

- the server's SMB2 NEGOTIATE response advertises signing as required;
- the NTLMSSP_AUTH username maps to guest;
- the SESSION_SETUP succeeds;
- the successful response is not signed.
