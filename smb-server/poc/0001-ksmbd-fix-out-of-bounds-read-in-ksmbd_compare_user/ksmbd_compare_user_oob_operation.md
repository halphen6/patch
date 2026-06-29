# ksmbd_compare_user() OOB Read PoC Operation Guide

## Files

- `poc_ksmbd_compare_user_oob.c`: standalone AddressSanitizer reproducer.
- `ksmbd_compare_user_oob_operation.md`: this operation guide.

## Vulnerability Summary

`ksmbd_compare_user()` compares two users with:

```c
memcmp(u1->passkey, u2->passkey, u1->passkey_sz)
```

`u2->passkey` is allocated with `u2->passkey_sz`. If `u1->passkey_sz`
is greater than `u2->passkey_sz`, `memcmp()` reads past the end of
`u2->passkey`.

The reachable kernel paths include:

- NTLM re-authentication in `server/smb2pdu.c`
- Kerberos session reuse/binding in `server/auth.c`

Trigger condition:

1. The first authenticated user object has a longer `passkey`.
2. A later re-authentication or binding path creates a same-name user object
   with a shorter `passkey`.
3. `ksmbd_compare_user(sess->user, user)` compares the old and new objects.

## Build

From this directory:

```sh
gcc -O0 -g -fsanitize=address -fno-omit-frame-pointer \
    poc_ksmbd_compare_user_oob.c -o /tmp/ksmbd_compare_user_oob
```

## Run

```sh
/tmp/ksmbd_compare_user_oob
```

## Expected Result

AddressSanitizer should report a heap buffer overflow similar to:

```text
About to compare 18 bytes against a 8-byte buffer
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 18
...
ksmbd_compare_user ... poc_ksmbd_compare_user_oob.c
```

This demonstrates that the vulnerable comparison reads 18 bytes from a
buffer that was allocated with only 8 bytes.

## Suggested Fix

Add a size equality check before `memcmp()`:

```c
bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2)
{
	if (strcmp(u1->name, u2->name))
		return false;
	if (u1->passkey_sz != u2->passkey_sz)
		return false;
	if (memcmp(u1->passkey, u2->passkey, u1->passkey_sz))
		return false;

	return true;
}
```

This matches the existing guarded comparison pattern used by
`destroy_previous_session()`.
