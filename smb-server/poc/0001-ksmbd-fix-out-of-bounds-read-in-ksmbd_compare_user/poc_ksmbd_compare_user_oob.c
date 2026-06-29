// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Standalone ASan reproducer for the ksmbd_compare_user() OOB read pattern.
 *
 * Build:
 *   gcc -O0 -g -fsanitize=address -fno-omit-frame-pointer \
 *       poc_ksmbd_compare_user_oob.c -o /tmp/ksmbd_compare_user_oob
 *
 * Run:
 *   /tmp/ksmbd_compare_user_oob
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ksmbd_user {
	size_t passkey_sz;
	char *name;
	char *passkey;
};

static bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2)
{
	if (strcmp(u1->name, u2->name))
		return false;
	if (memcmp(u1->passkey, u2->passkey, u1->passkey_sz))
		return false;

	return true;
}

int main(void)
{
	struct ksmbd_user established;
	struct ksmbd_user reauth;
	bool same;

	established.name = strdup("alice");
	reauth.name = strdup("alice");

	/*
	 * This mirrors the vulnerable condition:
	 *   u1 == sess->user, already established with a longer passkey
	 *   u2 == newly allocated reauth user with a shorter passkey
	 */
	established.passkey_sz = 18;
	reauth.passkey_sz = 8;

	established.passkey = malloc(established.passkey_sz);
	reauth.passkey = malloc(reauth.passkey_sz);
	if (!established.name || !reauth.name ||
	    !established.passkey || !reauth.passkey)
		return 1;

	memset(established.passkey, 'A', established.passkey_sz);
	memset(reauth.passkey, 'A', reauth.passkey_sz);

	printf("About to compare %zu bytes against a %zu-byte buffer\n",
	       established.passkey_sz, reauth.passkey_sz);
	fflush(stdout);

	same = ksmbd_compare_user(&established, &reauth);
	printf("compare result: %d\n", same);

	free(established.passkey);
	free(reauth.passkey);
	free(established.name);
	free(reauth.name);
	return 0;
}
