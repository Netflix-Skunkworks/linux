/* SPDX-License-Identifier: GPL-2.0 */
#include <sys/socket.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>

#include "../kselftest.h"
#include "cgroup_util.h"

#define N 100

static int open_N_fds(const char *cgroup, void *arg)
{
	int i;
	long nofile;

	for (i = 0; i < N; i++) {
		int fd;

		fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (fd < 0) {
			ksft_print_msg("%d socket: %s\n", i, strerror(errno));
			return 1;
		}
	}

	/*
	 * N+3 std fds + 1 fd for "misc.current"
	 */
	nofile = cg_read_key_long(cgroup, "misc.current", "nofile ");
	if (nofile != N+3+1) {
		ksft_print_msg("bad open files count: %d\n", nofile);
		return 1;
	}

	return 0;
}

static int test_miscg_basic(const char *root)
{
	int ret = KSFT_FAIL;
	char *foo;

	foo = cg_name(root, "foo");
	if (!foo) {
		goto cleanup;
	}

	if (cg_create(foo)) {
		perror("cg_create");
		ksft_print_msg("cg_create failed\n");
		goto cleanup;
	}

	if (cg_write(root, "cgroup.subtree_control", "+misc")) {
		ksft_print_msg("cg_write failed\n");
		goto cleanup;
	}

	ret = cg_run(foo, open_N_fds, NULL);
	if (ret < 0) {
		ksft_print_msg("cg_run failed\n");
		goto cleanup;
	}

	if (ret == 0)
		ret = KSFT_PASS;

cleanup:
	cg_destroy(foo);
	free(foo);
	return ret;
}

#define COPIES 5

static int open_N_fds_and_sleep(const char *root, void *arg)
{
	int i, *sk_pair = arg;

	close(sk_pair[0]);

	for (i = 0; i < N; i++) {
		int fd;

		fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (fd < 0) {
			ksft_print_msg("%d socket: %s\n", i, strerror(errno));
			return 1;
		}
	}

	if (write(sk_pair[1], "c", 1) != 1) {
		ksft_print_msg("%d write: %s\n", i, strerror(errno));
		return 1;
	}

	while (1)
		sleep(1000);
}

static int test_miscg_threads(const char *root)
{
	int ret = KSFT_FAIL, i;
	char *foo;
	int pids[COPIES] = {};
	long nofile;

	foo = cg_name(root, "foo");
	if (!foo) {
		goto cleanup;
	}

	if (cg_create(foo)) {
		ksft_print_msg("cg_create failed\n");
		goto cleanup;
	}

	if (cg_write(root, "cgroup.subtree_control", "+misc")) {
		ksft_print_msg("cg_write failed\n");
		goto cleanup;
	}

	nofile = cg_read_key_long(foo, "misc.current", "nofile ");

	for (i = 0; i < COPIES; i++) {
		char c;
		int sk_pair[2];

		if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair) < 0) {
			ksft_print_msg("socketpair failed %s\n", strerror(errno));
			goto cleanup;
		}

		pids[i] = cg_run_nowait(foo, open_N_fds_and_sleep, sk_pair);
		if (pids[i] < 0) {
			perror("cg_run_nowait");
			ksft_print_msg("cg_run failed\n");
			goto cleanup;
		}
		close(sk_pair[1]);

		if (read(sk_pair[0], &c, 1) != 1) {
			ksft_print_msg("%d read: %s\n", i, strerror(errno));
			goto cleanup;
		}
		close(sk_pair[0]);
	}

	/*
	 * We expect COPIES * (N + 3 stdfs + 1 socketpair fd).
	 */
	nofile = cg_read_key_long(foo, "misc.current", "nofile ");
	if (nofile != COPIES*(N+3+1)) {
		ksft_print_msg("bad open files count: %d != %d\n", nofile, COPIES*(N+3+1));
		goto cleanup;
	}

	ret = KSFT_PASS;
cleanup:
	for (i = 0; i < COPIES; i++) {
		if (pids[i] >= 0)
			kill(pids[i], SIGKILL);
	}
	cg_destroy(foo);
	free(foo);
	return ret;
}

#define EXTRA 5
static int open_more_than_N_fds(const char *cgroup, void *arg)
{
	int emfiles = 0, i;

	for (i = 0; i < N+EXTRA; i++) {
		int fd;

		fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (fd < 0) {
			if (errno != EMFILE) {
				ksft_print_msg("%d socket: %s\n", i, strerror(errno));
				return 1;
			}

			emfiles++;
		}
	}

	/*
	 * We have 3 existing stdfds open, plus the 100 that we tried to open,
	 * plus the five extra.
	 */
	if (emfiles != EXTRA+3) {
		ksft_print_msg("got %d EMFILEs\n", emfiles);
		return 1;
	}
	return 0;
}

static int test_miscg_emfile_count(const char *root)
{
	int ret = KSFT_FAIL;
	char *foo;
	char nofile[128];
	long nofile_events;

	foo = cg_name(root, "foo");
	if (!foo) {
		goto cleanup;
	}

	if (cg_create(foo)) {
		ksft_print_msg("cg_create failed\n");
		goto cleanup;
	}

	if (cg_write(root, "cgroup.subtree_control", "+misc")) {
		ksft_print_msg("cg_write failed\n");
		goto cleanup;
	}

	snprintf(nofile, sizeof(nofile), "nofile %d", N);
	if (cg_write(foo, "misc.max", nofile)) {
		ksft_print_msg("cg_write failed\n");
		goto cleanup;
	}

	if (cg_run(foo, open_more_than_N_fds, NULL)) {
		perror("cg_run");
		ksft_print_msg("cg_run failed\n");
		goto cleanup;
	}

	nofile_events = cg_read_key_long(foo, "misc.events", "nofile.max ");
	if (nofile_events != EXTRA+3) {
		ksft_print_msg("bad nofile events: %ld\n", nofile_events);
		goto cleanup;
	}

	ret = KSFT_PASS;
cleanup:
	cg_destroy(foo);
	free(foo);
	return ret;
}

#define T(x) { x, #x }
struct misccg_test {
	int (*fn)(const char *root);
	const char *name;
} tests[] = {
	T(test_miscg_basic),
	T(test_miscg_threads),
	T(test_miscg_emfile_count),
};
#undef T

int main(int argc, char *argv[])
{
	char root[PATH_MAX];
	int i, ret = EXIT_SUCCESS;

	if (cg_find_unified_root(root, sizeof(root)))
		ksft_exit_skip("cgroup v2 isn't mounted\n");
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		switch (tests[i].fn(root)) {
		case KSFT_PASS:
			ksft_test_result_pass("%s\n", tests[i].name);
			break;
		case KSFT_SKIP:
			ksft_test_result_skip("%s\n", tests[i].name);
			break;
		default:
			ret = EXIT_FAILURE;
			ksft_test_result_fail("%s\n", tests[i].name);
			break;
		}
	}

	return ret;
}
