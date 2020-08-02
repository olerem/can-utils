// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "isobusfs_cli.h"
#include "isobusfs_cmn.h"

size_t current_test = 0;
bool test_running = false;
bool all_tests_completed = false;
struct timespec test_start_time;

struct isobusfs_cli_test_case {
	int (*test_func)(struct isobusfs_priv *priv, bool *complete);
	const char *test_description;
};

static int isobusfs_cli_test_connect(struct isobusfs_priv *priv, bool *complete)
{
	struct timespec current_time;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (test_start_time.tv_sec == 0) {
		test_start_time = current_time;
	}

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_CONNECTING:
		if (current_time.tv_sec - test_start_time.tv_sec >= 5) {
			ret = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case ISOBUSFS_CLI_STATE_IDLE:
	case ISOBUSFS_CLI_STATE_CONNECTING_DONE:
		*complete = true;
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		ret = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	/* without server all other tests make no sense */
	all_tests_completed = true;
	*complete = true;

	return ret;
}

static int isobusfs_cli_test_property_req(struct isobusfs_priv *priv, bool *complete)
{
	struct timespec current_time;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (test_start_time.tv_sec == 0) {
		test_start_time = current_time;

		ret = isobusfs_cli_property_req(priv);
		if (ret)
			goto test_fail;
	}

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_WAIT_FS_PROPERTIES:
		if (current_time.tv_sec - test_start_time.tv_sec >= 5) {
			ret = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case ISOBUSFS_CLI_STATE_GET_FS_PROPERTIES_DONE:
		*complete = true;
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		ret = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	*complete = true;

	return ret;
}

static int isobusfs_cli_test_volume_status_req(struct isobusfs_priv *priv, bool *complete)
{
	const char volume_name[] = "\\\\vol1";
	struct timespec current_time;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (test_start_time.tv_sec == 0) {
		test_start_time = current_time;

		ret = isobusfs_cli_volume_status_req(priv, 0,
				       sizeof(volume_name) - 1, volume_name);
		if (ret)
			goto test_fail;
	}

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_WAIT_VOLUME_STATUS:
		if (current_time.tv_sec - test_start_time.tv_sec >= 5) {
			ret = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case ISOBUSFS_CLI_STATE_VOLUME_STATUS_DONE:
		*complete = true;
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		ret = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	*complete = true;

	return ret;
}

static int isobusfs_cli_test_current_dir_req(struct isobusfs_priv *priv, bool *complete)
{
	struct timespec current_time;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (test_start_time.tv_sec == 0) {
		test_start_time = current_time;

		ret = isobusfs_cli_get_current_dir_req(priv);
		if (ret)
			goto test_fail;
	}

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR:
		if (current_time.tv_sec - test_start_time.tv_sec >= 5) {
			ret = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case ISOBUSFS_CLI_STATE_GET_CURRENT_DIR_DONE:
		*complete = true;
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		ret = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	*complete = true;

	return ret;
}

struct isobusfs_cli_test_dir_path { 
	const char *dir_name;
	bool expect_pass;
};

static struct isobusfs_cli_test_dir_path test_dir_patterns[] = {
	/* expected result \\vol1\dir1\ */
	{ "\\\\vol1\\dir1", true },
	/* expected result \\vol1\dir1\dir2\ */
	{ "\\\\vol1\\dir1\\dir2", true },
	/* expected result \\vol1\dir1\dir2\dir3\dir4\ */
	{ ".\\dir3\\dir4", true },
	/* expected result \\vol1\dir1\dir2\dir3\dir5\ */
	{ "..\\dir5", true },
	/* expected result \\vol1\ */
	{ "..\\..\\..\\..\\..\\..\\vol1", true },
	/* expected result \\vol1\~\ */
	{ "~\\", true },
	/* expected result \\vol1\~\msd_dir1\msd_dir2\ */
	{ "~\\msd_dir1\\msd_dir2", true },
	/* expected result \\vol1\~\ */
	{ "\\\\vol1\\~\\", true },
	/* expected result \\vol1\~\msd_dir1\msd_dir2\ */
	{ "\\\\vol1\\~\\msd_dir1\\msd_dir2", true },
	/* expected result \\vol1\~\msd_dir1\msd_dir2\~\ */
	{ ".\\~\\", true },
	/* expected result \\vol1\~\msd_dir1\msd_dir2\~\~tilde_dir */
	{ "~tilde_dir", true },
	/* expected result \\vol1\dir1\~\ */
	{ "\\\\vol1\\dir1\\~", true },
	/* expected result \\vol1\~\ not clear if it is manufacture speficic dir */
	{ "\\~\\", true },
	/* expected result \\~\ */
	{ "\\\\~\\", false },
	/* expected result: should fail */
	{ "\\\\\\\\\\\\\\\\", false },
};

size_t current_dir_pattern_test = 0;

static int isobusfs_cli_test_ccd_req(struct isobusfs_priv *priv, bool *complete)
{
	size_t num_patterns = ARRAY_SIZE(test_dir_patterns);
	struct timespec current_time;
	bool fail = false;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &current_time);

	if (test_start_time.tv_sec == 0) {
		const char *dir_name = test_dir_patterns[current_dir_pattern_test].dir_name;
		size_t dir_name_len = strlen(dir_name);

		test_start_time = current_time;
		pr_info("Start pattern test: %s\n", dir_name);
		ret = isobusfs_cli_ccd_req(priv, dir_name, dir_name_len);
		if (ret)
			goto test_fail;

	}

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_WAIT_CCD_RESP:
		if (current_time.tv_sec - test_start_time.tv_sec >= 5) {
			ret = -ETIMEDOUT;
			goto test_fail;
		}
		break;
	case ISOBUSFS_CLI_STATE_CCD_FAIL:
		fail = true;
	case ISOBUSFS_CLI_STATE_CCD_DONE:
		if (test_dir_patterns[current_dir_pattern_test].expect_pass && fail) {
			pr_err("pattern test failed: %s\n", test_dir_patterns[current_dir_pattern_test].dir_name);
			ret = -EINVAL;
			goto test_fail;
		} else if (!test_dir_patterns[current_dir_pattern_test].expect_pass && !fail) {
			pr_err("pattern test failed: %s\n", test_dir_patterns[current_dir_pattern_test].dir_name);
			ret = -EINVAL;
			goto test_fail;
		}
		current_dir_pattern_test++;

		if (current_dir_pattern_test >= num_patterns) {
			*complete = true;
		} else {
			test_start_time.tv_sec = 0;
			priv->state = ISOBUSFS_CLI_STATE_SELFTEST;
		}
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		ret = -EINVAL;
		goto test_fail;
	}

	return 0;

test_fail:
	*complete = true;
	return ret;
}

struct isobusfs_cli_test_case test_cases[] = {
	{ isobusfs_cli_test_connect, "Server connection" },
	{ isobusfs_cli_test_property_req, "Server property request" },
	{ isobusfs_cli_test_volume_status_req, "Volume status request" },
	{ isobusfs_cli_test_current_dir_req, "Get current dir request" },
	{ isobusfs_cli_test_ccd_req, "Change current dir request" },
};

void isobusfs_cli_run_self_tests(struct isobusfs_priv *priv)
{
	if (!all_tests_completed) {
		size_t num_tests = ARRAY_SIZE(test_cases);

		if (current_test < num_tests) {
			bool test_complete = false;
			int ret;

			if (!test_running) {
				pr_info("Executing test %zu: %s\n", current_test + 1, test_cases[current_test].test_description);
				test_running = true;
				test_start_time.tv_sec = 0;
			}

			ret = test_cases[current_test].test_func(priv, &test_complete);

			if (test_complete) {
				test_running = false;
				pr_info("Test %zu: %s.\n", current_test + 1, ret ? "FAILED" : "PASSED");
				current_test++;
				priv->state = ISOBUSFS_CLI_STATE_SELFTEST;
			}
		} else {
			pr_info("All tests completed.\n");
			all_tests_completed = true;
			priv->state = ISOBUSFS_CLI_STATE_IDLE;
		}
	}
}
