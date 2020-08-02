// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "isobusfs_cmn.h"

#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * ISO 11783-13:2021 A.2.2.1 Names.
 * LongNameChar ::= any single character defined by Unicode/ISO/IEC 10646,
 * except 0x00 to 0x1F, 0x7F to 0x9F, ‘\’, ‘*’, ‘?’, ‘/’.
 */
static bool isobusfs_cmn_dh_is_valid_char(char c)
{
	return (c >= 0x20) && (c <= 0x7E) && (c != '\\') && (c != '*') &&
	       (c != '?') && (c != '/');
}

/*
 * sanitize_path - Sanitizes an input path according to ISO 11783-13:2021 and
 *                 converts Windows path separators to Linux path separators.
 *
 * This function checks the input path for invalid characters as defined by the
 * LongNameChar specification from ISO 11783-13:2021:
 * LongNameChar ::= any single character defined by Unicode/ISO/IEC 10646,
 *                  except 0x00 to 0x1F, 0x7F to 0x9F, '\', '*', '?', '/'.
 *
 * @input_path: The input path to sanitize.
 * @output_path: The sanitized output path.
 * @output_path_size: The size of the output path buffer.
 *
 * Returns true if the input path is valid and sanitized successfully, false otherwise.
 */
bool isobusfs_cmn_dh_sanitize_path(const char *input_path, char *output_path,
		   size_t output_path_size)
{
	size_t input_len = strlen(input_path);
	size_t output_index = 0;
	size_t i = 0;

	// Skip initial backslashes
	if (input_len > 0 && input_path[0] == '\\') {
		i = (input_len > 1 && input_path[1] == '\\') ? 2 : 1;
	}

	for (; i < input_len; ++i) {
		char c = input_path[i];

		// Check if the character is valid
		if (!isobusfs_cmn_dh_is_valid_char(c)) {
			return false;
		}

		// Convert path separator
		if (c == '\\') {
			c = '/';
		}

		// Check for buffer overflow
		if (output_index + 1 >= output_path_size) {
			return false;
		}

		output_path[output_index++] = c;
	}

	// Null-terminate the output string
	output_path[output_index] = '\0';

	return true;
}

int isobusfs_cmn_dh_validate_dir_path(const char *path, bool writable)
{
	struct stat path_stat;
	int mode = R_OK;
	int ret;

	mode |= writable ? W_OK : 0;
	ret = access(path, mode);
	if (ret == -1) {
		ret = -errno;
		pr_err("failed to acces path %s, for read %s. %s", path,
		       writable ? "and write" : "", strerror(ret));
		return ret;
	}

	ret = stat(path, &path_stat);
	if (ret == -1) {
		ret = -errno;
		pr_err("failed to get stat information on path %s. %s", path,
			strerror(ret));
		return ret;
	}

	if (!S_ISDIR(path_stat.st_mode)) {
		pr_err("path %s is not a directory", path);
		return -ENOTDIR;
	}

	return 0;
}

