// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "isobusfs_srv.h"

/* Command group: file access */
int isobusfs_srv_rx_cg_fa(struct isobusfs_srv_priv *priv,
			  struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FA_F_OPEN_FILE_REQ: /* fall through */
	case ISOBUSFS_FA_F_SEEK_FILE_REQ: /* fall through */
	case ISOBUSFS_FA_F_READ_FILE_REQ: /* fall through */
	case ISOBUSFS_FA_F_WRITE_FILE_REQ: /* fall through */
	case ISOBUSFS_FA_F_CLOSE_FILE_REQ: /* fall through */
	default:
		goto not_supported;
	}

	return ret;

not_supported:
	isobusfs_srv_send_error(priv, msg, ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);

	pr_warn("%s: unsupported function: %i", __func__, func);

	/* Not a critical error */
	return 0;
}
