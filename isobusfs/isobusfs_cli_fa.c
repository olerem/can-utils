// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "isobusfs_cli.h"
#include "isobusfs_cmn_fa.h"

int isobusfs_cli_fa_cf_req(struct isobusfs_priv *priv, uint8_t handle)
{
	struct isobusfs_close_file_request req;
	int ret;

	// Set the FS function: Command (0b0010 << 4) | Function (0b0100)
	req.fs_function = (0x02 << 4) | 0x04;
	req.fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
						      ISOBUSFS_FA_F_CLOSE_FILE_REQ);
	req.tan = priv->tan++;
	req.handle = handle;
	memset(req.reserved, 0xFF, sizeof(req.reserved));

	priv->state = ISOBUSFS_CLI_STATE_WAIT_CF_RESP;

	// Send the close file request
	ret = isobusfs_send(priv->sock_main, &req, sizeof(req), &priv->tx_buf_log);
	if (ret < 0) {
		ret = -errno;
		pr_warn("failed to send close file request: %d (%s)", ret, strerror(ret));
		return ret;
	}

	pr_debug("> tx: Close File Request for handle: %x", req.handle);

	return ret;
}


int isobusfs_cli_fa_of_req(struct isobusfs_priv *priv, const char *name,
			   size_t name_len, uint8_t flags)
{
	struct isobusfs_fa_openf_req *req;
	size_t req_len = sizeof(*req) + name_len;
	size_t padding_size = 0;
	int ret;

	if (name_len > ISOBUSFS_MAX_PATH_NAME_LENGTH) {
		pr_warn("path name too long: %i, max is %i", name_len,
			ISOBUSFS_MAX_PATH_NAME_LENGTH);
		return -EINVAL;
	}

	if (req_len < ISOBUSFS_MIN_TRANSFER_LENGH) {
		/* Update the buffer size accordingly */
		padding_size = ISOBUSFS_MIN_TRANSFER_LENGH - req_len;
		req_len = ISOBUSFS_MIN_TRANSFER_LENGH;
	}

	req = malloc(req_len);
	if (!req) {
		pr_err("failed to allocate memory for ccd request");
		return -ENOMEM;
	}

	req->fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
						       ISOBUSFS_FA_F_OPEN_FILE_REQ);
	req->tan = priv->tan++;
	req->flags = flags;
	memcpy(&req->name[0], name, name_len);
	req->name_len = name_len;

	if (padding_size) {
		/* Fill the rest of the res structure with 0xff */
		memset(((uint8_t *)req) + req_len - padding_size, 0xff,
		       padding_size);
	}

	priv->state = ISOBUSFS_CLI_STATE_WAIT_OF_RESP;
	ret = isobusfs_send(priv->sock_main, req, req_len, &priv->tx_buf_log);
	if (ret < 0) {
		ret = -errno;
		pr_warn("failed to send ccd request: %d (%s)",
			ret, strerror(ret));
		goto free_req;
	}

	pr_debug("> tx: Open File Request for %s, with flags: %x", name,
		 req->flags);

free_req:
	free(req);

	return ret;
}

static int isobusfs_cli_fa_open_file_res(struct isobusfs_priv *priv,
					 struct isobusfs_msg *msg)
{
	struct isobusfs_fa_openf_res *res =
		(struct isobusfs_fa_openf_res*)msg->buf;

	if (priv->state != ISOBUSFS_CLI_STATE_WAIT_OF_RESP) {
		pr_warn("invalid state: %i (expected %i)", priv->state,
			ISOBUSFS_CLI_STATE_WAIT_OF_RESP);
		return -EINVAL;
	}

	if (res->tan != priv->tan - 1) {
		pr_warn("invalid transaction id: %i (expected %i)", res->tan,
			priv->tan - 1);
		priv->state = ISOBUSFS_CLI_STATE_OF_FAIL;
	} else if (res->error_code != 0) {
		pr_warn("ccd failed with error code: %i", res->error_code);
		priv->state = ISOBUSFS_CLI_STATE_OF_FAIL;
	} else {
		priv->state = ISOBUSFS_CLI_STATE_OF_DONE;
	}

	pr_debug("< rx: Open File Response. Error code: %i",
		 res->error_code); 

	return 0;
}

/* Command group: directory handling */
int isobusfs_cli_rx_cg_fa(struct isobusfs_priv *priv,
			  struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FA_F_OPEN_FILE_RES:
		ret = isobusfs_cli_fa_open_file_res(priv, msg);
		break;
	case ISOBUSFS_FA_F_SEEK_FILE_RES:
	case ISOBUSFS_FA_F_READ_FILE_RES:
	case ISOBUSFS_FA_F_WRITE_FILE_RES:
	case ISOBUSFS_FA_F_CLOSE_FILE_RES:
	default:
		goto not_supported;
	}

	return ret;

not_supported:
	pr_warn("%s: unsupported function: %i", __func__, func);

	/* Not a critical error */
	return 0;
}
