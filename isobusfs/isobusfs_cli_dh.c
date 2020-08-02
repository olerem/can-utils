// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "isobusfs_cli.h"
#include "isobusfs_cmn_dh.h"

/* 
 * C.2.3.2 Change Current Directory Request
 */
int isobusfs_cli_ccd_req(struct isobusfs_priv *priv, const char *name,
			 size_t name_len)
{
	struct isobusfs_dh_ccd_req *req;
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

	req->fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
						       ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ);
	req->tan = priv->tan++;

	memcpy(&req->name[0], name, name_len);
	req->name_len = name_len;

	if (padding_size) {
		/* Fill the rest of the res structure with 0xff */
		memset(((uint8_t *)req) + req_len - padding_size, 0xff,
		       padding_size);
	}

	priv->state = ISOBUSFS_CLI_STATE_WAIT_CCD_RESP;
	ret = isobusfs_send(priv->sock_main, req, req_len, &priv->tx_buf_log);
	if (ret < 0) {
		ret = -errno;
		pr_warn("failed to send ccd request: %d (%s)",
			ret, strerror(ret));
		goto free_req;
	}

	pr_debug("> tx: ccd request for %s", name);

free_req:
	free(req);

	return ret;
}

/* function to send current directory request */
int isobusfs_cli_get_current_dir_req(struct isobusfs_priv *priv)
{
	struct isobusfs_dh_get_cd_req req;
	int ret;

	req.fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
						      ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ);
	req.tan = priv->tan++;

	ret = isobusfs_send(priv->sock_main, &req, sizeof(req), &priv->tx_buf_log);
	if (ret < 0) {
		ret = -errno;
		pr_warn("failed to send current directory request: %d (%s)",
			ret, strerror(ret));
		return ret;
	}

	priv->state = ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR;

	pr_debug("> tx: current directory request");
	return 0;
}

static int isobusfs_cli_dh_current_dir_res(struct isobusfs_priv *priv,
					   struct isobusfs_msg *msg)
{
	struct isobusfs_dh_get_cd_res *res =
		(struct isobusfs_dh_get_cd_res*)msg->buf;
	char str[ISOBUSFS_MAX_PATH_NAME_LENGTH];
	uint16_t total_space, free_space, str_len;

	if (priv->state != ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR) {
		pr_warn("invalid state: %i (expected %i)", priv->state,
			ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR);
		return -EINVAL;
	}

	if (res->tan != priv->tan - 1) {
		pr_warn("invalid transaction id: %i (expected %i)", res->tan,
			priv->tan - 1);
		return -EINVAL;
	}

	total_space = le16toh(res->total_space);
	free_space = le16toh(res->free_space);
	str_len = le16toh(res->name_len);
	if (str_len > ISOBUSFS_MAX_PATH_NAME_LENGTH) {
		pr_warn("path name too long: %i, max is %i", str_len,
			ISOBUSFS_MAX_PATH_NAME_LENGTH);
		str_len = ISOBUSFS_MAX_PATH_NAME_LENGTH;
	}
	strncpy(str, (const char *)&res->name[0], str_len);

	priv->state = ISOBUSFS_CLI_STATE_GET_CURRENT_DIR_DONE;

	pr_debug("< rx: current directory response: %s, total space: %i, free space: %i",
		 str, total_space, free_space);

	return 0;
}

static int isobusfs_cli_dh_ccd_res(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	struct isobusfs_dh_ccd_res *res =
		(struct isobusfs_dh_ccd_res*)msg->buf;

	if (priv->state != ISOBUSFS_CLI_STATE_WAIT_CCD_RESP) {
		pr_warn("invalid state: %i (expected %i)", priv->state,
			ISOBUSFS_CLI_STATE_WAIT_CCD_RESP);
		return -EINVAL;
	}

	if (res->tan != priv->tan - 1) {
		pr_warn("invalid transaction id: %i (expected %i)", res->tan,
			priv->tan - 1);
		priv->state = ISOBUSFS_CLI_STATE_CCD_FAIL;
	} else if (res->error_code != 0) {
		pr_warn("ccd failed with error code: %i", res->error_code);
		priv->state = ISOBUSFS_CLI_STATE_CCD_FAIL;
	} else {
		priv->state = ISOBUSFS_CLI_STATE_CCD_DONE;
	}

	pr_debug("< rx: change current directory response. Error code: %i",
		 res->error_code); 

	return 0;
}

/* Command group: directory handling */
int isobusfs_cli_rx_cg_dh(struct isobusfs_priv *priv,
			  struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_DH_F_GET_CURRENT_DIR_RES:
		return isobusfs_cli_dh_current_dir_res(priv, msg);
	case ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_RES:
		return isobusfs_cli_dh_ccd_res(priv, msg);
	default:
		goto not_supported;
	}

	return ret;

not_supported:
	pr_warn("%s: unsupported function: %i", __func__, func);

	/* Not a critical error */
	return 0;
}
