// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "isobusfs_srv.h"
#include "isobusfs_cmn_dh.h"

static void isobusfs_srv_set_default_current_dir(struct isobusfs_srv_priv *priv,
						 struct isobusfs_srv_client *client)
{
	snprintf(client->current_dir, ISOBUSFS_SRV_MAX_PATH_LEN, "\\%s",
		 priv->default_volume);
}

int isobusfs_path_to_linux_path(struct isobusfs_srv_priv *priv,
		const char *isobusfs_path, size_t isobusfs_path_size,
		char *linux_path, size_t linux_path_size)
{
	struct isobusfs_srv_volume *volume = NULL;
	char *ptr, *vol_end;
	int i;

	if (!priv || !isobusfs_path || !linux_path || !linux_path_size || !isobusfs_path_size) {
		return -EINVAL;
	}

	if (!(isobusfs_path[0] == '\\' && isobusfs_path[1] == '\\' &&
	      isobusfs_path[2] != '\0'))
		return -EINVAL;

	/* Find the volume in the isobusfs_path */
	vol_end = memchr(isobusfs_path + 2, '\\', isobusfs_path_size - 1);
	if (!vol_end)
		vol_end = memchr(isobusfs_path + 2, '\0', isobusfs_path_size - 1);

	/* Search for the volume in the priv->volumes array */
	for (i = 0; i < priv->volume_count; i++) {
		size_t volume_name_len = vol_end - (isobusfs_path + 2);
		if (volume_name_len == strlen(priv->volumes[i].name) && 
			memcmp(priv->volumes[i].name, isobusfs_path + 2, volume_name_len) == 0) {
			volume = &priv->volumes[i];
			break;
		}
	}
	if (!volume)
		return -ENOENT;

	/* Copy the volume's Linux path to the output buffer */
	strncpy(linux_path, volume->path, linux_path_size - 1);
	linux_path[linux_path_size - 1] = '\0';

	/* Add a forward slash if path ends after volume name */
	if (*vol_end == '\0' || vol_end == isobusfs_path + isobusfs_path_size - 1) {
		strncat(linux_path, "/", linux_path_size - strlen(linux_path) - 1);
	}

	/* Replace backslashes with forward slashes for the rest of the path */
	ptr = linux_path + strlen(linux_path);
	while (vol_end < isobusfs_path + isobusfs_path_size && *vol_end) {
		if (*vol_end == '\\') {
			*ptr = '/';
		} else {
			*ptr = *vol_end;
		}
		ptr++;
		vol_end++;
		if (ptr - linux_path >= linux_path_size) {
			/* Ensure null termination */
			linux_path[linux_path_size - 1] = '\0';
			break;
		}
	}

	return 0;
}


int isobusfs_check_current_dir_access(struct isobusfs_srv_priv *priv,
		struct isobusfs_srv_client *client)
{
	char linux_path[ISOBUSFS_SRV_MAX_PATH_LEN];
	int ret;

	ret = isobusfs_path_to_linux_path(priv, client->current_dir,
				          sizeof(client->current_dir),
					  linux_path, sizeof(linux_path));
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_dh_validate_dir_path(linux_path, false);
	if (ret < 0)
		return ret;

	return 0;
}


/* current directory response function */
static int isobusfs_srv_dh_current_dir_res(struct isobusfs_srv_priv *priv,
					   struct isobusfs_msg *msg)
{
	struct isobusfs_dh_get_cd_req *req =
		(struct isobusfs_dh_get_cd_req*)msg->buf;
	uint8_t error_code = ISOBUSFS_ERR_SUCCESS;
	struct isobusfs_dh_get_cd_res *res;
	struct isobusfs_srv_client *client;
	size_t str_len, buf_size;
	size_t fixed_res_size;
	int ret;

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		return -ENOENT;
	}

	if (client->current_dir[0] == '\0')
		isobusfs_srv_set_default_current_dir(priv, client);

	ret = isobusfs_check_current_dir_access(priv, client);
	if (ret < 0) {
		switch (ret) {
		case -ENOENT:
			error_code = ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
		case -ENOMEDIUM:
			error_code = ISOBUSFS_ERR_VOLUME_NOT_INITIALIZED;
		case -ENOMEM:
			error_code = ISOBUSFS_ERR_OUT_OF_MEM;
		default:
			error_code = ISOBUSFS_ERR_OTHER;
		}
	}

	fixed_res_size = sizeof(*res);
	str_len = strlen(client->current_dir) + 1;
	buf_size = fixed_res_size + str_len;

	if (buf_size > ISOBUSFS_MAX_TRANSFER_LENGH) {
		pr_warn("current directory response too long");

		/* Calculate the maximum allowed string length based on the 
		 * buffer size
		 */
		str_len = ISOBUSFS_MAX_TRANSFER_LENGH - fixed_res_size;

		/* Update the buffer size accordingly */
		buf_size = fixed_res_size + str_len;

		error_code = ISOBUSFS_ERR_OUT_OF_MEM;

	} else if (buf_size < ISOBUSFS_MIN_TRANSFER_LENGH) {
		/* Update the buffer size accordingly */
		buf_size = ISOBUSFS_MIN_TRANSFER_LENGH;
	}

	res = malloc(buf_size);
	if (!res) {
		pr_err("failed to allocate memory for current directory response");
		return -ENOMEM;
	}

	res->fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
					    ISOBUSFS_DH_F_GET_CURRENT_DIR_RES);
	res->tan = req->tan;
	res->error_code = error_code;
	/* TODO: implement total_space and free_space */
	res->total_space = htole16(0);
	res->free_space = htole16(0);
	res->name_len = htole16(str_len);
	memcpy(res->name, client->current_dir, str_len);

	if (buf_size < ISOBUSFS_MIN_TRANSFER_LENGH) {
		/* Calculate the padding size needed to reach the minimum
		 * transfer length
		 */
		size_t padding_size = ISOBUSFS_MIN_TRANSFER_LENGH - buf_size;

		/* Fill the rest of the res structure with 0xff */
		memset(((uint8_t *)&res) + fixed_res_size + str_len, 0xff,
		       padding_size);
	}

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, buf_size);
	if (ret < 0) {
		pr_warn("can't send current directory response");
		goto free_res;
	}

	pr_debug("> tx: current directory response: %s, total space: %i, free space: %i",
			 client->current_dir, le16toh(res->total_space),
			 le16toh(res->free_space));

free_res:
	free(res);

	return ret;
}


/* current directory response function */
/* Command group: directory handling */
int isobusfs_srv_rx_cg_dh(struct isobusfs_srv_priv *priv,
			  struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ: /* fall through */
		return isobusfs_srv_dh_current_dir_res(priv, msg);
	case ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ: /* fall through */
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
