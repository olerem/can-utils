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
	snprintf(client->current_dir, ISOBUSFS_SRV_MAX_PATH_LEN, "\\\\%s",
		 priv->default_volume);
}

static const char *isobusfs_srv_get_volume_end(const char *path, size_t path_size)
{
	const char *vol_end = NULL;
	size_t i;

	if (!path || !path_size)
		return NULL;

	if (!(path[0] == '\\' && path[1] == '\\' && path[2] != '\0'))
		return NULL;

	for (i = 2; i < path_size; i++) {
		if (path[i] == '\\' || path[i] == '\0') {
			vol_end = &path[i];
			break;
		}
	}

	if (!vol_end)
		vol_end = &path[i];

	return vol_end;
}

int isobusfs_path_to_linux_path(struct isobusfs_srv_priv *priv,
		const char *isobusfs_path, size_t isobusfs_path_size,
		char *linux_path, size_t linux_path_size)
{
	struct isobusfs_srv_volume *volume = NULL;
	size_t isobusfs_path_pos = 0;
	const char *vol_end;
	char *ptr;
	int i;

	if (!priv || !isobusfs_path || !linux_path || !linux_path_size ||
	    !isobusfs_path_size)
		return -EINVAL;

	vol_end = isobusfs_srv_get_volume_end(isobusfs_path, isobusfs_path_size);
	if (!vol_end)
		return -EINVAL;

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

	isobusfs_path_pos = vol_end - isobusfs_path;
	/* Add a forward slash if path ends after volume name */
	if (*vol_end == '\0' || isobusfs_path_pos == isobusfs_path_size - 1) {
		strncat(linux_path, "/", linux_path_size - strlen(linux_path) - 1);
	}

	if (isobusfs_path_pos + 3 < isobusfs_path_size && strncmp(vol_end, "\\~\\", 3) == 0) {
		strncat(linux_path, "/", linux_path_size - strlen(linux_path) - 1);
		/* convert tilde to manufacturer-specific directory */
		strncat(linux_path, priv->mfs_dir,
			linux_path_size - strlen(linux_path) - 1);
		vol_end += 2;
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
				      const char *path, size_t path_size)
{
	char linux_path[ISOBUSFS_SRV_MAX_PATH_LEN];
	int ret;

	ret = isobusfs_path_to_linux_path(priv, path, path_size,
					  linux_path, sizeof(linux_path));
	if (ret < 0)
		return ret;

	pr_debug("convert ISOBUS FS path to linux path: %.*s -> %s",
		 path_size, path, linux_path);

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
	size_t padding_size = 0;
	int ret;

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		return -ENOENT;
	}

	if (client->current_dir[0] == '\0')
		isobusfs_srv_set_default_current_dir(priv, client);

	ret = isobusfs_check_current_dir_access(priv, client->current_dir,
					 sizeof(client->current_dir));
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
		padding_size = ISOBUSFS_MIN_TRANSFER_LENGH - buf_size;
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

	if (padding_size) {
		/* Fill the rest of the res structure with 0xff */
		memset(((uint8_t *)res) + buf_size - padding_size, 0xff,
		       padding_size);
	}

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, res, buf_size);
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

static int isobusfs_convert_relative_to_absolute(struct isobusfs_srv_priv *priv, const char *current_dir,
					  const char *rel_path, size_t rel_path_size, char *abs_path,
					  size_t abs_path_size)
{
	size_t abs_path_pos = 0;
	size_t rel_path_pos = 0;
	size_t current_dir_len;

	if (!current_dir || !rel_path || !abs_path || !rel_path_size || !abs_path_size) {
		return -EINVAL;
	}

	current_dir_len = strlen(current_dir);
	if (current_dir_len >= abs_path_size)
		return -ENOMEM;
	if (current_dir_len == 0)
		return -EINVAL;

	if (strncmp(rel_path, "~\\", 2) == 0) {
		size_t vol_len;
		const char *vol_end;

		vol_end = isobusfs_srv_get_volume_end(current_dir, current_dir_len);
		if (!vol_end)
			return -EINVAL;

		vol_len = vol_end - current_dir;
		strncpy(abs_path, current_dir, vol_len);
		abs_path[vol_len] = '\\';
		abs_path_pos = vol_len + 1;
	} else if (strncmp(rel_path, "\\\\", 2) == 0) {
		/* Too many back slashes, drop it. */
		if (rel_path[2] == '\\')
			return -EINVAL;

		strncpy(abs_path, rel_path, 2);
		abs_path_pos = 2;
		rel_path_pos = 2;
	} else {
		strncpy(abs_path, current_dir, abs_path_size);
		abs_path_pos = current_dir_len;
		if (abs_path[abs_path_pos - 1] != '\\') {
			if (abs_path_pos < abs_path_size - 1) {
				abs_path[abs_path_pos++] = '\\';
			} else {
				return -ENOMEM;
			}
		}
		if (rel_path[rel_path_pos] == '\\')
			++rel_path_pos;
	}

	while (rel_path_pos < rel_path_size && rel_path[rel_path_pos] != '\0') {
		if (abs_path_pos >= abs_path_size - 1) {
			return -ENOMEM;
		}

		if (strncmp(rel_path + rel_path_pos, ".\\", 2) == 0) {
			rel_path_pos += 2;
		} else if (strncmp(rel_path + rel_path_pos, "..\\", 3) == 0) {
			rel_path_pos += 3;
			if (abs_path_pos > 2 && abs_path[abs_path_pos - 1] == '\\')
				--abs_path_pos;

			while (abs_path_pos > 2 && abs_path[abs_path_pos - 1] != '\\') {
				--abs_path_pos;
			}
		} else {
			abs_path[abs_path_pos++] = rel_path[rel_path_pos++];
			while (rel_path_pos < rel_path_size && rel_path[rel_path_pos] != '\0' && rel_path[rel_path_pos] != '\\') {
				if (abs_path_pos >= abs_path_size - 1) {
					return -ENOMEM;
				}
				abs_path[abs_path_pos++] = rel_path[rel_path_pos++];
			}
		}
	}

	abs_path[abs_path_pos] = '\0';

	return 0;
}

/* change current directory response function */
static int isobusfs_srv_dh_ccd_res(struct isobusfs_srv_priv *priv,
				   struct isobusfs_msg *msg)
{
	struct isobusfs_dh_ccd_req *req =
		(struct isobusfs_dh_ccd_req*)msg->buf;
	uint8_t error_code = ISOBUSFS_ERR_SUCCESS;
	struct isobusfs_srv_client *client;
	struct isobusfs_dh_ccd_res res;
	size_t abs_path_len;
	char *abs_path;
	int ret;

	/*
	 * We assime, the relative path stored in res->name is not longer
	 * than absolue path
	 */
	if (req->name_len > ISOBUSFS_SRV_MAX_PATH_LEN) {
		pr_warn("path too long");
		return -EINVAL;
	}

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		return -ENOENT;
	}

	abs_path_len = ISOBUSFS_SRV_MAX_PATH_LEN;
	abs_path = malloc(abs_path_len);
	if (!abs_path) {
		pr_warn("failed to allocate memory");
		return -ENOMEM;
	}

	pr_debug("< rx change current directory request from client 0x%2x: %.*s. Current directory: %s",
		 client->addr, req->name_len, req->name, client->current_dir);
	/* Normalize provided string and convert it to absolute ISOBUS FS path */
	ret = isobusfs_convert_relative_to_absolute(priv, client->current_dir,
						    (char *)req->name, req->name_len,
						    abs_path, abs_path_len);
	if (ret < 0) {
		error_code = ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
		goto send_response;
	}

	pr_debug("converted relative to absolute ISOBUS FS internal path: %s", abs_path);

	ret = isobusfs_check_current_dir_access(priv, abs_path, abs_path_len);
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
	} else {
		/* change current directory */
		strncpy(client->current_dir, abs_path, ISOBUSFS_SRV_MAX_PATH_LEN);
	}

send_response:
	res.fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
					    ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_RES);
	res.tan = req->tan;
	res.error_code = error_code;
	memset(&res.reserved[0], 0xff, sizeof(res.reserved));

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, sizeof(res));
	if (ret < 0) {
		pr_warn("can't send current directory response");
		goto free_abs_path;
	}

	pr_debug("> tx: ccd response. Error code: %d", error_code);
free_abs_path:
	free(abs_path);

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
	case ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ:
		return isobusfs_srv_dh_current_dir_res(priv, msg);
	case ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ:
		return isobusfs_srv_dh_ccd_res(priv, msg);
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
