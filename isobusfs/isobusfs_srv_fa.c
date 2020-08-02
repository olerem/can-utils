// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/kernel.h>

#include "isobusfs_cmn.h"
#include "isobusfs_srv.h"
#include "isobusfs_cmn_fa.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static struct isobusfs_srv_files *
isobusfs_srv_walk_files(struct isobusfs_srv_priv *priv, const char *path)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(priv->files); i++) {
		if (priv->files[i].path == NULL)
			continue;

		if (!strcmp(priv->files[i].path, path))
			return &priv->files[i];
	}

	return NULL;
}

static int isobusfs_srv_add_file(struct isobusfs_srv_priv *priv,
				 const char *path, int fd)
{
	int j;

	if (priv->files_count >= ARRAY_SIZE(priv->files)) {
		pr_err("too many files");
		return -ENOSPC;
	}

	for (j = 0; j < ARRAY_SIZE(priv->files); j++) {
		if (priv->files[j].path == NULL) {
			break;
		}
	}

	priv->files[j].path = strdup(path);
	priv->files[j].fd = fd;
	priv->files[j].refcount = 1;

	priv->files_count++;
	return j;
}

static int isobusfs_srv_add_client_to_file(struct isobusfs_srv_files *file,
					   struct isobusfs_srv_client *client)
{
	int j;

	for (j = 0; j < ARRAY_SIZE(file->clients); j++) {
		if (file->clients[j] == client) {
			return 0;
		}
	}

	for (j = 0; j < ARRAY_SIZE(file->clients); j++) {
		if (file->clients[j] == NULL) {
			file->clients[j] = client;
			file->refcount++;
			return 0;
		}
	}

	return -ENOENT;
}

static int isobusfs_srv_request_file(struct isobusfs_srv_priv *priv,
				     struct isobusfs_srv_client *client,
				     const char *path, int fd)
{
	struct isobusfs_srv_files *file;
	int file_index, ret;

	file = isobusfs_srv_walk_files(priv, path);
	if (!file) {
		file_index = isobusfs_srv_add_file(priv, path, fd);
		if (file_index < 0) {
			return file_index;
		}

		file = &priv->files[file_index];
	} else {
		file_index = file - priv->files;
	}

	ret = isobusfs_srv_add_client_to_file(file, client);
	if (ret < 0) {
		return ret;
	}

	return file_index;
}

static int isobusfs_srv_release_file(struct isobusfs_srv_priv *priv,
				     struct isobusfs_srv_client *client,
				     int file_index)
{
	if (file_index < 0 || file_index >= ARRAY_SIZE(priv->files)) {
		return -EINVAL;
	}

	struct isobusfs_srv_files *file = &priv->files[file_index];
	int client_index;

	// Find the client in the file's client list and remove it
	for (client_index = 0; client_index < ARRAY_SIZE(file->clients); client_index++) {
		if (file->clients[client_index] == client) {
			file->clients[client_index] = NULL;
			file->refcount--;

			// If refcount is 0, close the file and remove it from the list
			if (file->refcount == 0) {
				close(file->fd);
				memset(file, 0, sizeof(*file));
				priv->files_count--;
			}

			return 0;
		}
	}

	return -ENOENT;
}

void isobusfs_srv_remove_client_from_files(struct isobusfs_srv_priv *priv,
					   struct isobusfs_srv_client *client)
{
	int file_index;
	int client_index;

	for (file_index = 0; file_index < ARRAY_SIZE(priv->files); file_index++) {
		struct isobusfs_srv_files *file = &priv->files[file_index];

		if (file->path == NULL) {
			continue;
		}

		for (client_index = 0; client_index < ARRAY_SIZE(file->clients); client_index++) {
			if (file->clients[client_index] == client) {
				file->clients[client_index] = NULL;
				file->refcount--;

				// If refcount is 0, close the file and remove it from the list
				if (file->refcount == 0) {
					close(file->fd);
					memset(file, 0, sizeof(*file));
					priv->files_count--;
				}

				break;
			}
		}
	}
}

static int isobusfs_srv_fa_open_file(struct isobusfs_srv_priv *priv,
				     struct isobusfs_srv_client *client,
				     const char *path, size_t path_len,
				     uint8_t flags, uint8_t *handle)
{
	char linux_path[ISOBUSFS_SRV_MAX_PATH_LEN];
	struct isobusfs_srv_files *file;
	struct stat file_stat;
	int open_flags = 0;
	int file_index;
	int ret, fd;

	ret = isobusfs_path_to_linux_path(priv, path, path_len,
					  linux_path, sizeof(linux_path));
	if (ret < 0)
		return ret;

	pr_debug("convert ISOBUS FS path to linux path: %.*s -> %s",
		 path_len, path, linux_path);

	/* Determine open flags based on the requested access type */
	switch (flags & ISOBUSFS_FA_OPEN_MASK) {
	case ISOBUSFS_FA_OPEN_FILE_RO:
		open_flags |= O_RDONLY;
		break;
	case ISOBUSFS_FA_OPEN_FILE_WO:
		open_flags |= O_WRONLY;
		break;
	case ISOBUSFS_FA_OPEN_FILE_WR:
		open_flags |= O_RDWR;
		if (!(flags & ISOBUSFS_FA_OPEN_APPEND))
			open_flags |= O_TRUNC;
		break;
	default:
		return ISOBUSFS_ERR_INVALID_ACCESS;
	}

	if (flags & ISOBUSFS_FA_OPEN_APPEND)
		open_flags |= O_APPEND;

	/* Check if the file is already opened */
	file = isobusfs_srv_walk_files(priv, linux_path);
	if (file) {
		pr_warn("File: %s is already opened by client: %x\n",
			linux_path, client->addr);
		fd = file->fd;
	} else {
		// Open the file if not already opened
		fd = open(linux_path, open_flags);
		if (fd < 0) {
			switch (errno) {
			case EACCES:
				return ISOBUSFS_ERR_ACCESS_DENIED;
			case EINVAL:
				return ISOBUSFS_ERR_INVALID_ACCESS;
			case EMFILE:
			case ENFILE:
				return ISOBUSFS_ERR_TOO_MANY_FILES_OPEN;
			case ENOENT:
				return ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
			case ENOMEM:
				return ISOBUSFS_ERR_OUT_OF_MEM;
			default:
				return ISOBUSFS_ERR_OTHER;
			}
		}
		/* Check if the opened path is a regular file */
		if (fstat(fd, &file_stat) < 0) {
			close(fd);
			return ISOBUSFS_ERR_OTHER;
		}

		if (!S_ISREG(file_stat.st_mode)) {
			close(fd);
			/* Invalid access (not a regular file) */
			return ISOBUSFS_ERR_INVALID_ACCESS;
		}
	}

	// Request the file, which also handles refcount and client list updates
	file_index = isobusfs_srv_request_file(priv, client, linux_path, fd);
	if (file_index < 0) {
		close(fd);
		return file_index;
	}

	*handle = (uint8_t)file_index;

	return 0;
}

static int isobusfs_srv_fa_open_file_req(struct isobusfs_srv_priv *priv,
					 struct isobusfs_msg *msg)
{
	struct isobusfs_fa_openf_req *req =
		(struct isobusfs_fa_openf_req*)msg->buf;
	uint16_t name_len = le16toh(req->name_len);
	struct isobusfs_srv_client *client;
	struct isobusfs_fa_openf_res res;
	uint8_t error_code = 0;
	uint8_t access_type;
	size_t abs_path_len;
	char *abs_path;
	uint8_t handle;
	int ret = 0;

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		/* TODO: shoould we send an error response? */
		return -ENOENT;
	}

	if (name_len > msg->len - sizeof(*req)) {
		error_code = ISOBUSFS_ERR_INVALID_ACCESS;
		goto send_response;
	}

	// Perform checks on the received request, e.g., validate path length
	if (name_len > ISOBUSFS_MAX_PATH_NAME_LENGTH) {
		error_code = ISOBUSFS_ERR_INVALID_ACCESS;
		goto send_response;
	}

	abs_path_len = ISOBUSFS_SRV_MAX_PATH_LEN;
	abs_path = malloc(abs_path_len);
	if (!abs_path) {
		pr_warn("failed to allocate memory");
		return -ENOMEM;
	}

	/* Normalize provided string and convert it to absolute ISOBUS FS path */
	ret = isobusfs_convert_relative_to_absolute(priv, client->current_dir,
						    (char *)req->name, req->name_len,
						    abs_path, abs_path_len);
	if (ret < 0) {
		error_code = ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
		goto send_response;
	}

	pr_debug("< rx: Open File Request. from client 0x%2x: %.*s. Current directory: %s",
		 client->addr, req->name_len, req->name, client->current_dir);

	access_type = FIELD_GET(ISOBUSFS_FA_OPEN_MASK, req->flags);
	if (access_type == ISOBUSFS_FA_OPEN_DIR) {
		pr_debug("Directory access");
		// Implement logic for opening a file for reading
	} else {
		error_code = isobusfs_srv_fa_open_file(priv, client, abs_path,
						       abs_path_len, req->flags,
						       &handle);
	}

send_response:
	res.fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
					    ISOBUSFS_FA_F_OPEN_FILE_RES);
	res.tan = req->tan;
	res.error_code = error_code;
	res.handle = handle;
	memset(&res.reserved[0], 0xff, sizeof(res.reserved));

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, sizeof(res));
	if (ret < 0) {
		pr_warn("can't send current directory response");
		goto err;
	}

	pr_debug("> tx: Open File Response. Error code: %d", error_code);
err:

	return ret;
}

/* Command group: file access */
int isobusfs_srv_rx_cg_fa(struct isobusfs_srv_priv *priv,
			  struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FA_F_OPEN_FILE_REQ:
		ret = isobusfs_srv_fa_open_file_req(priv, msg);
		break;
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
