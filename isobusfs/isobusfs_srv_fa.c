// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <endian.h>
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

static struct isobusfs_srv_handles *
isobusfs_srv_walk_handles(struct isobusfs_srv_priv *priv, const char *path)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(priv->handles); i++) {
		if (priv->handles[i].path == NULL)
			continue;

		if (!strcmp(priv->handles[i].path, path))
			return &priv->handles[i];
	}

	return NULL;
}

static int isobusfs_srv_add_file(struct isobusfs_srv_priv *priv,
				 const char *path, int fd)
{
	int j;

	if (priv->handles_count >= ARRAY_SIZE(priv->handles)) {
		pr_err("too many handles");
		return -ENOSPC;
	}

	for (j = 0; j < ARRAY_SIZE(priv->handles); j++) {
		if (priv->handles[j].path == NULL) {
			break;
		}
	}

	priv->handles[j].path = strdup(path);
	priv->handles[j].fd = fd;
	priv->handles[j].refcount = 1;

	priv->handles_count++;
	return j;
}

static int isobusfs_srv_add_client_to_file(struct isobusfs_srv_handles *file,
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
	struct isobusfs_srv_handles *file;
	int handle, ret;

	file = isobusfs_srv_walk_handles(priv, path);
	if (!file) {
		handle = isobusfs_srv_add_file(priv, path, fd);
		if (handle < 0) {
			return handle;
		}

		file = &priv->handles[handle];
	} else {
		handle = file - priv->handles;
	}

	ret = isobusfs_srv_add_client_to_file(file, client);
	if (ret < 0) {
		return ret;
	}

	return handle;
}

static struct isobusfs_srv_handles *
isobusfs_srv_get_handle(struct isobusfs_srv_priv *priv, int handle)
{
	if (handle < 0 || handle >= ARRAY_SIZE(priv->handles)) {
		return NULL;
	}

	return &priv->handles[handle];
}

static int isobusfs_srv_release_handle(struct isobusfs_srv_priv *priv,
				       struct isobusfs_srv_client *client,
				       int handle)
{
	struct isobusfs_srv_handles *hdl = isobusfs_srv_get_handle(priv, handle);
	int client_index;

	if (!hdl)
		return -ENOENT;

	/* Find the client in the hdl's client list and remove it */
	for (client_index = 0; client_index < ARRAY_SIZE(hdl->clients); client_index++) {
		if (hdl->clients[client_index] == client) {
			hdl->clients[client_index] = NULL;
			hdl->refcount--;

			/* If refcount is 0, close the hdl and remove it from the list */
			if (hdl->refcount == 0) {
				close(hdl->fd);
				memset(hdl, 0, sizeof(*hdl));
				priv->handles_count--;
			}

			return 0;
		}
	}

	return -ENOENT;
}

void isobusfs_srv_remove_client_from_handles(struct isobusfs_srv_priv *priv,
					   struct isobusfs_srv_client *client)
{
	int handle;
	int client_index;

	for (handle = 0; handle < ARRAY_SIZE(priv->handles); handle++) {
		struct isobusfs_srv_handles *hdl = &priv->handles[handle];

		if (hdl->path == NULL) {
			continue;
		}

		for (client_index = 0; client_index < ARRAY_SIZE(hdl->clients); client_index++) {
			if (hdl->clients[client_index] == client) {
				hdl->clients[client_index] = NULL;
				hdl->refcount--;

				// If refcount is 0, close the hdl and remove it from the list
				if (hdl->refcount == 0) {
					close(hdl->fd);
					memset(hdl, 0, sizeof(*hdl));
					priv->handles_count--;
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
	struct isobusfs_srv_handles *hdl;
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
	hdl = isobusfs_srv_walk_handles(priv, linux_path);
	if (hdl) {
		pr_warn("Handle: %s is already opened by client: %x\n",
			linux_path, client->addr);
		fd = hdl->fd;
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
		error_code = ISOBUSFS_ERR_OTHER;
		goto send_response;
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
		pr_warn("Directory access is not supported");
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

static int isobusfs_srv_fa_rf_req(struct isobusfs_srv_priv *priv,
				  struct isobusfs_msg *msg)
{
	uint8_t res_fail[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct isobusfs_read_file_response *res;
	struct isobusfs_srv_handles *handle;
	struct isobusfs_srv_client *client;
	struct isobusfs_fa_readf_req *req;
	ssize_t readed_size = 0;
	uint8_t error_code = 0;
	ssize_t send_size;
	int ret = 0;
	int count;

	req = (struct isobusfs_fa_readf_req *)msg->buf;

        count = le16toh(req->count);
	pr_debug("< rx: Read File Request. tan: %d, handle: %d, count: %d",
	  	 req->tan, req->handle, count);
        /* C.3.5.1 Read File, General:
         * The requested data (excluding the other parameters) is sent in
	 * the response (up to 1 780 bytes when TP is used, up to 65 530 bytes
	 * when ETP is used). The number of data bytes read can be less than
	 * requested if the end of the file is reached.
	 * TODO: currently we are not able to detect support transport mode,
	 * so ETP is assumed.
	 */
        if (count > ISOBUSFS_MAX_DATA_LENGH)
                count = ISOBUSFS_MAX_DATA_LENGH;

        res = malloc(sizeof(*res) + count);
	if (!res) {
		pr_warn("failed to allocate memory");
		res = (struct isobusfs_read_file_response *)&res_fail[0];
		error_code = ISOBUSFS_ERR_OUT_OF_MEM;
		goto send_response;
	}

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		error_code = ISOBUSFS_ERR_OTHER;
		goto send_response;
	}

	handle = isobusfs_srv_get_handle(priv, req->handle);
	if (!handle) {
		pr_warn("failed to find file with handle: %x", req->handle);
		error_code = ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
	}

	readed_size = read(handle->fd, res->data, count);
	if (readed_size < 0) {
		ret = errno;
		pr_warn("failed to read file: %s", strerror(ret));

		switch (ret) {
		case EBADF:
			error_code = ISOBUSFS_ERR_INVALID_HANDLE;
		case EFAULT:
			error_code = ISOBUSFS_ERR_OUT_OF_MEM;
		case EIO:
			error_code = ISOBUSFS_ERR_ON_READ;
		default:
			error_code = ISOBUSFS_ERR_OTHER;
		}

		readed_size = 0;
	} else if (count != 0 && readed_size == 0) {
		pr_debug("end of file");
		error_code = ISOBUSFS_ERR_END_OF_FILE;
	}

send_response:
	res->fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
					    ISOBUSFS_FA_F_READ_FILE_RES);
	res->tan = req->tan;
	res->error_code = error_code;
	res->count = htole16(readed_size);

	send_size = sizeof(*res) + readed_size;
	if (send_size < ISOBUSFS_MIN_TRANSFER_LENGH)
		send_size = ISOBUSFS_MIN_TRANSFER_LENGH;

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, res, send_size);
	if (ret < 0) {
		pr_warn("can't send Read File Response");
		goto free_res;
	}

	pr_debug("> tx: Read File Response. Error code: %d, readed size: %d",
		 error_code, readed_size);

free_res:
	free(res);
	return ret;
}

static int isobusfs_srv_seek(struct isobusfs_srv_priv *priv,
			     struct isobusfs_srv_handles *handle, int32_t offset,
			     uint8_t position_mode)
{
	int whence;
	off_t offs;

	switch (position_mode) {
	case ISOBUSFS_FA_SEEK_SET:
		whence = SEEK_SET;
		if (offset < 0) {
			pr_warn("Invalid offset. Offset must be positive.");
			return ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT;
		}
		break;
	case ISOBUSFS_FA_SEEK_CUR:
		whence = SEEK_CUR;
		if (offset < 0 && handle->offset < -offset) {
			pr_warn("Invalid offset. Negative offset is too big.");
			return ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT;
		}
		break;
	case ISOBUSFS_FA_SEEK_END:
		whence = SEEK_END;
		if (offset > 0) {
			pr_warn("Invalid offset. Offset must be negative");
			return ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT;
		}
		break;
	default:
		pr_warn("invalid position mode");
		return ISOBUSFS_ERR_OTHER;
	}

	/* seek file */
	offs = lseek(handle->fd, offset, whence);
	if (offs < 0) {
		pr_warn("Failed to seek file");

		switch (offs) {
		case EBADF:
			return ISOBUSFS_ERR_INVALID_HANDLE;
		case EINVAL:
			return ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT;
		case ENXIO:
			return ISOBUSFS_ERR_END_OF_FILE;
		case EOVERFLOW:
			return ISOBUSFS_ERR_OUT_OF_MEM;
		case ESPIPE:
			return ISOBUSFS_ERR_ACCESS_DENIED;
		default:
			return ISOBUSFS_ERR_OTHER;
		}
	}

	handle->offset = offs;

	return ISOBUSFS_ERR_SUCCESS;
}

static int isobusfs_srv_fa_sf_req(struct isobusfs_srv_priv *priv,
				  struct isobusfs_msg *msg)
{
	struct isobusfs_fa_seekf_res res = {0};
	struct isobusfs_srv_client *client;
	struct isobusfs_fa_seekf_req *req;
	struct isobusfs_srv_handles *handle;
	int32_t offset_out = 0;
	uint8_t error_code = 0;
	int ret;

	req = (struct isobusfs_fa_seekf_req *)msg->buf;
	pr_debug("< rx: Seek File Request. Handle: %x, offset: %d, position mode: %d",
		 req->handle, le32toh(req->offset), req->position_mode);

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		error_code = ISOBUSFS_ERR_OTHER;
		goto send_response;
	}

	handle = isobusfs_srv_get_handle(priv, req->handle);
	if (!handle) {
		pr_warn("failed to find handle: %x", req->handle);
		error_code = ISOBUSFS_ERR_INVALID_HANDLE;
		goto send_response;
	}

	if (handle->is_dir) {
		pr_warn("Directory handle is currently not supported");
		error_code = ISOBUSFS_ERR_ACCESS_DENIED;
	} else {
		error_code = isobusfs_srv_seek(priv, handle, le32toh(req->offset),
					       req->position_mode);
		res.position = htole32(handle->offset);
	}
	
send_response:
	res.fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
					    ISOBUSFS_FA_F_SEEK_FILE_RES);
	res.tan = req->tan;
	res.error_code = error_code;

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, sizeof(res));
	if (ret < 0) {
		pr_warn("can't send seek file response");
		return ret;
	}

	pr_debug("> tx: Seek File Response. Error code: %d, offset: %d",
		 error_code, offset_out);

	return 0;
}

static int isobusfs_srv_fa_cf_req(struct isobusfs_srv_priv *priv,
				  struct isobusfs_msg *msg)
{
	struct isobusfs_close_file_request *req;
	struct isobusfs_close_file_res res;
	struct isobusfs_srv_client *client;
	uint8_t error_code = 0;
	int ret;

	req = (struct isobusfs_close_file_request *)msg->buf;

	client = isobusfs_srv_get_client_by_msg(priv, msg);
	if (!client) {
		pr_warn("client not found");
		error_code = ISOBUSFS_ERR_OTHER;
		goto send_response;
	}

	ret = isobusfs_srv_release_handle(priv, client, req->handle);
	if (ret < 0) {
		pr_warn("failed to release handle: %x", req->handle);
		switch (ret) {
		case -ENOENT:
			error_code = ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND;
			break;
		default:
			error_code = ISOBUSFS_ERR_OTHER;
		}
	}

send_response:
	res.fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_FILE_ACCESS,
					    ISOBUSFS_FA_F_CLOSE_FILE_RES);
	res.tan = req->tan;
	res.error_code = error_code;
	memset(&res.reserved[0], 0xff, sizeof(res.reserved));

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, sizeof(res));
	if (ret < 0) {
		pr_warn("can't send current directory response");
		goto err;
	}

	pr_debug("> tx: Close File Response. Error code: %d", error_code);

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
	case ISOBUSFS_FA_F_CLOSE_FILE_REQ:
		ret = isobusfs_srv_fa_cf_req(priv, msg);
		break;
	case ISOBUSFS_FA_F_READ_FILE_REQ:
		ret = isobusfs_srv_fa_rf_req(priv, msg);
		break;
	case ISOBUSFS_FA_F_SEEK_FILE_REQ:
		ret = isobusfs_srv_fa_sf_req(priv, msg);
		break;
	case ISOBUSFS_FA_F_WRITE_FILE_REQ: /* fall through */
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
