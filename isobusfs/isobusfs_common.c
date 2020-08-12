// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2020 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <linux/errqueue.h>
#include <linux/netlink.h>
#include <linux/net_tstamp.h>
#include <linux/socket.h>

#include "isobusfs.h"

static const char *isobusfs_error_to_str(enum isobusfs_error err)
{
	switch (err) {
	case ISOBUSFS_ERR_ACCESS_DENIED:
		return "Access Denied";
	case ISOBUSFS_ERR_INVALID_ACCESS:
		return "Invalid Access";
	case ISOBUSFS_ERR_TOO_MANY_FILES_OPEN:
		return "Too many files open";
	case ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND:
		return "File or path not found";
	case ISOBUSFS_ERR_INVALID_HANDLE:
		return "Invalid handle";
	case ISOBUSFS_ERR_INVALID_SRC_NAME:
		return "Invalid given source name";
	case ISOBUSFS_ERR_INVALID_DST_NAME:
		return "Invalid given destination name";
	case ISOBUSFS_ERR_NO_SPACE:
		return "Volume out of free space";
	case ISOBUSFS_ERR_ON_WRITE:
		return "Failure during a write operation";
	case ISOBUSFS_ERR_VOLUME_NOT_INITIALIZED:
		return "Volume is possibly not initialized";
	case ISOBUSFS_ERR_ON_READ:
		return "Failure during a read operation";
	case ISOBUSFS_ERR_FUNC_NOT_SUPPORTED:
		return "Function not supported";
	case ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT:
		return "Invalid request length";
	case ISOBUSFS_ERR_OUT_OF_MEM:
		return "Out of memory";
	case ISOBUSFS_ERR_OTHER:
		return "Any other error";
	case ISOBUSFS_ERR_END_OF_FILE:
		return "End of file reached, will only be reported when file pointer is at end of file";
	default:
		return "<unknown>";
	}
}

void isobusfs_init_sockaddr_can(struct sockaddr_can *sac, uint32_t pgn)
{
	sac->can_family = AF_CAN;
	sac->can_addr.j1939.addr = J1939_NO_ADDR;
	sac->can_addr.j1939.name = J1939_NO_NAME;
	sac->can_addr.j1939.pgn = pgn;
}

static int isobusfs_buf_to_cmd(uint8_t *buf)
{
	return (buf[0] & 0xf0) >> 4;
}

static int isobusfs_buf_to_function(uint8_t *buf)
{
	return (buf[0] & 0xf);
}

static uint8_t isobusfs_cmd_function_to_buf(uint8_t cmd, uint8_t func)
{
	return (func & 0xf) | ((cmd & 0xf) << 4);
}

static ssize_t isobusfs_cl_send(struct isobusfs_priv *priv,
				const void *buf, size_t buf_size)
{
	ssize_t num_sent;
	int flags = 0;

	flags |= MSG_DONTWAIT;

	num_sent = send(priv->sock, buf, buf_size, flags);

	if (num_sent > (ssize_t)buf_size) /* Should never happen */ {
		warn("%s: send more then read", __func__);
		return -EINVAL;
	}

	return num_sent;
}

static ssize_t isobusfs_ser_sendto(struct isobusfs_priv *priv,
			       struct isobusfs_msg *msg,
			       const void *buf, size_t buf_size)
{
	ssize_t num_sent;
	int flags = 0;

	flags |= MSG_DONTWAIT;

	priv->peername.can_addr.j1939.addr = msg->peername.can_addr.j1939.addr;

	num_sent = sendto(priv->sock, buf, buf_size, flags,
			  (struct sockaddr *)&priv->peername,
			   sizeof(priv->peername));

	if (num_sent > (ssize_t)buf_size) /* Should never happen */ {
		warn("%s: send more then read", __func__);
		return -EINVAL;
	}

	return num_sent;
}


static int isobusfs_ser_send_error(struct isobusfs_priv *priv,
				   struct isobusfs_msg *msg,
				   enum isobusfs_error err)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	/* copy 2 bytes with command group, function and TAN from the source
	 * package */
	memcpy(buf, &msg->buf[0], 2);
	buf[2] = err;

	ret = isobusfs_ser_sendto(priv, msg, &buf[0], ARRAY_SIZE(buf));
	if (ret < 0)
		return ret;

	return 0;
}

static int isobusfs_ser_property_res(struct isobusfs_priv *priv,
				     struct isobusfs_msg *msg)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	buf[0] = isobusfs_cmd_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					      ISOBUSFS_CM_GET_FS_PROPERTIES_RES);
	/* Version number:
	 * 0 - Draft
	 * 1 - Final draft
	 * 2 - First published version
	 */
	buf[1] = 2;
	/* Maximum Number of Simultaneously Open Files */
	buf[2] = ISOBUSFS_MAX_OPENED_FILES;
	/* File Server Capabilities */
	// TODO: set proper caps
	buf[3] = 0;

	ret = isobusfs_ser_sendto(priv, msg, &buf[0], ARRAY_SIZE(buf));
	if (ret < 0)
		return ret;

	return 0;
}

/* Command group: connection management */
static int isobusfs_ser_rx_cg_cm(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_CM_GET_FS_PROPERTIES:
		ret = isobusfs_ser_property_res(priv, msg);
		break;
	default:
		ret = isobusfs_ser_send_error(priv, msg,
					      ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

/* Command group: directory handling */
static int isobusfs_ser_rx_cg_dh(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ:
		break;
	case ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ:
		break;
	default:
		ret = isobusfs_ser_send_error(priv, msg,
					      ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

/* Command group: file access */
static int isobusfs_ser_rx_cg_fa(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FA_F_OPEN_FILE_REQ:
		break;
	case ISOBUSFS_FA_F_SEEK_FILE_REQ:
		break;
	case ISOBUSFS_FA_F_READ_FILE_REQ:
		break;
	case ISOBUSFS_FA_F_WRITE_FILE_REQ:
		break;
	case ISOBUSFS_FA_F_CLOSE_FILE_REQ:
		break;
	default:
		ret = isobusfs_ser_send_error(priv, msg,
					      ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

/* Command group: file handling */
static int isobusfs_ser_rx_cg_fh(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FH_F_MOVE_FILE_REQ:
		break;
	case ISOBUSFS_FH_F_DELETE_FILE_REQ:
		break;
	case ISOBUSFS_FH_F_GET_FILE_ATTR_REQ:
		break;
	case ISOBUSFS_FH_F_SET_FILE_ATTR_REQ:
		break;
	case ISOBUSFS_FH_F_GET_FILE_DATETIME_REQ:
		break;
	default:
		ret = isobusfs_ser_send_error(priv, msg,
					      ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

/* Command group: volume hnadling */
static int isobusfs_ser_rx_cg_vh(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_VA_F_INITIALIZE_VOLUME_REQ:
		break;
	default:
		ret = isobusfs_ser_send_error(priv, msg,
					      ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

/* server side rx */
int isobusfs_ser_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	int cmd = isobusfs_buf_to_cmd(msg->buf);
	int ret = 0;

	switch (cmd) {
	case ISOBUSFS_CG_CONNECTION_MANAGMENT:
		ret = isobusfs_ser_rx_cg_cm(priv, msg);
		break;
	case ISOBUSFS_CG_DIRECTORY_HANDLING:
		ret = isobusfs_ser_rx_cg_dh(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_ACCESS:
		ret = isobusfs_ser_rx_cg_fa(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_HANDLING:
		ret = isobusfs_ser_rx_cg_fh(priv, msg);
		break;
	case ISOBUSFS_CG_VOLUME_HANDLING:
		ret = isobusfs_ser_rx_cg_vh(priv, msg);
		break;
	default:
		warn("%s: unsupported command: %i", __func__, cmd);
		return -EINVAL;
	}

	return ret;
}

/* client side rx */

static int isobusfs_cl_property_res(struct isobusfs_priv *priv,
				     struct isobusfs_msg *msg)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	warn("%s: got resposne", __func__);
	return 0;
}

/* Command group: connection management */
static int isobusfs_cl_rx_cg_cm(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_CM_GET_FS_PROPERTIES:
		ret = isobusfs_cl_property_res(priv, msg);
		break;
	default:
		warn("%s: unsupported function: %i", __func__, func);
		return -EINVAL;
	}

	return ret;
}

int isobusfs_cl_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	int cmd = isobusfs_buf_to_cmd(msg->buf);
	int ret = 0;

	switch (cmd) {
	case ISOBUSFS_CG_CONNECTION_MANAGMENT:
		ret = isobusfs_cl_rx_cg_cm(priv, msg);
		break;
	case ISOBUSFS_CG_DIRECTORY_HANDLING:
		ret = isobusfs_ser_rx_cg_dh(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_ACCESS:
		ret = isobusfs_ser_rx_cg_fa(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_HANDLING:
		ret = isobusfs_ser_rx_cg_fh(priv, msg);
		break;
	case ISOBUSFS_CG_VOLUME_HANDLING:
		ret = isobusfs_ser_rx_cg_vh(priv, msg);
		break;
	default:
		warn("%s: unsupported command: %i", __func__, cmd);
		return -EINVAL;
	}

	return ret;
}

/* client tx side */

int isobusfs_cl_property_req(struct isobusfs_priv *priv)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	buf[0] = isobusfs_cmd_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					      ISOBUSFS_CM_GET_FS_PROPERTIES);

	ret = isobusfs_cl_send(priv, &buf[0], ARRAY_SIZE(buf));
	if (ret < 0)
		return ret;

	return 0;
}
