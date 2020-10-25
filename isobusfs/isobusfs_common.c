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

static ssize_t isobusfs_send_one(struct isobusfs_priv *priv,
				  const void *buf, size_t buf_size)
{
	ssize_t num_sent;
	int flags = 0;

	if (priv->polltimeout)
		flags |= MSG_DONTWAIT;

	if (priv->valid_peername)
		num_sent = sendto(priv->sock, buf, buf_size, flags,
				  (struct sockaddr *)&priv->peername,
				  sizeof(priv->peername));
	else
		num_sent = send(priv->sock, buf, buf_size, flags);

	if (num_sent == -1) {
		warn("%s: transfer error: %i", __func__, -errno);
		return -errno;
	}

	if (num_sent == 0) /* Should never happen */ {
		warn("%s: transferred 0 bytes", __func__);
		return -EINVAL;
	}

	if (num_sent > (ssize_t)buf_size) /* Should never happen */ {
		warn("%s: send more then read", __func__);
		return -EINVAL;
	}

	return num_sent;
}

static void isobusfs_print_timestamp(struct isobusfs_priv *priv, const char *name,
			      struct timespec *cur)
{
	struct isobusfs_stats *stats = &priv->stats;

	if (!(cur->tv_sec | cur->tv_nsec))
		return;

	fprintf(stderr, "  %s: %lu s %lu us (seq=%u, send=%u)",
			name, cur->tv_sec, cur->tv_nsec / 1000,
			stats->tskey, stats->send);

	fprintf(stderr, "\n");
}

static const char *isobusfs_tstype_to_str(int tstype)
{
	switch (tstype) {
	case SCM_TSTAMP_SCHED:
		return "  ENQ";
	case SCM_TSTAMP_SND:
		return "  SND";
	case SCM_TSTAMP_ACK:
		return "  ACK";
	default:
		return "  unk";
	}
}

/* Check the stats of SCM_TIMESTAMPING_OPT_STATS */
static void isobusfs_scm_opt_stats(struct isobusfs_priv *priv, void *buf, int len)
{
	struct isobusfs_stats *stats = &priv->stats;
	int offset = 0;

	while (offset < len) {
		struct nlattr *nla = (struct nlattr *) ((char *)buf + offset);

		switch (nla->nla_type) {
		case J1939_NLA_BYTES_ACKED:
			stats->send = *(uint32_t *)((char *)nla + NLA_HDRLEN);
			break;
		default:
			warnx("not supported J1939_NLA field\n");
		}

		offset += NLA_ALIGN(nla->nla_len);
	}
}

static int isobusfs_extract_serr(struct isobusfs_priv *priv)
{
	struct isobusfs_stats *stats = &priv->stats;
	struct sock_extended_err *serr = priv->serr;
	struct scm_timestamping *tss = priv->tss;

	switch (serr->ee_origin) {
	case SO_EE_ORIGIN_TIMESTAMPING:
		/*
		 * We expect here following patterns:
		 *   serr->ee_info == SCM_TSTAMP_ACK
		 *     Activated with SOF_TIMESTAMPING_TX_ACK
		 * or
		 *   serr->ee_info == SCM_TSTAMP_SCHED
		 *     Activated with SOF_TIMESTAMPING_SCHED
		 * and
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 * the serr->ee_errno should be ENOMSG
		 */
		if (serr->ee_errno != ENOMSG)
			warnx("serr: expected ENOMSG, got: %i",
			      serr->ee_errno);
		stats->tskey = serr->ee_data;

		isobusfs_print_timestamp(priv, isobusfs_tstype_to_str(serr->ee_info),
				     &tss->ts[0]);

		if (serr->ee_info == SCM_TSTAMP_SCHED)
			return -EINTR;
		else
			return 0;
	case SO_EE_ORIGIN_LOCAL:
		/*
		 * The serr->ee_origin == SO_EE_ORIGIN_LOCAL is
		 * currently used to notify about locally
		 * detected protocol/stack errors.
		 * Following patterns are expected:
		 *   serr->ee_info == J1939_EE_INFO_TX_ABORT
		 *     is used to notify about session TX
		 *     abort.
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 *   serr->ee_errno == actual error reason
		 *     error reason is converted from J1939
		 *     abort to linux error name space.
		 */
		if (serr->ee_info != J1939_EE_INFO_TX_ABORT)
			warnx("serr: unknown ee_info: %i",
			      serr->ee_info);

		isobusfs_print_timestamp(priv, "  ABT", &tss->ts[0]);
		warnx("serr: tx error: %i, %s", serr->ee_errno, strerror(serr->ee_errno));

		return serr->ee_errno;
	default:
		warnx("serr: wrong origin: %u", serr->ee_origin);
	}

	return 0;
}

static int isobusfs_parse_cm(struct isobusfs_priv *priv, struct cmsghdr *cm)
{
	const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));

	if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
		priv->tss = (void *)CMSG_DATA(cm);
	} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS) {
		void *jstats = (void *)CMSG_DATA(cm);

		/* Activated with SOF_TIMESTAMPING_OPT_STATS */
		isobusfs_scm_opt_stats(priv, jstats, cm->cmsg_len - hdr_len);
	} else if (cm->cmsg_level == SOL_CAN_J1939 &&
		   cm->cmsg_type == SCM_J1939_ERRQUEUE) {
		priv->serr = (void *)CMSG_DATA(cm);
	} else
		warnx("serr: not supported type: %d.%d",
		      cm->cmsg_level, cm->cmsg_type);

	return 0;
}

static int isobusfs_recv_err(struct isobusfs_priv *priv)
{
	char control[200];
	struct cmsghdr *cm;
	int ret;
	struct msghdr msg = {
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};

	ret = recvmsg(priv->sock, &msg, MSG_ERRQUEUE);
	if (ret == -1)
		err(EXIT_FAILURE, "recvmsg error notification: %i", errno);
	if (msg.msg_flags & MSG_CTRUNC)
		err(EXIT_FAILURE, "recvmsg error notification: truncated");

	priv->serr = NULL;
	priv->tss = NULL;

	for (cm = CMSG_FIRSTHDR(&msg); cm && cm->cmsg_len;
	     cm = CMSG_NXTHDR(&msg, cm)) {
		isobusfs_parse_cm(priv, cm);
		if (priv->serr && priv->tss)
			return isobusfs_extract_serr(priv);
	}

	return 0;
}



static int isobusfs_send(struct isobusfs_priv *priv, uint8_t *buf,
			  size_t buf_size)
{
	struct isobusfs_stats *stats = &priv->stats;
	ssize_t count;
	char *tmp_buf = buf;
	unsigned int events = POLLOUT | POLLERR;
	bool tx_done = false;

	count = buf_size;

	while (!tx_done) {
		ssize_t num_sent = 0;

		if (priv->polltimeout) {
			struct pollfd fds = {
				.fd = priv->sock,
				.events = events,
			};
			int ret;

			ret = poll(&fds, 1, priv->polltimeout);
			if (ret == -EINTR)
				continue;
			else if (ret < 0)
				return -errno;
			else if (!ret)
				return -ETIME;

			if (!(fds.revents & events)) {
				warn("%s: something else is wrong", __func__);
				return -EIO;
			}

			if (fds.revents & POLLERR) {
				ret = isobusfs_recv_err(priv);
				if (ret == -EINTR)
					continue;
				else if (ret)
					return ret;
				else if ((priv->repeat - 1) == stats->tskey)
					tx_done = true;

			}

			if (fds.revents & POLLOUT) {
				num_sent = isobusfs_send_one(priv, tmp_buf, count);
				if (num_sent < 0)
					return num_sent;
			}
		} else {
			num_sent = isobusfs_send_one(priv, tmp_buf, count);
			if (num_sent < 0)
				return num_sent;
		}

		count -= num_sent;
		tmp_buf += num_sent;
		if (buf + buf_size < tmp_buf + count) {
			warn("%s: send buffer is bigger than the read buffer",
			     __func__);
			return -EINVAL;
		}
		if (!count)
			tx_done = true;
	}
	return 0;
}

static int isobusfs_cl_recv_one(struct isobusfs_priv *priv,
			      struct isobusfs_msg *msg)
{
	int ret;

	int flags = 0;

	//flags |= MSG_DONTWAIT;

	warn("%s:%i", __func__, __LINE__);
	ret = recvfrom(priv->sock, &msg->buf[0], msg->buf_size, flags,
		       (struct sockaddr *)&msg->peername, &msg->peer_addr_len);

	warn("%s:%i", __func__, __LINE__);
	if (ret < 0) {
		warn("recvfrom()");
		return EXIT_FAILURE;
	}

	if (ret < ISOBUSFS_MIN_TRANSFER_LENGH) {
		warn("buf is less then min transfer: %i", ret);
		return EXIT_FAILURE;
	}

	/* TODO: handle transfer more then allowed */

	warn("%s:%i", __func__, __LINE__);
	ret = isobusfs_cl_rx_buf(priv, msg);
	if (ret < 0) {
		warn("process buffer");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int isobusfs_cl_recv(struct isobusfs_priv *priv)
{
	struct isobusfs_stats *stats = &priv->stats;
	unsigned int events = POLLIN | POLLERR;
	struct isobusfs_msg *msg;
	int ret = EXIT_SUCCESS;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		warn("can't allocate rx msg struct");
		return EXIT_FAILURE;;
	}
	msg->buf_size = ISOBUSFS_MAX_TRANSFER_LENGH;
	msg->peer_addr_len = sizeof(msg->peername);

	while (priv->todo_recv) {
		struct pollfd fds = {
			.fd = priv->sock,
			.events = events,
		};
		int ret;

		ret = poll(&fds, 1, priv->polltimeout);
		if (ret == -EINTR)
			continue;
		else if (ret < 0)
			return -errno;
		else if (!ret)
			return -ETIME;

		if (!(fds.revents & events)) {
			warn("%s: something else is wrong", __func__);
			return -EIO;
		}

		if (fds.revents & POLLERR) {
			ret = isobusfs_recv_err(priv);
			if (ret == -EINTR)
				continue;
			else if (ret)
				return ret;
		}

		if (fds.revents & POLLIN) {
			/* ignore errors? */
			isobusfs_cl_recv_one(priv, msg);
		}

#if 0
		if (fds.revents & POLLOUT) {
			num_sent = isobusfs_client_send_one(priv, priv->sock, tmp_buf, count);
			if (num_sent < 0)
				return num_sent;
		}
#endif
	}

	free(msg);
	return ret;
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

static int isobusfs_ser_dh_get_cur_dir(struct isobusfs_priv *priv,
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

static int isobusfs_ser_dh_set_cur_dir(struct isobusfs_priv *priv,
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

/* Command group: directory handling */
static int isobusfs_ser_rx_cg_dh(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ:
		ret = isobusfs_ser_dh_get_cur_dir(priv, msg);
		break;
	case ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ:
		ret = isobusfs_ser_dh_set_cur_dir(priv, msg);
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
/* Get File Server Properties Request */
int isobusfs_cl_property_req(struct isobusfs_priv *priv)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	buf[0] = isobusfs_cmd_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					      ISOBUSFS_CM_GET_FS_PROPERTIES);

	ret = isobusfs_send(priv, &buf[0], ARRAY_SIZE(buf));
	if (ret < 0)
		return ret;

	ret = isobusfs_cl_recv(priv);
	if (ret < 0)
		return ret;

	return 0;
}

/* Get Current Directory Request */
int isobusfs_cl_get_cur_dir_req(struct isobusfs_priv *priv)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	uint8_t tan;
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	buf[0] = isobusfs_cmd_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
					      ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ);
	tan = priv->tan++;

	buf[1] = tan;
	ret = isobusfs_send(priv, &buf[0], ARRAY_SIZE(buf));
	if (ret < 0)
		return ret;

	ret = isobusfs_cl_recv(priv);
	if (ret < 0)
		return ret;

	return 0;
}

