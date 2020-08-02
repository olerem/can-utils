// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/net_tstamp.h>

#include "isobusfs_srv.h"

static const char help_msg[] =
	"isobusfsd: netcat-like tool for j1939\n"
	"Usage: isobusfsd [options] FROM TO\n"
	" FROM / TO	- or [IFACE][:[SA][,[PGN][,NAME]]]\n"
	"Options:\n"
	"\n"
	"Example:\n"
	"isobusfsd -i some_file_to_send  can0:0x80 :0x90,0x12300\n"
	"isobusfsd can0:0x90 -r > /tmp/some_file_to_receive\n"
	"\n"
	;

static const char optstring[] = "?:d:";

int isobusfs_srv_sendto(struct isobusfs_srv_priv *priv,
			struct isobusfs_msg *msg, const void *buf,
			size_t buf_size)
{
	ssize_t num_sent;
	int flags = 0;

	flags |= MSG_DONTWAIT;

	/* TODO: if client is registered, use separate client socket */
	if (0)
		num_sent = send(msg->sock, buf, buf_size, flags);
	else {
		struct sockaddr_can addr = msg->peername;

		addr.can_addr.j1939.pgn = ISOBUSFS_PGN_FS_TO_CL;
		num_sent = isobusfs_sendto(msg->sock, buf, buf_size, &addr,
					   &priv->tx_buf_log);
	}
	if (num_sent < 0) {
		warn("%s: sendto", __func__);
		return -errno;
	}

	if (num_sent > (ssize_t)buf_size) /* Should never happen */ {
		pr_warn("%s: send more then read", __func__);
		return -EINVAL;
	}

	/* TODO: currently it is naive implementation. We do not care about
	 * retries or sending more than socket can handle.
	 */
	if (num_sent != (ssize_t)buf_size) {
		pr_warn("%s: send less as we should", __func__);
		return -EINVAL;
	}

	/* Do not return number of bytes. We care only about error value */
	return 0;
}

int isobusfs_srv_send_error(struct isobusfs_srv_priv *priv,
			    struct isobusfs_msg *msg,
			    enum isobusfs_error err)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];

	/* copy 2 bytes with command group, function and TAN from the source
	 * package */
	memcpy(buf, &msg->buf[0], 2);
	buf[2] = err;

	/* not used space should be filled with 0xff */
	memset(&buf[3], 0xff, ARRAY_SIZE(buf) - 3);

	pr_debug("> tx error: 0x%02x (%s)", err, isobusfs_error_to_str(err));

	return isobusfs_srv_sendto(priv, msg, &buf[0], ARRAY_SIZE(buf));
}

/* current directory response function */
static int isobusfs_srv_dh_current_dir_res(struct isobusfs_srv_priv *priv,
					   struct isobusfs_msg *msg)
{
	struct isobusfs_dh_get_current_dir_req *req =
		(struct isobusfs_dh_get_current_dir_req *)msg->buf;
	struct isobusfs_dh_current_dir_res res;
	char str[] = "\\some_dir";
	size_t str_len, buf_size;
	int ret;

	/* TODO: actually get current directory */
	pr_warn("TODO: get current directory");

	str_len = ARRAY_SIZE(str);
	buf_size = sizeof(res) - sizeof(res.path_name) + str_len;

	if (buf_size > ISOBUSFS_MAX_TRANSFER_LENGH) {
		pr_warn("current directory response too long");
		return -EINVAL;
	}

	res.fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
					      ISOBUSFS_DH_F_GET_CURRENT_DIR_RES);
	res.tan = req->tan;
	res.total_space = 0;
	res.free_space = 0;
	res.path_name_length = str_len;
	// TODO: add sanity check for str not to be longer than max path name
	memcpy(res.path_name, str, str_len);

	/* send to socket */
	ret = isobusfs_srv_sendto(priv, msg, &res, buf_size);
	if (ret < 0) {
		pr_warn("can't send current directory response");
		return ret;
	}

	pr_debug("> tx current directory response");
	return 0;
}

/* Command group: directory handling */
static int isobusfs_srv_rx_cg_dh(struct isobusfs_srv_priv *priv,
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

/* Command group: file access */
static int isobusfs_srv_rx_cg_fa(struct isobusfs_srv_priv *priv,
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

/* Command group: file handling */
static int isobusfs_srv_rx_cg_fh(struct isobusfs_srv_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_FH_F_MOVE_FILE_REQ:
	case ISOBUSFS_FH_F_DELETE_FILE_REQ:
	case ISOBUSFS_FH_F_GET_FILE_ATTR_REQ:
	case ISOBUSFS_FH_F_SET_FILE_ATTR_REQ:
	case ISOBUSFS_FH_F_GET_FILE_DATETIME_REQ:
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

/* Command group: volume hnadling */
static int isobusfs_srv_rx_cg_vh(struct isobusfs_srv_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_VA_F_INITIALIZE_VOLUME_REQ: /* fall through */
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

/* server side rx */
static int isobusfs_srv_rx_fs(struct isobusfs_srv_priv *priv,
			      struct isobusfs_msg *msg)
{
	enum isobusfs_cg cg = isobusfs_buf_to_cmd(msg->buf);
	int ret = 0;

	pr_debug("< rx: cg: %i, func: %i", cg,
		 isobusfs_buf_to_function(msg->buf));

	switch (cg) {
	case ISOBUSFS_CG_CONNECTION_MANAGMENT:
		ret = isobusfs_srv_rx_cg_cm(priv, msg);
		break;
	case ISOBUSFS_CG_DIRECTORY_HANDLING:
		ret = isobusfs_srv_rx_cg_dh(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_ACCESS:
		ret = isobusfs_srv_rx_cg_fa(priv, msg);
		break;
	case ISOBUSFS_CG_FILE_HANDLING:
		ret = isobusfs_srv_rx_cg_fh(priv, msg);
		break;
	case ISOBUSFS_CG_VOLUME_HANDLING:
		ret = isobusfs_srv_rx_cg_vh(priv, msg);
		break;
	default:
		goto not_supported;
	}

	return ret;

not_supported:
	pr_warn("%s: unsupported command group (%i)", __func__,
	      cg);

        /* ISO 11783-13:2021 - Annex C.1.1 Overview:
         * If a client sends a command, which is not defined withing this
	 * documentation, the file server shall respond with a
	 * NACK (ISO 11783-3:2018 Chapter 5.4.5)
         */
	isobusfs_send_nack(msg->sock, msg, priv->addr.can_addr.j1939.addr);

	/* Not a critical error */
	return 0;
}

static int isobusfs_srv_rx_ack(struct isobusfs_srv_priv *priv,
			       struct isobusfs_msg *msg)
{
	enum isobusfs_ack_ctrl ctrl = msg->buf[0];

	switch (ctrl) {
	case ISOBUS_ACK_CTRL_ACK:
		pr_debug("< rx: ACK?????");
		break;
	case ISOBUS_ACK_CTRL_NACK:
		/* we did something wrong */
		pr_debug("< rx: NACK!!!!!");
		isobusfs_dump_tx_data(&priv->tx_buf_log);
		break;
	default:
		pr_warn("%s: unsupported ACK control: %i", __func__, ctrl);
		return -EINVAL;
	}

	/* Not a critical error */
	return 0;
}

static int isobusfs_srv_rx_buf(struct isobusfs_srv_priv *priv, struct isobusfs_msg *msg)
{
	pgn_t pgn = msg->peername.can_addr.j1939.pgn;
	int ret;

	switch (pgn) {
	case ISOBUSFS_PGN_CL_TO_FS:
		ret = isobusfs_srv_rx_fs(priv, msg);
		break;
	case ISOBUS_PGN_ACK:
		ret = isobusfs_srv_rx_ack(priv, msg);
		break;
	default:
		pr_warn("%s: unsupported PGN: %i", __func__, pgn);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int isobusfs_srv_recv_one(struct isobusfs_srv_priv *priv, int sock)
{
	struct isobusfs_msg *msg;
	int flags = 0;
	int ret;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		pr_err("can't allocate rx msg struct");
		goto done;
	}
	msg->buf_size = ISOBUSFS_MAX_TRANSFER_LENGH;
	msg->peer_addr_len = sizeof(msg->peername);
	msg->sock = sock;

	ret = recvfrom(sock, &msg->buf[0], msg->buf_size, flags,
		       (struct sockaddr *)&msg->peername, &msg->peer_addr_len);
	if (ret < 0) {
		pr_err("recvfrom(): %i (%s)", errno, strerror(errno));
		goto free_msg;
	}

	if (ret < ISOBUSFS_MIN_TRANSFER_LENGH) {
		pr_warn("buf is less then min transfer: %i < %i. Dropping.",
			ret, ISOBUSFS_MIN_TRANSFER_LENGH);

		isobusfs_send_nack(sock, msg, priv->addr.can_addr.j1939.addr);

		goto free_msg;
	}

	/* TODO: handle transfer more then allowed */
	msg->len = ret;

	ret = isobusfs_srv_rx_buf(priv, msg);
	if (ret < 0) {
		pr_err("unhandled error by rx buf: %i", ret);
		goto free_msg;
	}

free_msg:
	free(msg);
done:
	return EXIT_SUCCESS;
}

static int isobusfs_srv_go(struct isobusfs_srv_priv *priv)
{
	int ret, timeout_ms, nfds, n;

	timeout_ms = isobusfs_get_timeout_ms(&priv->st_next_send_time);
	nfds = epoll_wait(priv->epoll_fd, priv->epoll_events,
			  ARRAY_SIZE(priv->epoll_events), timeout_ms);
	if (nfds < 0 && nfds != -EINTR) {
		perror("epoll_wait failed");
		return -errno;
	}

	ret = clock_gettime(CLOCK_MONOTONIC, &priv->last_time);
	if (ret < 0) {
		warn("clock_gettime");
		return EXIT_FAILURE;
	}

	if (nfds <= 0) {
		/* timeout or -EINTR */
		goto send_status;
	}

	for (n = 0; n < nfds; ++n) {
		struct epoll_event *ev = &priv->epoll_events[n];

		if (!ev->events) {
			warn("no events");
			continue;
		}

		if (ev->data.fd == priv->ctrl_sock) {
			if (ev->events & POLLERR) {
				struct isobusfs_err_msg emsg = {
					.stats = &priv->st_msg_stats,
				};

				ret = isobusfs_recv_err(priv->ctrl_sock, &emsg);
				if (ret && ret != -EINTR) {
					pr_warn("Error receiving error message");
					return ret;
				}
			}
		} else {
			warn("unknown fd %d", ev->data.fd);
		}

		if (ev->events & POLLIN) {
			ret = isobusfs_srv_recv_one(priv, ev->data.fd);
			if (ret) {
				warn("Error receiving message");
				return ret;
			}
		}
	}

send_status:
	/* remove timeouted clients */
	isobusfs_srv_remove_timeouted_clients(priv);

	/* this function will send status only if it is proper time to do so */
	return isobusfs_srv_fss_send(priv);
}

/**********************************************************/

/**
 * isobusfs_srv_open_socket - Opens a J1939 socket
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Stores the socket file descriptor in priv->ctrl_sock.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_open_socket(struct isobusfs_srv_priv *priv)
{
	int ret;

	priv->ctrl_sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (priv->ctrl_sock < 0) {
		ret = -errno;
		pr_err("socket(j1939): %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_configure_socket_filter - Configures the socket filter
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Configures the socket filter to ignore non-broadcasted messages.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_configure_socket_filter(struct isobusfs_srv_priv *priv)
{
	struct j1939_filter ctrl_filt[] = {
		{
			.pgn = ISOBUSFS_PGN_CL_TO_FS,
			.pgn_mask = J1939_PGN_PDU1_MAX,
		}, {
			.pgn = ISOBUS_PGN_ACK,
			.pgn_mask = J1939_PGN_PDU1_MAX,
		},
	};
	int ret;

	ret = setsockopt(priv->ctrl_sock, SOL_CAN_J1939, SO_J1939_FILTER,
					 &ctrl_filt, sizeof(ctrl_filt));
	if (ret < 0) {
		ret = errno;
		pr_err("failed to set j1939 filter: %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_configure_error_queue - Configures the error queue
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Configures the error queue for the socket.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_configure_error_queue(struct isobusfs_srv_priv *priv)
{
	int err_queue = true;
	int ret;

	ret = setsockopt(priv->ctrl_sock, SOL_CAN_J1939, SO_J1939_ERRQUEUE,
					 &err_queue, sizeof(err_queue));
	if (ret < 0) {
		ret = errno;
		pr_err("set recverr: %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_configure_timestamping - Configures socket timestamping
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Configures the socket timestamping options.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_configure_timestamping(struct isobusfs_srv_priv *priv)
{
	unsigned int sock_opt;
	int ret;

	sock_opt = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_OPT_CMSG |
		   SOF_TIMESTAMPING_TX_ACK | SOF_TIMESTAMPING_TX_SCHED |
		   SOF_TIMESTAMPING_OPT_STATS | SOF_TIMESTAMPING_OPT_TSONLY |
		   SOF_TIMESTAMPING_OPT_ID;

	ret = setsockopt(priv->ctrl_sock, SOL_SOCKET, SO_TIMESTAMPING,
					 (char *)&sock_opt, sizeof(sock_opt));
	if (ret < 0) {
		ret = errno;
		pr_err("setsockopt timestamping: %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_bind_socket - Binds the socket to the specified address
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Binds the socket to the address specified in the priv->addr structure.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_bind_socket(struct isobusfs_srv_priv *priv)
{
	int ret;

	ret = bind(priv->ctrl_sock, (void *)&priv->addr, sizeof(priv->addr));
	if (ret < 0) {
		ret = errno;
		pr_err("bind(): %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_set_broadcast - Sets the SO_BROADCAST socket option
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Sets the SO_BROADCAST socket option for the control socket.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_set_broadcast(struct isobusfs_srv_priv *priv)
{
	int broadcast = true;
	int ret;

	ret = setsockopt(priv->ctrl_sock, SOL_SOCKET, SO_BROADCAST, &broadcast,
					 sizeof(broadcast));
	if (ret < 0) {
		ret = errno;
		pr_err("setsockopt(SO_BROADCAST): %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_create_epoll - Creates an epoll instance
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Creates an epoll instance and stores its file descriptor in priv->epoll_fd.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_create_epoll(struct isobusfs_srv_priv *priv)
{
	int ret;

	priv->epoll_fd = epoll_create1(0);
	if (priv->epoll_fd < 0) {
		ret = errno;
		pr_err("epoll_create1: %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_add_socket_to_epoll - Adds the control socket to the epoll instance
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * Adds the control socket to the epoll instance for monitoring events.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_add_socket_to_epoll(struct isobusfs_srv_priv *priv)
{
	struct epoll_event ev;
	int ret;

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = priv->ctrl_sock;

	ret = epoll_ctl(priv->epoll_fd, EPOLL_CTL_ADD, priv->ctrl_sock, &ev);
	if (ret < 0) {
		ret = errno;
		pr_err("epoll_ctl(EPOLL_CTL_ADD): %d (%s)", ret, strerror(ret));
		return ret;
	}
	return 0;
}

/**
 * isobusfs_srv_sock_prepare - Prepares the control socket and epoll instance
 * @priv: pointer to the isobusfs_srv_priv structure
 *
 * This function calls multiple helper functions to prepare the control socket
 * and epoll instance for the ISOBUS server.
 * Returns: 0 on success, negative error code on failure
 */
static int isobusfs_srv_sock_prepare(struct isobusfs_srv_priv *priv)
{
	int ret;

	ret = isobusfs_srv_open_socket(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_configure_socket_filter(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_configure_error_queue(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_configure_timestamping(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_bind_socket(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_set_broadcast(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_create_epoll(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_srv_add_socket_to_epoll(priv);
	if (ret < 0)
		return ret;

	return 0;
}

static int isobusfs_srv_parse_args(struct isobusfs_srv_priv *priv, int argc,
				char *argv[])
{
	int opt, level;

	/* argument parsing */
	while ((opt = getopt(argc, argv, optstring)) != -1)
		switch (opt) {
		case 'h': /* fallthroug */
		case 'd':
			level = strtoul(optarg, NULL, 0);
			if (level < LOG_LEVEL_ERROR || level > LOG_LEVEL_DEBUG)
				errx(EXIT_FAILURE, "invalid debug level %d",
				     level);
			isobusfs_log_level_set(level);
			break;
		default:
			fputs(help_msg, stderr);
			return EXIT_FAILURE;
		}

	if (argv[optind]) {
		if (strcmp("-", argv[optind]))
			 libj1939_parse_canaddr(argv[optind], &priv->addr);
		optind++;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	struct isobusfs_srv_priv *priv;
	struct timespec ts;
	int ret;

	/* Allocate memory for the private structure */
	priv = malloc(sizeof(*priv));
	if (!priv)
		err(EXIT_FAILURE, "can't allocate priv");

	/* Clear memory for the private structure */
	memset(priv, 0, sizeof(*priv));

	/* Initialize sockaddr_can with a non-configurable PGN */
	isobusfs_init_sockaddr_can(&priv->addr, J1939_NO_PGN);

	/* Parse command line arguments */
	ret = isobusfs_srv_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	/* Prepare sockets for the server */
	ret = isobusfs_srv_sock_prepare(priv);
	if (ret)
		return ret;

	/* Initialize File Server Status structure */
	isobusfs_srv_fss_init(priv);
	/* Initialize client structures */
	isobusfs_srv_init_clients(priv);

	/* Init next st_next_send_time value to avoid warnings */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	priv->st_next_send_time = ts;

	/* Start the isobusfsd server */
	pr_info("Starting isobusfsd");
	while (1) {
		ret = isobusfs_srv_go(priv);
		if (ret)
			break;
	}

	/* Close epoll and control sockets */
	close(priv->epoll_fd);
	close(priv->ctrl_sock);
	return ret;
}
