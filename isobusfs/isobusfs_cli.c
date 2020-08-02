// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>

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
#include <sys/epoll.h>
#include <time.h>

#include <linux/errqueue.h>
#include <linux/netlink.h>
#include <linux/net_tstamp.h>
#include <linux/socket.h>

#include "isobusfs_cmn.h"
#include "../libj1939.h"

static const char help_msg[] =
	"isobusfs_client: FTP like client for IsoBUS file server\n"
	"Usage: isobusfs_client [options] FROM TO\n"
	" FROM / TO	- or [IFACE][:[SA][,[PGN][,NAME]]]\n"
	"Options:\n"
	" -I		Get server information\n"
	"\n"
	"Example:\n"
	"isobusfs_client can0:0x80 can0:0x90\n"
	"\n"
	;

static const char optstring[] = "?hi:vs:rp:P:R:I";

enum isobusfs_cl_state {
	ISOBUSFS_CL_STATE_NO_FS,
	ISOBUSFS_CL_STATE_GET_FS_PROPERTIES,
	ISOBUSFS_CL_STATE_GET_CURRENT_DIR,
	ISOBUSFS_CL_STATE_GET_FILE_SIZE,
	ISOBUSFS_CL_STATE_GET_FILE,
	ISOBUSFS_CL_STATE_MAX,
};

struct isobusfs_priv {
	int sock;
	int broadcast_sock;
	int infile;
	int outfile;
	size_t max_transfer;
	unsigned long repeat;
	unsigned long round;
	int prio;
	int epoll_fd;
	struct epoll_event epoll_events[1];
	struct timespec ccm_next_send_time;
	struct isobusfs_cm_ccm ccm; /* file server status message */

	bool todo_recv;
	bool todo_filesize;
	bool todo_connect;

	unsigned long polltimeout;

	struct sockaddr_can sockname;
	struct sockaddr_can peername;

	struct sock_extended_err *serr;
	struct scm_timestamping *tss;
	struct isobusfs_stats stats;

	uint8_t tan;
	bool server;
	uint8_t cl_buf[1];

	struct timespec last_time;

	/* file server specific variables */
	bool fs_is_active;
	struct timespec fs_last_seen;
	uint8_t fs_version;
	uint8_t fs_max_open_files;
	uint8_t fs_caps;
	struct isobusfs_buf_log tx_buf_log;
	enum isobusfs_cl_state state;
};

/* ccm section */
static void isobusfs_ccm_init(struct isobusfs_priv *priv)
{
	struct isobusfs_cm_ccm *ccm = &priv->ccm;

	ccm->fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					     ISOBUSFS_CM_F_FS_STATUS);
	ccm->version = 2;
	memset(ccm->reserved, 0xFF, sizeof(ccm->reserved));
}

static int isobusfs_ccm_send(struct isobusfs_priv *priv)
{
	int64_t time_diff;
	int ret;

	/* Test if it is proper time to send next status message. */
	time_diff = isobusfs_timespec_diff_ms(&priv->ccm_next_send_time,
					      &priv->last_time);
	if (time_diff > ISOBUSFS_CM_F_FS_STATUS_RATE_JITTER) {
		/* too early to send next message */
		return EXIT_SUCCESS;
	}

	if (time_diff < -ISOBUSFS_CM_F_FS_STATUS_RATE_JITTER) {
		pr_warn("too late to send next fs status message: %ld ms",
		      time_diff);
	}

	/* Make sure we send the message with the latest stats */
	if (priv->stats.tskey_sch != priv->stats.tskey_ack)
		pr_warn("previous message was not acked");

	/* send periodic file servers status messages. */
	ret = isobusfs_send(priv->sock, &priv->ccm, sizeof(priv->ccm),
			    &priv->tx_buf_log);
	if (ret < 0) {
		pr_err("sendto() failed: %d (%s)", errno, strerror(errno));
		return EXIT_FAILURE;
	}

	pr_debug("> tx: ccm version: %d", priv->ccm.version);

	priv->ccm_next_send_time = priv->last_time;
	isobusfs_timespec_add_ms(&priv->ccm_next_send_time, 2000);

	return EXIT_SUCCESS;
}

/* detect if FS is timeout */
static void isobusfs_fs_detect_timeout(struct isobusfs_priv *priv)
{
	int64_t time_diff;

	if (!priv->fs_is_active)
		return;

	time_diff = isobusfs_timespec_diff_ms(&priv->last_time,
					      &priv->fs_last_seen);
	if (time_diff > ISOBUSFS_FS_TIMEOUT) {
		pr_debug("file server timeout");
		priv->fs_is_active = false;
		priv->state = ISOBUSFS_CL_STATE_NO_FS;
	}
}

/* activate FS status if was not active till now */
static void isobusfs_fs_activate(struct isobusfs_priv *priv)
{
	if (priv->fs_is_active)
		return;

	pr_debug("file server detectet");
	priv->fs_is_active = true;
	priv->state = ISOBUSFS_CL_STATE_GET_FS_PROPERTIES;
}

static int isobusfs_cl_rx_fs_status(struct isobusfs_priv *priv,
				     struct isobusfs_msg *msg)
{
	struct isobusfs_cm_fs_status *fs_status = (void *)msg->buf;
	int ret = 0;

	if (msg->len != sizeof(*fs_status)) {
		pr_warn("wrong message length: %d", msg->len);
		return -EINVAL;
	}

	isobusfs_fs_activate(priv);

	priv->fs_last_seen = priv->last_time;
	pr_debug("< rx: fs status: %x, opened files: %d",
	      fs_status->status, fs_status->opened_files);

	return ret;
}

/* process FS properties response */
static int isobusfs_cl_rx_fs_property_res(struct isobusfs_priv *priv,
					   struct isobusfs_msg *msg)
{
	struct isobusfs_cm_fs_properties *fs_prop = (void *)msg->buf;
	int ret = 0;

	if (msg->len != sizeof(*fs_prop)) {
		pr_warn("wrong message length: %d", msg->len);
		return -EINVAL;
	}

	priv->fs_version = fs_prop->version;
	priv->fs_max_open_files = fs_prop->max_open_files;
	priv->fs_caps = fs_prop->caps;


	pr_debug("< rx: fs properties: version: %d, max open files: %d, caps: %x",
		 priv->fs_version, priv->fs_max_open_files, priv->fs_caps);

	priv->state = ISOBUSFS_CL_STATE_GET_CURRENT_DIR;

	return ret;
}

/* Command group: connection management */
static int isobusfs_cl_rx_cg_cm(struct isobusfs_priv *priv,
				 struct isobusfs_msg *msg)
{
	int func = isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	switch (func) {
	case ISOBUSFS_CM_F_FS_STATUS:
		return isobusfs_cl_rx_fs_status(priv, msg);
	case ISOBUSFS_CM_GET_FS_PROPERTIES_RES:
		return isobusfs_cl_rx_fs_property_res(priv, msg);
	case ISOBUSFS_CM_VOLUME_STATUS_RES: /* fall through */
	default:
		pr_warn("unsupported function: %i", func);
		return -EINVAL;
	}

	return ret;
}

static int isobusfs_rx_cl(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	int cmd = isobusfs_buf_to_cmd(msg->buf);
	int ret = 0;

	switch (cmd) {
	case ISOBUSFS_CG_CONNECTION_MANAGMENT:
		ret = isobusfs_cl_rx_cg_cm(priv, msg);
		break;
	case ISOBUSFS_CG_DIRECTORY_HANDLING: /* fall through */
	case ISOBUSFS_CG_FILE_ACCESS: /* fall through */
	case ISOBUSFS_CG_FILE_HANDLING: /* fall through */
	case ISOBUSFS_CG_VOLUME_HANDLING: /* fall through */
	default:
		isobusfs_send_nack(priv->sock, msg, priv->sockname.can_addr.j1939.addr);
		pr_warn("unsupported command group: %i", cmd);
		/* Not a critical error */
		return EXIT_FAILURE;
	}

	return ret;
}

static int isobusfs_rx_ack(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	enum isobusfs_ack_ctrl ctrl = msg->buf[0];

	switch (ctrl) {
	case ISOBUS_ACK_CTRL_ACK:
		pr_debug("< rx: ACK?????");
		break;
	case ISOBUS_ACK_CTRL_NACK:
		/* we did something wrong */
		pr_debug("< rx: NACK!!!!!!");
		isobusfs_dump_tx_data(&priv->tx_buf_log);
		break;
	default:
		pr_warn("%s: unsupported ACK control: %i", __func__, ctrl);
	}

	/* Not a critical error */
	return 0;
}

static int isobusfs_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	pgn_t pgn = msg->peername.can_addr.j1939.pgn;
	int ret;

	switch (pgn) {
	case ISOBUSFS_PGN_FS_TO_CL:
		ret = isobusfs_rx_cl(priv, msg);
		break;
	case ISOBUS_PGN_ACK:
		ret = isobusfs_rx_ack(priv, msg);
		break;
	default:
		pr_warn("%s: unsupported PGN: %x", __func__, pgn);
		/* Not a critical error */
		ret = EXIT_SUCCESS;
		break;
	}

	return ret;
}

static int isobusfs_recv_one(struct isobusfs_priv *priv, int sock)
{
	struct isobusfs_msg *msg;
	int flags = 0;
	int ret;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		warn("can't allocate rx msg struct");
		return EXIT_FAILURE;;
	}
	msg->buf_size = ISOBUSFS_MAX_TRANSFER_LENGH;
	msg->peer_addr_len = sizeof(msg->peername);
	msg->sock = sock;

	ret = recvfrom(sock, &msg->buf[0], msg->buf_size, flags,
		       (struct sockaddr *)&msg->peername, &msg->peer_addr_len);

	if (ret < 0) {
		warn("recvfrom()");
		return EXIT_FAILURE;
	}

	if (ret < ISOBUSFS_MIN_TRANSFER_LENGH) {
		warn("buf is less then min transfer: %i", ret);
		isobusfs_send_nack(sock, msg, priv->sockname.can_addr.j1939.addr);
		return EXIT_FAILURE;
	}

	/* TODO: handle transfer more then allowed */
	msg->len = ret;

	ret = isobusfs_rx_buf(priv, msg);
	if (ret < 0) {
		warn("process buffer");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* actions */

static int isobusfs_cl_property_req(struct isobusfs_priv *priv)
{
	uint8_t buf[ISOBUSFS_MIN_TRANSFER_LENGH];
	int ret;

	/* not used space should be filled with 0xff */
	memset(buf, 0xff, ARRAY_SIZE(buf));
	buf[0] = isobusfs_cg_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					     ISOBUSFS_CM_GET_FS_PROPERTIES);

	/* send property request */
	ret = isobusfs_send(priv->sock, buf, sizeof(buf), &priv->tx_buf_log);
	if (ret < 0) {
		pr_err("failed to send FS properties request: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	pr_debug("> tx: FS property request");
	return EXIT_SUCCESS;
}

/* function to send current directory request */
static int isobusfs_cl_current_dir_req(struct isobusfs_priv *priv)
{
	struct isobusfs_dh_get_current_dir_req req;
	int ret;

	req.fs_function = isobusfs_cg_function_to_buf(ISOBUSFS_CG_DIRECTORY_HANDLING,
						      ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ);
	req.tan = priv->tan++;

	ret = isobusfs_send(priv->sock, &req, sizeof(req), &priv->tx_buf_log);
	if (ret < 0) {
		pr_warn("failed to send current directory request: %d (%s)",
			errno, strerror(errno));
		return ret;
	}

	pr_debug("> tx: current directory request");
	return EXIT_SUCCESS;
}

static int isobusfs_cl_action(struct isobusfs_priv *priv)
{
	int ret = 0;

	switch (priv->state) { 
	case ISOBUSFS_CL_STATE_NO_FS:
		/* nothing to do */
		break;
	case ISOBUSFS_CL_STATE_GET_FS_PROPERTIES:
		ret = isobusfs_cl_property_req(priv);
		break;
	case ISOBUSFS_CL_STATE_GET_CURRENT_DIR:
		ret = isobusfs_cl_current_dir_req(priv);
		break;
	case ISOBUSFS_CL_STATE_GET_FILE_SIZE:
		break;
	case ISOBUSFS_CL_STATE_GET_FILE:
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		return EXIT_FAILURE;
	}

	return ret;
}

static int isobusfs_cl_go(struct isobusfs_priv *priv)
{
	int ret, timeout_ms, nfds, n;

	timeout_ms = isobusfs_get_timeout_ms(&priv->ccm_next_send_time);
	nfds = epoll_wait(priv->epoll_fd, priv->epoll_events,
			 ARRAY_SIZE(priv->epoll_events), timeout_ms);
	if (nfds < 0 && nfds != -EINTR)
		return -errno;

	ret = clock_gettime(CLOCK_MONOTONIC, &priv->last_time);
	if (ret < 0) {
		pr_err("failed to get time: %s", strerror(errno));
		return EXIT_FAILURE;
	}

	if (nfds <= 0)
		/* timeout or -EINTR */
		goto send_status;

	for (n = 0; n < nfds; ++n) {
		struct epoll_event *ev = &priv->epoll_events[n];

		if (!ev->events) {
			warn("no events");
			continue;
		}

		if (ev->data.fd == priv->sock) {
			if (ev->events & POLLERR) {
				struct isobusfs_err_msg emsg = {
					.stats = &priv->stats,
				};

				ret = isobusfs_recv_err(priv->sock, &emsg);
				if (ret && ret != -EINTR)
					return ret;
			}
		} else {
			warn("unknown fd %d", ev->data.fd);
		}
		if (ev->events & POLLIN) {
			ret = isobusfs_recv_one(priv, ev->data.fd);
			if (ret) {
				warn("recv one");
				return ret;
			}
		}
	}

send_status:
	/* detect FS timeout */
	isobusfs_fs_detect_timeout(priv);
	
	ret = isobusfs_cl_action(priv);
	if (ret)
		pr_warn("client action failed");

	/* this function will send status only if it is proper time to do so */
	return isobusfs_ccm_send(priv);
}

static int isobusfs_client_sock_prepare(struct isobusfs_priv *priv)
{
	struct j1939_filter filt[] = {
		{
			.pgn = ISOBUSFS_PGN_FS_TO_CL,
			.pgn_mask = J1939_PGN_PDU1_MAX,
		}, {
			.pgn = ISOBUS_PGN_ACK,
			.pgn_mask = J1939_PGN_PDU1_MAX,
		},
	};
	struct epoll_event ev = { 0 };
	unsigned int sock_opt;
	int true_val = true;
	int ret;

	priv->sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (priv->sock < 0) {
		pr_err("failed to open socket: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	/* configure socket filter to ignore not brooadcasted messages */
	ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_FILTER,
			 &filt, sizeof(filt));
	if (ret < 0) {
		pr_err("failed to set j1939 filter: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_SEND_PRIO,
			&priv->prio, sizeof(priv->prio));
	if (ret < 0) {
		pr_err("failed to set SO_J1939_SEND_PRIO: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	/* we need to receive broadcast file server status messages */
	ret = setsockopt(priv->sock, SOL_SOCKET, SO_BROADCAST, &true_val,
			 sizeof(true_val));
	if (ret < 0) {
		pr_err("failed to set SO_BROADCAST: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_ERRQUEUE, &true_val,
			 sizeof(true_val));
	if (ret < 0) {
		pr_err("failed to set SO_J1939_ERRQUEUE: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	sock_opt = SOF_TIMESTAMPING_SOFTWARE |
		   SOF_TIMESTAMPING_OPT_CMSG |
		   SOF_TIMESTAMPING_TX_ACK |
		   SOF_TIMESTAMPING_TX_SCHED |
		   SOF_TIMESTAMPING_OPT_STATS | SOF_TIMESTAMPING_OPT_TSONLY |
		   SOF_TIMESTAMPING_OPT_ID;

	ret = setsockopt(priv->sock, SOL_SOCKET, SO_TIMESTAMPING,
			 (char *) &sock_opt, sizeof(sock_opt));
	if (ret < 0) {
		pr_err("failed to set SO_TIMESTAMPING: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	ret = bind(priv->sock, (void *)&priv->sockname, sizeof(priv->sockname));
	if (ret < 0) {
		pr_err("failed to bind socket: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	ret = connect(priv->sock, (void *)&priv->peername,
		      sizeof(priv->peername));
	if (ret < 0) {
		pr_err("failed to connect socket: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	priv->epoll_fd = epoll_create1(0);
	if (priv->epoll_fd < 0) {
		pr_err("failed to create epoll fd: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	ev.events = EPOLLIN | EPOLLERR;
	ev.data.fd = priv->sock;
	ret = epoll_ctl(priv->epoll_fd, EPOLL_CTL_ADD, priv->sock, &ev);
	if (ret < 0) {
		pr_err("failed to add socket to epoll: %d (%s)", errno,
		       strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int isobusfs_client_parse_args(struct isobusfs_priv *priv,
				      int argc, char *argv[])
{
	int opt;

	/* argument parsing */
	while ((opt = getopt(argc, argv, optstring)) != -1) {
		switch (opt) {
		case 'i':
			priv->infile = open(optarg, O_RDONLY);
			if (priv->infile == -1)
				err(EXIT_FAILURE, "can't open input file");
			priv->todo_filesize = 1;
			break;
		case 's':
			priv->max_transfer = strtoul(optarg, NULL, 0);
			if (priv->max_transfer > ISOBUSFS_MAX_TRANSFER_LENGH)
				err(EXIT_FAILURE, "used value (%zu) is bigger then allowed maximal size: %u.\n",
				    priv->max_transfer, ISOBUSFS_MAX_TRANSFER_LENGH);
			break;
		case 'r':
			priv->todo_recv = 1;
			break;
		case 'p':
			priv->prio = strtoul(optarg, NULL, 0);
			break;
		case 'P':
			break;
		case 'c':
			priv->todo_connect = 1;
			break;
		case 'R':
			priv->repeat = strtoul(optarg, NULL, 0);
			if (priv->repeat < 1)
				err(EXIT_FAILURE, "send/repeat count can't be less then 1\n");
			break;
		case 'I':
			break;
		case 'h': /*fallthrough*/
		default:
			fputs(help_msg, stderr);
			return EXIT_FAILURE;
		}
	}

	if (argv[optind]) {
		if (strcmp("-", argv[optind]))
			libj1939_parse_canaddr(argv[optind], &priv->sockname);
		optind++;
	}

	if (argv[optind]) {
		if (strcmp("-", argv[optind])) {
			libj1939_parse_canaddr(argv[optind], &priv->peername);
		}
		optind++;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	struct isobusfs_priv *priv;
	struct timespec ts;
	int ret;

	priv = malloc(sizeof(*priv));
	if (!priv)
		err(EXIT_FAILURE, "can't allocate priv");

	bzero(priv, sizeof(*priv));

	priv->prio = ISOBUSFS_DEFAULT_PRIO;
	priv->infile = STDIN_FILENO;
	priv->outfile = STDOUT_FILENO;
	priv->max_transfer = ISOBUSFS_MAX_TRANSFER_LENGH;
	priv->polltimeout = 100000;
	priv->repeat = 1;
	priv->todo_recv = true;

	isobusfs_init_sockaddr_can(&priv->sockname, J1939_NO_PGN);
	isobusfs_init_sockaddr_can(&priv->peername, ISOBUSFS_PGN_CL_TO_FS);

	ret = isobusfs_client_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	ret = isobusfs_client_sock_prepare(priv);
	if (ret)
		return ret;

	isobusfs_ccm_init(priv);

	/* Init next st_next_send_time value to avoid warnings */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	priv->ccm_next_send_time = ts;

	pr_debug("starting client\n");

	while (1) {
		ret = isobusfs_cl_go(priv);
		if (ret)
			break;
	}

	close(priv->epoll_fd);
	close(priv->infile);
	close(priv->outfile);
	close(priv->sock);
	return ret;
}

