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
#include "isobusfs_cli.h"
#include "../libj1939.h"

static const char help_msg[] =
	"isobusfs_cli: FTP like client for IsoBUS file server\n"
	"Usage: isobusfs_cli [options] FROM TO\n"
	" FROM / TO	- or [IFACE][:[SA][,[PGN][,NAME]]]\n"
	"Options:\n"
	" -I		Get server information\n"
	"\n"
	"Example:\n"
	"isobusfs_cli can0:0x80 can0:0x90\n"
	"\n"
	;

static const char optstring[] = "?hi:vs:rp:P:R:I";

static int isobusfs_cli_rx(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	int cmd = isobusfs_buf_to_cmd(msg->buf);
	int ret = 0;

	switch (cmd) {
	case ISOBUSFS_CG_CONNECTION_MANAGMENT:
		ret = isobusfs_cli_rx_cg_cm(priv, msg);
		break;
	case ISOBUSFS_CG_DIRECTORY_HANDLING:
		ret = isobusfs_cli_rx_cg_dh(priv, msg);
		priv->state = ISOBUSFS_CLI_STATE_IDLE;
		break;
	case ISOBUSFS_CG_FILE_ACCESS: /* fall through */
	case ISOBUSFS_CG_FILE_HANDLING: /* fall through */
	case ISOBUSFS_CG_VOLUME_HANDLING: /* fall through */
	default:
		isobusfs_send_nack(priv->sock_nack, msg);
		pr_warn("unsupported command group: %i", cmd);
		/* Not a critical error */
		return 0;
	}

	return ret;
}

static int isobusfs_cli_rx_ack(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
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
		priv->state = ISOBUSFS_CLI_STATE_IDLE;
		break;
	default:
		pr_warn("%s: unsupported ACK control: %i", __func__, ctrl);
	}

	/* Not a critical error */
	return 0;
}

static int isobusfs_cli_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg)
{
	pgn_t pgn = msg->peername.can_addr.j1939.pgn;
	int ret;

	switch (pgn) {
	case ISOBUSFS_PGN_FS_TO_CL:
		ret = isobusfs_cli_rx(priv, msg);
		break;
	case ISOBUS_PGN_ACK:
		ret = isobusfs_cli_rx_ack(priv, msg);
		break;
	default:
		pr_warn("%s: unsupported PGN: %x", __func__, pgn);
		/* Not a critical error */
		ret = 0;
		break;
	}

	return ret;
}

static int isobusfs_cli_rx_one(struct isobusfs_priv *priv, int sock)
{
	struct isobusfs_msg *msg;
	int flags = 0;
	int ret;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		pr_err("can't allocate rx msg struct\n");
		return -ENOMEM;
	}
	msg->buf_size = ISOBUSFS_MAX_TRANSFER_LENGH;
	msg->peer_addr_len = sizeof(msg->peername);
	msg->sock = sock;

	ret = recvfrom(sock, &msg->buf[0], msg->buf_size, flags,
		       (struct sockaddr *)&msg->peername, &msg->peer_addr_len);

	if (ret < 0) {
		ret = -errno;
		pr_warn("recvfrom() failed: %i %s", ret, strerror(-ret));
		return ret;
	}

	if (ret < ISOBUSFS_MIN_TRANSFER_LENGH) {
		pr_warn("buf is less then min transfer: %i\n", ret);
		isobusfs_send_nack(priv->sock_nack, msg);
		return -EINVAL;
	}

	msg->len = ret;

	ret = isobusfs_cli_rx_buf(priv, msg);
	if (ret < 0) {
		pr_warn("failed to process rx buf: %i (%s)\n", ret, strerror(ret));
		return ret;
	}

	return 0;
}

/* actions */

static int isobusfs_cli_action(struct isobusfs_priv *priv)
{
	const char volume_name[] = "\\\\vol1";
	int ret = 0;

	switch (priv->state) { 
	case ISOBUSFS_CLI_STATE_CONNECTING:
	case ISOBUSFS_CLI_STATE_IDLE:
	case ISOBUSFS_CLI_STATE_WAIT_FS_PROPERTIES:
	case ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR:
	case ISOBUSFS_CLI_STATE_WAIT_FILE_SIZE:
	case ISOBUSFS_CLI_STATE_WAIT_FILE:
	case ISOBUSFS_CLI_STATE_WAIT_VOLUME_STATUS:
		/* nothing to do */
		break;
	case ISOBUSFS_CLI_STATE_CONNECTING_DONE:
		ret = isobusfs_cli_property_req(priv);
		break;
	case ISOBUSFS_CLI_STATE_GET_FS_PROPERTIES_DONE:
		ret = isobusfs_cli_volume_status_req(priv, 0,
				       sizeof(volume_name) - 1, volume_name);

		break;
	case ISOBUSFS_CLI_STATE_GET_CURRENT_DIR_DONE:
		ret = isobusfs_cli_get_current_dir_req(priv);
		break;
	case ISOBUSFS_CLI_STATE_VOLUME_STATUS_DONE:
		/* TODO: get file size */
		break;
	case ISOBUSFS_CLI_STATE_GET_FS_PROPERTIES:
		break;
	case ISOBUSFS_CLI_STATE_GET_CURRENT_DIR:
		break;
	case ISOBUSFS_CLI_STATE_GET_FILE_SIZE:
		break;
	case ISOBUSFS_CLI_STATE_GET_FILE:
		break;
	default:
		pr_err("unknown state: %d", priv->state);
		return -EINVAL;
	}

	return ret;
}

static int isobusfs_cli_handle_events(struct isobusfs_priv *priv, int nfds)
{
	int ret;
	int n;

	for (n = 0; n < nfds && n < priv->cmn.epoll_events_size; ++n) {
		struct epoll_event *ev = &priv->cmn.epoll_events[n];

		if (!ev->events) {
			warn("no events");
			continue;
		}

		if (ev->data.fd == priv->sock_ccm) {
			if (ev->events & POLLERR) {
				struct isobusfs_err_msg emsg = {
					.stats = &priv->stats,
				};

				ret = isobusfs_recv_err(priv->sock_ccm, &emsg);
				if (ret && ret != -EINTR)
					return ret;
			}
		} else {
			warn("unknown fd %d", ev->data.fd);
		}

		if (ev->events & POLLIN) {
			ret = isobusfs_cli_rx_one(priv, ev->data.fd);
			if (ret) {
				warn("recv one");
				return ret;
			}
		}
	}

	return 0;
}

static int isobusfs_cli_handle_periodic_tasks(struct isobusfs_priv *priv)
{
	int ret;

	/* detect FS timeout */
	isobusfs_cli_fs_detect_timeout(priv);

	ret = isobusfs_cli_action(priv);
	if (ret)
		pr_warn("client action failed");

	/* this function will send status only if it is proper time to do so */
	return isobusfs_cli_ccm_send(priv);
}

static int isobusfs_cli_process_events_and_tasks(struct isobusfs_priv *priv)
{
	int ret, nfds;

	ret = isobusfs_cmn_prepare_for_events(&priv->cmn, &nfds);
	if (ret)
		return ret;

	if (nfds > 0) {
		ret = isobusfs_cli_handle_events(priv, nfds);
		if (ret)
			return ret;
	}

	return isobusfs_cli_handle_periodic_tasks(priv);
}

static int isobusfs_cli_sock_main_prepare(struct isobusfs_priv *priv)
{
	struct sockaddr_can addr = priv->sockname;
	int ret;

	ret = isobusfs_cmn_open_socket();
	if (ret < 0)
		return ret;

	priv->sock_main = ret;

	/* TODO: this is TX only socket */
	addr.can_addr.j1939.pgn = ISOBUSFS_PGN_FS_TO_CL;
	ret = isobusfs_cmn_bind_socket(priv->sock_main, &addr);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_set_linger(priv->sock_main);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_socket_prio(priv->sock_main, ISOBUSFS_PRIO_DEFAULT);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_connect_socket(priv->sock_main, &priv->peername);
	if (ret < 0)
		return ret;

	return isobusfs_cmn_add_socket_to_epoll(priv->cmn.epoll_fd,
						priv->sock_main, EPOLLIN);
}

static int isobusfs_cli_sock_ccm_prepare(struct isobusfs_priv *priv)
{
	struct sockaddr_can addr = priv->sockname;
	int ret;

	ret = isobusfs_cmn_open_socket();
	if (ret < 0)
		return ret;

	priv->sock_ccm = ret;

	ret = isobusfs_cmn_configure_error_queue(priv->sock_ccm);
	if (ret < 0)
		return ret;

	/* TODO: this is TX only socket */
	addr.can_addr.j1939.pgn = J1939_NO_PGN;
	ret = isobusfs_cmn_bind_socket(priv->sock_ccm, &addr);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_set_linger(priv->sock_ccm);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_socket_prio(priv->sock_ccm, ISOBUSFS_PRIO_DEFAULT);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_connect_socket(priv->sock_ccm, &priv->peername);
	if (ret < 0)
		return ret;

	/* poll for errors to get confirmation if our packets are send */
	return isobusfs_cmn_add_socket_to_epoll(priv->cmn.epoll_fd, priv->sock_ccm,
						EPOLLERR);
}

static int isobusfs_cli_sock_nack_prepare(struct isobusfs_priv *priv)
{
	struct sockaddr_can addr = priv->sockname;
	int ret;

	ret = isobusfs_cmn_open_socket();
	if (ret < 0)
		return ret;

	priv->sock_nack = ret;

	addr.can_addr.j1939.pgn = ISOBUS_PGN_ACK;
	ret = isobusfs_cmn_bind_socket(priv->sock_nack, &addr);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_socket_prio(priv->sock_nack, ISOBUSFS_PRIO_ACK);
	if (ret < 0)
		return ret;

	/* poll for errors to get confirmation if our packets are send */
	return isobusfs_cmn_add_socket_to_epoll(priv->cmn.epoll_fd,
						priv->sock_nack, EPOLLIN);
}

/* rx socket for fss and volume status announcements */
static int isobusfs_cli_sock_bcast_prepare(struct isobusfs_priv *priv)
{
	struct sockaddr_can addr = priv->sockname;
	int ret;

	ret = isobusfs_cmn_open_socket();
	if (ret < 0)
		return ret;

	priv->sock_bcast_rx = ret;

	/* keep address and name and overwrite PGN */
	addr.can_addr.j1939.name = J1939_NO_NAME;
	addr.can_addr.j1939.addr = J1939_NO_ADDR;
	addr.can_addr.j1939.pgn = ISOBUSFS_PGN_FS_TO_CL;
	ret = isobusfs_cmn_bind_socket(priv->sock_bcast_rx, &addr);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_set_broadcast(priv->sock_bcast_rx);
	if (ret < 0)
		return ret;

	ret = isobusfs_cmn_connect_socket(priv->sock_bcast_rx, &priv->peername);
	if (ret < 0)
		return ret;

	return isobusfs_cmn_add_socket_to_epoll(priv->cmn.epoll_fd, priv->sock_bcast_rx,
						EPOLLIN);
}

static int isobusfs_cli_sock_prepare(struct isobusfs_priv *priv)
{
	int ret;

	ret = isobusfs_cmn_create_epoll();
	if (ret < 0)
		return ret;

	priv->cmn.epoll_fd = ret;

	priv->cmn.epoll_events = calloc(ISOBUSFS_CLI_MAX_EPOLL_EVENTS,
					sizeof(struct epoll_event));
	if (!priv->cmn.epoll_events)
		return -ENOMEM;

	priv->cmn.epoll_events_size = ISOBUSFS_CLI_MAX_EPOLL_EVENTS;

	ret = isobusfs_cli_sock_ccm_prepare(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_cli_sock_bcast_prepare(priv);
	if (ret < 0)
		return ret;

	ret = isobusfs_cli_sock_main_prepare(priv);
	if (ret < 0)
		return ret;

	return isobusfs_cli_sock_nack_prepare(priv);
}

static int isobusfs_cli_parse_args(struct isobusfs_priv *priv,
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

	priv->prio = ISOBUSFS_PRIO_DEFAULT;
	priv->infile = STDIN_FILENO;
	priv->outfile = STDOUT_FILENO;
	priv->max_transfer = ISOBUSFS_MAX_TRANSFER_LENGH;
	priv->polltimeout = 100000;
	priv->repeat = 1;
	priv->todo_recv = true;

	isobusfs_init_sockaddr_can(&priv->sockname, J1939_NO_PGN);
	isobusfs_init_sockaddr_can(&priv->peername, ISOBUSFS_PGN_CL_TO_FS);

	ret = isobusfs_cli_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	ret = isobusfs_cli_sock_prepare(priv);
	if (ret)
		return ret;

	isobusfs_cli_ccm_init(priv);

	/* Init next st_next_send_time value to avoid warnings */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	priv->cmn.next_send_time = ts;

	pr_debug("starting client\n");

	while (1) {
		ret = isobusfs_cli_process_events_and_tasks(priv);
		if (ret)
			break;
	}

	close(priv->cmn.epoll_fd);
	free(priv->cmn.epoll_events);
	close(priv->infile);
	close(priv->outfile);

	close(priv->sock_main);
	close(priv->sock_nack);
	close(priv->sock_ccm);
	close(priv->sock_bcast_rx);

	return ret;
}

