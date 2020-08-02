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
#include <getopt.h>
#include <net/if.h>



#include <linux/errqueue.h>
#include <linux/netlink.h>
#include <linux/net_tstamp.h>
#include <linux/socket.h>

#include "isobusfs_cmn.h"
#include "isobusfs_cli.h"
#include "../libj1939.h"

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
#if 0
static int isobusfs_cli_action(struct isobusfs_priv *priv)
{
	const char volume_name[] = "\\\\vol1";
	const char dir_name[] = "\\\\vol1\\can";
	int ret = 0;

	switch (priv->state) {
	case ISOBUSFS_CLI_STATE_CONNECTING:
	case ISOBUSFS_CLI_STATE_IDLE:
	case ISOBUSFS_CLI_STATE_WAIT_FS_PROPERTIES:
	case ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR:
	case ISOBUSFS_CLI_STATE_WAIT_CCD_RESP:
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
	case ISOBUSFS_CLI_STATE_VOLUME_STATUS_DONE:
		ret = isobusfs_cli_get_current_dir_req(priv);
		break;
	case ISOBUSFS_CLI_STATE_GET_CURRENT_DIR_DONE:
		/* TODO: isobusfs_cli_volume_status_req() and
		 * isobusfs_cli_ccd_req() have different variable sequence 1.
		 * name, 2. size...*/
		ret = isobusfs_cli_ccd_req(priv, dir_name, sizeof(dir_name) - 1);
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
#endif

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
	/* detect FS timeout */
	isobusfs_cli_fs_detect_timeout(priv);

	isobusfs_cli_run_self_tests(priv);

#if 0
	ret = isobusfs_cli_action(priv);
	if (ret)
		pr_warn("client action failed");
#endif
	/* this function will send status only if it is proper time to do so */
	return isobusfs_cli_ccm_send(priv);
}

static int isobusfs_cli_process_events_and_tasks(struct isobusfs_priv *priv)
{
	bool dont_wait = false;
	int nfds = 0;
	int ret;

	if (priv->state == ISOBUSFS_CLI_STATE_SELFTEST)
		dont_wait = true;

	ret = isobusfs_cmn_prepare_for_events(&priv->cmn, &nfds, dont_wait);
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

static void isobusfs_cli_print_help(void)
{
	printf("Usage: isobusfs-cli [options]\n");
	printf("Options:\n");
	printf("  --local-address <local_address_hex> or -a <local_address_hex>\n");
	printf("  --local-name <local_name_hex> or -n <local_name_hex>\n");
	printf("  --remote-address <remote_address_hex> or -r <remote_address_hex>\n");
	printf("  --remote-name <remote_name_hex> or -m <remote_name_hex>\n");
	printf("  --interface <interface_name> or -i <interface_name>\n");
	printf("  --log-level <logging_level> or -l <logging_level>\n");
	printf("Note: Local address and local name are mutually exclusive\n");
	printf("Note: Remote address and remote name are mutually exclusive\n");
}

static int isobusfs_cli_parse_args(struct isobusfs_priv *priv, int argc, char *argv[])
{
	struct sockaddr_can *remote = &priv->peername;
	struct sockaddr_can *local = &priv->sockname;
	bool local_address_set = false;
	bool local_name_set = false;
	bool remote_address_set = false;
	bool remote_name_set = false;
	bool interface_set = false;
	int long_index = 0;
	int level;
	int opt;

	static struct option long_options[] = {
		{"local-address", required_argument, 0, 'a'},
		{"local-name", required_argument, 0, 'n'},
		{"remote-address", required_argument, 0, 'r'},
		{"remote-name", required_argument, 0, 'm'},
		{"interface", required_argument, 0, 'i'},
		{"log-level", required_argument, 0, 'l'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "a:n:r:m:i:l:", long_options, &long_index)) != -1) {
		switch (opt) {
		case 'a':
			local->can_addr.j1939.addr = strtoul(optarg, NULL, 16);
			local_address_set = true;
			break;
		case 'n':
			local->can_addr.j1939.name = strtoull(optarg, NULL, 16);
			local_name_set = true;
			break;
		case 'r':
			remote->can_addr.j1939.addr = strtoul(optarg, NULL, 16);
			remote_address_set = true;
			break;
		case 'm':
			remote->can_addr.j1939.name = strtoull(optarg, NULL, 16);
			remote_name_set = true;
			break;
		case 'i':
			local->can_ifindex = if_nametoindex(optarg);
			if (!local->can_ifindex) {
				pr_err("Interface %s not found. Error: %d (%s)\n",
				       optarg, errno, strerror(errno));
				return -EINVAL;
			}
			remote->can_ifindex = local->can_ifindex;
			interface_set = true;
			break;
		case 'l':
			level = strtoul(optarg, NULL, 0);
			if (level < LOG_LEVEL_ERROR || level > LOG_LEVEL_DEBUG)
				pr_err("invalid debug level %d", level);
			isobusfs_log_level_set(level);
			break;
		default:
			isobusfs_cli_print_help();
			return -EINVAL;
		}
	}

	if (!interface_set) {
		pr_err("interface not specified");
		isobusfs_cli_print_help();
		return -EINVAL;
	}

	if ((local_address_set && local_name_set) ||
	    (remote_address_set && remote_name_set)) {
		pr_err("local address and local name or remote address and remote name are mutually exclusive");
		isobusfs_cli_print_help();
		return -EINVAL;
	}

	return 0;
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

