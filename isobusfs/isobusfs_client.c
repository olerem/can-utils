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

#define J1939_MAX_ETP_PACKET_SIZE (7 * 0x00ffffff)
#define JCAT_BUF_SIZE (1000 * 1024)

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

static int isobusfs_client_sock_prepare(struct isobusfs_priv *priv)
{
	unsigned int sock_opt;
	int value;
	int ret;

	/* open socket */
	priv->sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (priv->sock < 0) {
		warn("socket(j1939)");
		return EXIT_FAILURE;
	}

	ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_SEND_PRIO,
			&priv->prio, sizeof(priv->prio));
	if (ret < 0) {
		warn("set priority %i", priv->prio);
		return EXIT_FAILURE;
	}

	value = 1;
	ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_ERRQUEUE, &value,
			 sizeof(value));
	if (ret < 0) {
		warn("set recverr");
		return EXIT_FAILURE;
	}

	sock_opt = SOF_TIMESTAMPING_SOFTWARE |
		   SOF_TIMESTAMPING_OPT_CMSG |
		   SOF_TIMESTAMPING_TX_ACK |
		   SOF_TIMESTAMPING_TX_SCHED |
		   SOF_TIMESTAMPING_OPT_STATS | SOF_TIMESTAMPING_OPT_TSONLY |
		   SOF_TIMESTAMPING_OPT_ID;

	if (setsockopt(priv->sock, SOL_SOCKET, SO_TIMESTAMPING,
		       (char *) &sock_opt, sizeof(sock_opt)))
		err(1, "setsockopt timestamping");

	ret = bind(priv->sock, (void *)&priv->sockname, sizeof(priv->sockname));
	if (ret < 0) {
		warn("bind()");
		return EXIT_FAILURE;
	}

	if (!priv->valid_peername) {
		warn("no peername supplied");
		return EXIT_FAILURE;
	}
	ret = connect(priv->sock, (void *)&priv->peername,
		      sizeof(priv->peername));
	if (ret < 0) {
		warn("connect()");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int isobusfs_client_parse_args(struct isobusfs_priv *priv,
				      int argc, char *argv[])
{
	int opt;

	/* argument parsing */
	while ((opt = getopt(argc, argv, optstring)) != -1)
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

	if (argv[optind]) {
		if (strcmp("-", argv[optind]))
			libj1939_parse_canaddr(argv[optind], &priv->sockname);
		optind++;
	}

	if (argv[optind]) {
		if (strcmp("-", argv[optind])) {
			libj1939_parse_canaddr(argv[optind], &priv->peername);
			priv->valid_peername = 1;
		}
		optind++;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	struct isobusfs_priv *priv;
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

	isobusfs_init_sockaddr_can(&priv->sockname, ISOBUS_PGN_CLIENT);
	isobusfs_init_sockaddr_can(&priv->peername, ISOBUS_PGN_FS);

	ret = isobusfs_client_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	ret = isobusfs_client_sock_prepare(priv);
	if (ret)
		return ret;

	isobusfs_cl_property_req(priv);

	close(priv->infile);
	close(priv->outfile);
	close(priv->sock);
	return ret;
}

