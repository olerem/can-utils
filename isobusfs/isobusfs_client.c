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
	"isobusfs_client: netcat-like tool for j1939\n"
	"Usage: isobusfs_client [options] FROM TO\n"
	" FROM / TO	- or [IFACE][:[SA][,[PGN][,NAME]]]\n"
	"Options:\n"
	" -i <infile>	(default stdin)\n"
	" -s <size>	Set maximal transfer size. Default: 117440505 byte\n"
	" -r		Receive data\n"
	" -P <timeout>  poll timeout in milliseconds before sending data.\n"
	"		With this option send() will be used with MSG_DONTWAIT flag.\n"
	" -R <count>	Set send repeat count. Default: 1\n"
	" -I		Get server information\n"
	"\n"
	"Example:\n"
	"isobusfs_client -i some_file_to_send  can0:0x80 :0x90,0x12300\n"
	"isobusfs_client can0:0x90 -r > /tmp/some_file_to_receive\n"
	"\n"
	;

static const char optstring[] = "?hi:vs:rp:P:R:I";

static ssize_t isobusfs_client_send_one(struct isobusfs_priv *priv, int out_fd,
			     const void *buf, size_t buf_size)
{
	ssize_t num_sent;
	int flags = 0;

	if (priv->polltimeout)
		flags |= MSG_DONTWAIT;

	if (priv->valid_peername && !priv->todo_connect)
		num_sent = sendto(out_fd, buf, buf_size, flags,
				  (struct sockaddr *)&priv->peername,
				  sizeof(priv->peername));
	else
		num_sent = send(out_fd, buf, buf_size, flags);

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

static void isobusfs_client_print_timestamp(struct isobusfs_priv *priv, const char *name,
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

static const char *isobusfs_client_tstype_to_str(int tstype)
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
static void isobusfs_client_scm_opt_stats(struct isobusfs_priv *priv, void *buf, int len)
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

static int isobusfs_client_extract_serr(struct isobusfs_priv *priv)
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

		isobusfs_client_print_timestamp(priv, isobusfs_client_tstype_to_str(serr->ee_info),
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

		isobusfs_client_print_timestamp(priv, "  ABT", &tss->ts[0]);
		warnx("serr: tx error: %i, %s", serr->ee_errno, strerror(serr->ee_errno));

		return serr->ee_errno;
	default:
		warnx("serr: wrong origin: %u", serr->ee_origin);
	}

	return 0;
}

static int isobusfs_client_parse_cm(struct isobusfs_priv *priv, struct cmsghdr *cm)
{
	const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));

	if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
		priv->tss = (void *)CMSG_DATA(cm);
	} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS) {
		void *jstats = (void *)CMSG_DATA(cm);

		/* Activated with SOF_TIMESTAMPING_OPT_STATS */
		isobusfs_client_scm_opt_stats(priv, jstats, cm->cmsg_len - hdr_len);
	} else if (cm->cmsg_level == SOL_CAN_J1939 &&
		   cm->cmsg_type == SCM_J1939_ERRQUEUE) {
		priv->serr = (void *)CMSG_DATA(cm);
	} else
		warnx("serr: not supported type: %d.%d",
		      cm->cmsg_level, cm->cmsg_type);

	return 0;
}

static int isobusfs_client_recv_err(struct isobusfs_priv *priv)
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
		isobusfs_client_parse_cm(priv, cm);
		if (priv->serr && priv->tss)
			return isobusfs_client_extract_serr(priv);
	}

	return 0;
}

static int isobusfs_client_send_loop(struct isobusfs_priv *priv, int out_fd, char *buf,
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
				ret = isobusfs_client_recv_err(priv);
				if (ret == -EINTR)
					continue;
				else if (ret)
					return ret;
				else if ((priv->repeat - 1) == stats->tskey)
					tx_done = true;

			}

			if (fds.revents & POLLOUT) {
				num_sent = isobusfs_client_send_one(priv, out_fd, tmp_buf, count);
				if (num_sent < 0)
					return num_sent;
			}
		} else {
			num_sent = isobusfs_client_send_one(priv, out_fd, tmp_buf, count);
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
		if (!count) {
			if (priv->repeat == priv->round)
				events = POLLERR;
			else
				tx_done = true;
		}
	}
	return 0;
}

static int isobusfs_client_sendfile(struct isobusfs_priv *priv, int out_fd, int in_fd,
			 off_t *offset, size_t count)
{
	int ret = EXIT_SUCCESS;
	off_t orig = 0;
	char *buf;
	ssize_t num_read;
	size_t to_read, buf_size;

	buf_size = min(priv->max_transfer, count);
	buf = malloc(buf_size);
	if (!buf) {
		warn("can't allocate buf");
		ret = EXIT_FAILURE;
		goto do_nofree;
	}

	if (offset) {

		/* Save current file offset and set offset to value in '*offset' */

		orig = lseek(in_fd, 0, SEEK_CUR);
		if (orig == -1) {
			ret = EXIT_FAILURE;
			goto do_free;
		}
		if (lseek(in_fd, *offset, SEEK_SET) == -1) {
			ret = EXIT_FAILURE;
			goto do_free;
		}
	}

	while (count > 0) {
		to_read = min(buf_size, count);

		num_read = read(in_fd, buf, to_read);
		if (num_read == -1) {
			ret = EXIT_FAILURE;
			goto do_free;
		}
		if (num_read == 0)
			break; /* EOF */

		ret = isobusfs_client_send_loop(priv, out_fd, buf, num_read);
		if (ret)
			goto do_free;

		count -= num_read;
	}

	if (offset) {
		/* Return updated file offset in '*offset', and reset the file offset
		   to the value it had when we were called. */

		*offset = lseek(in_fd, 0, SEEK_CUR);
		if (*offset == -1) {
			ret = EXIT_FAILURE;
			goto do_free;
		}

		if (lseek(in_fd, orig, SEEK_SET) == -1) {
			ret = EXIT_FAILURE;
			goto do_free;
		}
	}

do_free:
	free(buf);
do_nofree:
	return ret;
}

static size_t isobusfs_client_get_file_size(int fd)
{
	off_t offset;

	offset = lseek(fd, 0, SEEK_END);
	if (offset == -1)
		err(1, "%s lseek()\n", __func__);

	if (lseek(fd, 0, SEEK_SET) == -1)
		err(1, "%s lseek() start\n", __func__);

	return offset;
}

static int isobusfs_client_send(struct isobusfs_priv *priv)
{
	unsigned int size = 0;
	unsigned int i;
	int ret;

	if (priv->todo_filesize)
		size = isobusfs_client_get_file_size(priv->infile);

	if (!size)
		return EXIT_FAILURE;

	for (i = 0; i < priv->repeat; i++) {
		priv->round++;
		ret = isobusfs_client_sendfile(priv, priv->sock, priv->infile, NULL, size);
		if (ret)
			break;

		if (lseek(priv->infile, 0, SEEK_SET) == -1)
			err(1, "%s lseek() start\n", __func__);
	}

	return ret;
}

static int isobusfs_client_recv_one(struct isobusfs_priv *priv,
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

static int isobusfs_client_recv(struct isobusfs_priv *priv)
{
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
			ret = isobusfs_client_recv_err(priv);
			if (ret == -EINTR)
				continue;
			else if (ret)
				return ret;
		}

		if (fds.revents & POLLIN) {
			/* ignore errors? */
			isobusfs_client_recv_one(priv, msg);
		}

#if 0
		if (fds.revents & POLLOUT) {
			num_sent = isobusfs_client_send_one(priv, out_fd, tmp_buf, count);
			if (num_sent < 0)
				return num_sent;
		}
#endif
	}

	free(msg);
	return ret;
}



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
		priv->polltimeout = strtoul(optarg, NULL, 0);
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
	ret = isobusfs_client_recv(priv);

	close(priv->infile);
	close(priv->outfile);
	close(priv->sock);
	return ret;
}

