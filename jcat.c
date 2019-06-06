// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2018 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>
 */

#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <linux/socket.h>
#include <linux/input.h>
#include <linux/uinput.h>

#include "libj1939.h"
#define J1939_MAX_ETP_PACKET_SIZE (7 * 0x00ffffff)
#define JCAT_BUF_SIZE (1000 * 1024)

char *uinput_dev_str = "/dev/uinput";
struct uinput_user_dev uidev;
/*
 * min()/max()/clamp() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })


struct jcat_stats {
	int err;
	uint32_t tskey;
	uint32_t send;
};

struct jcat_priv {
	int sock;
	int infile;
	int uinput_fd;
	int outfile;
	size_t max_transfer;
	int repeat;
	int todo_prio;

	bool valid_peername;

	unsigned long polltimeout;

	struct sockaddr_can sockname;
	struct sockaddr_can peername;

	uint8_t old_buf[8];
};

static const char help_msg[] =
	"jcat: netcat tool for j1939\n"
	"Usage: jcat FROM TO\n"
	" FROM / TO	- or [IFACE][:[SA][,[PGN][,NAME]]]\n"
	"Options:\n"
	" -P <timeout>  poll timeout in milliseconds before sending data.\n"
	"		With this option send() will be used with MSG_DONTWAIT flag.\n"
	"\n"
	"Example:\n"
	"\n"
	;

static const char optstring[] = "?i:vs:rp:P:R:";

static void crash(char *str)
{
	perror(str);
	exit(-1);
}

static void jcat_init_sockaddr_can(struct sockaddr_can *sac)
{
	sac->can_family = AF_CAN;
	sac->can_addr.j1939.addr = J1939_NO_ADDR;
	sac->can_addr.j1939.name = J1939_NO_NAME;
	sac->can_addr.j1939.pgn = J1939_NO_PGN;
}


static int jcat_set_event(struct jcat_priv *priv, int  event)
{
	struct input_event     ev[2];

	ev[0].type = EV_KEY;
	ev[0].code = event;
	ev[0].value = 1;

	if (write(priv->uinput_fd,  &ev[0], sizeof(ev[0])) < 0)
		crash("event write: Left-click");
	return 0;
}

static int jcat_process_event(struct jcat_priv *priv, uint8_t *buf,
			      size_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		fprintf(stdout, "0x%02x ", buf[i]);
		priv->old_buf[i] = buf[i];
		/* TODO: send some uevent here */
	}

	fprintf(stdout, "\n");

	return jcat_set_event(priv, BTN_LEFT);
}

static int jcat_recv_one(struct jcat_priv *priv)
{
	int ret, i;
	uint8_t buf[8];
	bool new = false;

	ret = recv(priv->sock, buf, sizeof(buf), 0);
	if (ret < 0) {
		warn("recvf()");
		return EXIT_FAILURE;
	}

	for (i = 0; i < sizeof(buf); i++) {
		if (priv->old_buf[i] != buf[i]) {
			new = true;
			break;
		}
	}

	if (new)
		return jcat_process_event(priv, buf, sizeof(buf));

	return EXIT_SUCCESS;
}

static int jcat_recv_loop(struct jcat_priv *priv)
{
	unsigned int events = POLLIN;
	bool abort = false;
	int ret = 0;

	while (!abort) {
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

			if (fds.revents & POLLIN) {
				ret = jcat_recv_one(priv);
				if (ret < 0)
					return ret;
			}
		} else {
			ret = jcat_recv_one(priv);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int jcat_sock_prepare(struct jcat_priv *priv)
{
	int value;
	int ret;

	/* open socket */
	priv->sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (priv->sock < 0) {
		warn("socket(j1939)");
		return EXIT_FAILURE;
	}

	if (priv->todo_prio >= 0) {
		ret = setsockopt(priv->sock, SOL_CAN_J1939, SO_J1939_SEND_PRIO,
				&priv->todo_prio, sizeof(priv->todo_prio));
		if (ret < 0) {
			warn("set priority %i", priv->todo_prio);
			return EXIT_FAILURE;
		}
	}

	value = 1;
	ret = setsockopt(priv->sock, SOL_SOCKET, SO_BROADCAST,
			&value, sizeof(value));
	if (ret < 0)
		error(1, errno, "setsockopt set broadcast");


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

static int jcat_parse_args(struct jcat_priv *priv, int argc, char *argv[])
{
	int opt;

	/* argument parsing */
	while ((opt = getopt(argc, argv, optstring)) != -1)
	switch (opt) {
	case 'P':
		priv->polltimeout = strtoul(optarg, NULL, 0);
		break;
	case 'R':
		priv->repeat = atoi(optarg);
		if (priv->repeat < 1)
			err(EXIT_FAILURE, "send/repeat count can't be less then 1\n");
		break;
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

static int init_uinput(struct jcat_priv *priv) {
	int fd;

	if ((fd = open(uinput_dev_str, O_WRONLY | O_NONBLOCK)) < 0)
		crash(uinput_dev_str);

	if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0
		|| ioctl(fd, UI_SET_KEYBIT, BTN_LEFT) < 0
		|| ioctl(fd, UI_SET_KEYBIT, BTN_RIGHT) < 0)
		crash("ioctl(UI_SET_*)");

	snprintf(uidev.name, UINPUT_MAX_NAME_SIZE, "jbutton2uinput");
	uidev.id.bustype = BUS_USB;
	uidev.id.vendor  = 0x1;
	uidev.id.product = 0x1; /* should be something else */
	uidev.id.version = 1;

	if (write(fd, &uidev, sizeof(uidev)) < 0)
		crash("write(&uidev)");

	if (ioctl(fd, UI_DEV_CREATE) < 0)
		crash("UI_DEV_CREATE");
	return(fd);
}

int main(int argc, char *argv[])
{
	struct jcat_priv *priv;
	int ret;

	priv = malloc(sizeof(*priv));
	if (!priv)
		error(EXIT_FAILURE, errno, "can't allocate priv");

	bzero(priv, sizeof(*priv));

	priv->todo_prio = -1;
	priv->infile = STDIN_FILENO;
	priv->outfile = STDOUT_FILENO;
	priv->max_transfer = J1939_MAX_ETP_PACKET_SIZE;
	priv->polltimeout = 100000;
	priv->repeat = 1;
	priv->uinput_fd = init_uinput(priv);

	jcat_init_sockaddr_can(&priv->sockname);
	jcat_init_sockaddr_can(&priv->peername);

	ret = jcat_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	ret = jcat_sock_prepare(priv);
	if (ret)
		return ret;

	ret = jcat_recv_loop(priv);

	ioctl(priv->uinput_fd, UI_DEV_DESTROY);

	close(priv->infile);
	close(priv->outfile);
	close(priv->sock);
	return ret;
}

