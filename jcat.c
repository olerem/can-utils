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
#define ARRAY_SIZE(array) \
	    (sizeof(array) / sizeof(*array))


char *uinput_dev_str = "/dev/uinput";
struct uinput_user_dev uidev;

struct jbutton_key {
	uint8_t byte;
	uint8_t mask;
	uint8_t shift;
	int code;
};

struct jbutton_priv {
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

/*
 *  1  2  3
 *   (4/5)
 *    6 7
 * Keys - 1, 2, 3, 6, 7
 * Wheel - 4 + key 5
 */

static const struct jbutton_key jbutton_keys[] = {
	{ 1, 0xff, 0, KEY_J }, /* 4 - wheel */
	{ 3, 0x01, 0, KEY_K }, /* 1 - key */
	{ 3, 0x04, 2, KEY_K }, /* 2 - key */
	{ 3, 0x10, 4, KEY_K }, /* 3 - key */
	{ 3, 0x40, 6, KEY_K }, /* 6 - key */
	{ 4, 0x01, 0, KEY_K }, /* 7 - key */
	{ 4, 0x04, 0, KEY_SPACE }, /* 5 - wheel key */
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

static void jbutton_init_sockaddr_can(struct sockaddr_can *sac)
{
	sac->can_family = AF_CAN;
	sac->can_addr.j1939.addr = J1939_NO_ADDR;
	sac->can_addr.j1939.name = J1939_NO_NAME;
	sac->can_addr.j1939.pgn = J1939_NO_PGN;
}

static void emit(int fd, int type, int code, int val)
{
	struct input_event ie;

	ie.type = type;
	ie.code = code;
	ie.value = val;
	/* timestamp values below are ignored */
	ie.time.tv_sec = 0;
	ie.time.tv_usec = 0;

	if (write(fd,  &ie, sizeof(ie)) < 0)
		crash("event write: Left-click");
}

static int jbutton_set_rot_event(struct jbutton_priv *priv,
			     const struct jbutton_key *key,
			     uint8_t *buf)
{
	uint8_t val = (buf[key->byte] & key->mask) >> key->shift;
	uint8_t oldval = (priv->old_buf[key->byte] & key->mask) >> key->shift;
	int8_t diffval = val - oldval;	// uint8_t -> int8_t magic!
	int code, i;

	code = key->code;
	if (diffval > 0)
		code = KEY_L;

	for (i = 0; i < abs(diffval); i++) {
		emit(priv->uinput_fd, EV_KEY, code, 1);
		emit(priv->uinput_fd, EV_SYN, SYN_REPORT, 0);
		emit(priv->uinput_fd, EV_KEY, code, 0);
		emit(priv->uinput_fd, EV_SYN, SYN_REPORT, 0);
	}

	return 0;
}

static int jbutton_set_event(struct jbutton_priv *priv,
			     const struct jbutton_key *key,
			     uint8_t *buf)
{
	uint8_t val = (buf[key->byte] & key->mask) >> key->shift;
	uint8_t oldval = (priv->old_buf[key->byte] & key->mask) >> key->shift;
	int ret = 0;

	if (oldval == val)
		return 0;

	if (key->code == KEY_J) {
		ret = jbutton_set_rot_event(priv, key, buf);
		goto out;
	}

	if (!val)
		goto out;

	emit(priv->uinput_fd, EV_KEY, key->code, 1);
	emit(priv->uinput_fd, EV_SYN, SYN_REPORT, 0);
	emit(priv->uinput_fd, EV_KEY, key->code, 0);
	emit(priv->uinput_fd, EV_SYN, SYN_REPORT, 0);

out:
	fprintf(stdout, "%i 0x%02x !\n", key->byte, val);
	return ret;
}

static int jbutton_process_event(struct jbutton_priv *priv, uint8_t *buf,
			      size_t size)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jbutton_keys); i++)
		jbutton_set_event(priv, &jbutton_keys[i], buf);

	for (i = 0; i < size; i++) {
		//fprintf(stdout, "0x%02x ", buf[i]);
		priv->old_buf[i] = buf[i];
		/* TODO: send some uevent here */
	}

	return 0;
}

static int jbutton_recv_one(struct jbutton_priv *priv)
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
		return jbutton_process_event(priv, buf, sizeof(buf));

	return EXIT_SUCCESS;
}

static int jbutton_recv_loop(struct jbutton_priv *priv)
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
				ret = jbutton_recv_one(priv);
				if (ret < 0)
					return ret;
			}
		} else {
			ret = jbutton_recv_one(priv);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int jbutton_sock_prepare(struct jbutton_priv *priv)
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

static int jbutton_parse_args(struct jbutton_priv *priv, int argc, char *argv[])
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

static int init_uinput(struct jbutton_priv *priv) {
	int fd;

	if ((fd = open(uinput_dev_str, O_WRONLY | O_NONBLOCK)) < 0)
		crash(uinput_dev_str);

	if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_P) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_J) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_L) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_S) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_D) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_A) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_SPACE) < 0
		|| ioctl(fd, UI_SET_KEYBIT, KEY_K) < 0)
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
	struct jbutton_priv *priv;
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

	jbutton_init_sockaddr_can(&priv->sockname);
	jbutton_init_sockaddr_can(&priv->peername);

	ret = jbutton_parse_args(priv, argc, argv);
	if (ret)
		return ret;

	ret = jbutton_sock_prepare(priv);
	if (ret)
		return ret;

	ret = jbutton_recv_loop(priv);

	ioctl(priv->uinput_fd, UI_DEV_DESTROY);

	close(priv->infile);
	close(priv->outfile);
	close(priv->sock);
	return ret;
}

