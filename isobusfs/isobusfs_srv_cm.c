// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>
/*
 * ISOBUS File System Server Connection Management (isobusfs_srv_cm.c)
 *
 * This code implements the Connection Management functionality for the
 * ISOBUS File System Server, according to the ISO 11783-13:2021 standard,
 * specifically Section 5.10: Connection/Disconnection of a client.
 *
 * The ISOBUS File System Server provides a way for clients to interact with
 * files and directories on an ISOBUS network. Connection Management is
 * responsible for handling client connections and disconnections, ensuring
 * proper communication and resource allocation between the server and its
 * clients.
 *
 * This code includes functions for initializing clients, adding new clients,
 * managing client connections, and handling client disconnections. It also
 * provides utility functions for managing sockets and filters for the
 * communication between the server and its clients.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "isobusfs_srv.h"

/**
 * isobusfs_srv_init_clients - Initialize the list of clients for the server
 * @priv: Pointer to the isobusfs_srv_priv structure containing clients array
 *
 * This function initializes the clients array in the isobusfs_srv_priv
 * structure by setting the socket value to -1 for each client in the list.
 * This indicates that the clients are not currently connected.
 */
void isobusfs_srv_init_clients(struct isobusfs_srv_priv *priv)
{
	int i;

	for (i = 0; i < ISOBUSFS_SRV_MAX_CLIENTS; i++)
		priv->clients[i].sock = -1;
}

/**
 * isobusfs_srv_get_client - Find a client in the list of clients by address
 * @priv: Pointer to the isobusfs_srv_priv structure containing clients array
 * @addr: Address of the client to find
 *
 * This function searches for a client in the list of clients using the
 * provided address. If a client with a matching address is found, the
 * function returns a pointer to the corresponding isobusfs_srv_client
 * structure. If no matching client is found, the function returns NULL.
 *
 * Note: The function skips clients with negative socket values.
 */
static struct isobusfs_srv_client *isobusfs_srv_get_client(
				struct isobusfs_srv_priv *priv, uint8_t addr)
{
	int i;

	for (i = 0; i < priv->clients_count; i++) {
		struct isobusfs_srv_client *client = &priv->clients[i];

		if (client->sock < 0)
			continue;

		if (client->addr == addr)
			return &priv->clients[i];
	}

	return NULL;
}

/**
 * isobusfs_srv_remove_client - Remove a client from the list of clients
 * @priv: Pointer to the isobusfs_srv_priv structure containing clients array
 * @client: Pointer to the isobusfs_srv_client structure to be removed
 *
 * This function removes a client from the list of clients, adjusts the
 * clients array, and decrements the clients_count. The function also closes
 * the client's socket.
 */
static void isobusfs_srv_remove_client(struct isobusfs_srv_priv *priv,
				       struct isobusfs_srv_client *client)
{
	int index = client - priv->clients;
	int i;

	if (client->sock < 0)
		return;

	close(client->sock);
	client->sock = -1;

	/* Shift all elements after the removed client to the left by one
	 * position
	 */
	for (i = index; i < priv->clients_count - 1; i++)
		priv->clients[i] = priv->clients[i + 1];

	priv->clients_count--;

	pr_debug("client 0x%02x removed", client->addr);
}

/**
 * isobusfs_srv_init_client - Initialize a client's socket and connection
 * @priv: pointer to the server's private data structure
 * @client: pointer to the client's data structure
 *
 * This function initializes a client's socket, binds it to the server's address,
 * sets the socket options, and connects the socket to the destination address.
 * If any step fails, it will log a warning message, close the socket if needed,
 * and return an error code.
 *
 * Return: 0 on success, negative error code on failure
 */
static int isobusfs_srv_init_client(struct isobusfs_srv_priv *priv,
		struct isobusfs_srv_client *client)
{
	struct sockaddr_can dst_addr = { 0 };
	struct j1939_filter filt = {
		.addr = J1939_NO_ADDR,
		.addr_mask = J1939_NO_ADDR, /* mask is 0xff */
	};
	int ret;

	if (client->sock >= 0) {
		pr_warn("client %d already initialized", client->addr);
		return -EINVAL;
	}

	client->sock = socket(PF_CAN, SOCK_DGRAM, CAN_J1939);
	if (client->sock < 0) {
		ret = -errno;
		pr_warn("can't open socket for client %d. Error: %i (%s)",
			client->addr, ret, strerror(ret));
		return ret;
	}

	ret = bind(client->sock, (struct sockaddr *)&priv->addr,
			sizeof(priv->addr));
	if (ret < 0) {
		ret = -errno;
		pr_warn("can't bind socket for client %d. Error: %i (%s)",
			client->addr, ret, strerror(ret));
		goto close_socket;
	}

	/* use positive filter to not no allow any unicast messages. At same
	 * time do not allow any broadcast messages. So, this will be transmit
	 * only socket. This is needed to not let the J1939 kernel stack to
	 * ACK ETP/TP transfers on the bus and provide false information to
	 * the client about received data.
	 */ 
	ret = setsockopt(client->sock, SOL_CAN_J1939, SO_J1939_FILTER, &filt,
			sizeof(filt));
	if (ret < 0) {
		ret = -errno;
		pr_warn("can't set socket filter for client 0x%02x. Error: %i (%s)",
			client->addr, ret, strerror(ret));
		goto close_socket;
	}

	dst_addr.can_family = AF_CAN;
	dst_addr.can_ifindex = priv->addr.can_ifindex;
	dst_addr.can_addr.j1939.name = J1939_NO_NAME;
	dst_addr.can_addr.j1939.addr = client->addr;
	dst_addr.can_addr.j1939.pgn = ISOBUSFS_PGN_FS_TO_CL;

	ret = connect(client->sock, (struct sockaddr *)&dst_addr,
			sizeof(dst_addr));
	if (ret < 0) {
		ret = -errno;
		pr_warn("can't connect socket for client 0x%02x. Error: %i (%s)",
			client->addr, ret, strerror(ret));
		goto close_socket;
	}

	return 0;

close_socket:
	close(client->sock);
	client->sock = -1;
	return ret;
}

/**
 * isobusfs_srv_add_client - Add a new client to the server's client list
 * @priv: pointer to the server's private data structure
 * @addr: address of the new client
 *
 * This function adds a new client to the server's client list if the list
 * hasn't reached its maximum capacity (ISOBUSFS_SRV_MAX_CLIENTS).
 * If the maximum number of clients is reached, a warning message will be
 * logged, and the function returns NULL.
 *
 * Return: pointer to the new client on success, NULL on failure
 */
static struct isobusfs_srv_client *isobusfs_srv_add_client(
		struct isobusfs_srv_priv *priv, uint8_t addr)
{
	struct isobusfs_srv_client *client;
	int ret;

	if (priv->clients_count >= ISOBUSFS_SRV_MAX_CLIENTS) {
		pr_warn("too many clients");
		return NULL;
	}

	client = &priv->clients[priv->clients_count];
	client->addr = addr;

	ret = isobusfs_srv_init_client(priv, client);
	if (ret < 0)
		return NULL;

	priv->clients_count++;
	pr_debug("client 0x%02x added", client->addr);

	return client;
}

/**
 * isobusfs_srv_remove_timeouted_clients - Remove clients that have timed out
 * @priv: pointer to the server's private data structure
 *
 * This function checks each client in the server's client list to determine
 * if the client has timed out. If a client has timed out, it is removed
 * from the list.
 */
void isobusfs_srv_remove_timeouted_clients(struct isobusfs_srv_priv *priv)
{
	int i;

	for (i = 0; i < priv->clients_count; i++) {
		struct isobusfs_srv_client *client = &priv->clients[i];
		int64_t time_diff;

		if (client->sock < 0)
			continue;

		time_diff = isobusfs_timespec_diff_ms(&priv->last_time,
						      &client->last_received);

		if (time_diff > ISOBUSFS_CLIENT_TIMEOUT) {
			isobusfs_srv_remove_client(priv, client);
			i--;
		}
	}
}

/**
 * isobusfs_srv_property_res - Send a Get File Server Properties Response
 * @priv: pointer to the server's private data structure
 * @msg: pointer to the received message that requires a response
 *
 * This function sends a response to a client's Get File Server Properties
 * request according to ISO 11783-13:2021, Annex C.1.5. The response contains
 * information about the server's capabilities, version, and maximum number
 * of simultaneously open files.
 *
 * Return: 0 on success, negative error code on failure
 */
static int isobusfs_srv_property_res(struct isobusfs_srv_priv *priv,
				     struct isobusfs_msg *msg)
{
	struct isobusfs_cm_fs_properties p;
	int ret;

	p.fs_function =
		isobusfs_cg_function_to_buf(ISOBUSFS_CG_CONNECTION_MANAGMENT,
					    ISOBUSFS_CM_GET_FS_PROPERTIES_RES);
	/* Version number:
	 * 0 - Draft
	 * 1 - Final draft
	 * 2 - First published version
	 */
	p.version = 3;
	/* Maximum Number of Simultaneously Open Files */
	p.max_open_files = ISOBUSFS_MAX_OPENED_FILES;
	/* File Server Capabilities */
	p.caps = 0;

	/* not used space should be filled with 0xff */
	memset(&p.reserved[0], 0xff, sizeof(p.reserved));

	ret = isobusfs_srv_sendto(priv, msg, &p, sizeof(p));
	if (ret < 0) {
		pr_warn("can't send property response");
		return ret;
	}

	pr_debug("> tx property response");

	return 0;
}

/**
 * isobusfs_srv_handle_ccm - Handle a Connection Control Maintenance message
 * @priv: pointer to the server's private data structure
 * @msg: pointer to the received message that requires a response
 *
 * This function handles a Connection Control Maintenance (CCM) message
 * according to ISO 11783-13:2021, Annex C.1.3. The CCM is used to establish a
 * connection between a client and a server. If the client is not found in the
 * server's client list, it is added to the list. If the client is found, the
 * client's socket is reinitialized.
 *
 * Return: 0 on success, negative error code on failure
 */
static int isobusfs_srv_handle_ccm(struct isobusfs_srv_priv *priv,
				   struct isobusfs_msg *msg)
{
	struct isobusfs_cm_ccm *ccm = (struct isobusfs_cm_ccm *)msg->buf;
	uint8_t addr = msg->peername.can_addr.j1939.addr;
	struct isobusfs_srv_client *client;

	pr_debug("< rx ccm version: %d", ccm->version);

	/* Get the client with the specified address */
	client = isobusfs_srv_get_client(priv, addr);
	/* If client is not found, create a new one */
	if (!client) {
		client = isobusfs_srv_add_client(priv, addr);
		if (!client) {
			pr_warn("can't add client");
			/* Keep running. Nothing we can do here */
			return -ENOMEM;
		}
	}

	/* Update the client's last_received timestamp */
	client->last_received = priv->last_time;

	return 0;
}

/**
 * isobusfs_srv_rx_cg_cm - Handle received connection management commands
 * @priv: pointer to the server's private data structure
 * @msg: pointer to the received message that requires processing
 *
 * This function handles the received connection management commands according
 * to the specific function code provided in the message. It then delegates
 * the processing to the corresponding handler for each supported function.
 * Unsupported functions will result in a warning message and an error response.
 *
 * Return: 0 on success or when an unsupported function is encountered,
 *         negative error code on failure
 */
int isobusfs_srv_rx_cg_cm(struct isobusfs_srv_priv *priv,
			  struct isobusfs_msg *msg)
{
	enum isobusfs_cm_cl_to_fs_function func =
		isobusfs_buf_to_function(msg->buf);
	int ret = 0;

	/* Process the received function code and delegate to appropriate
	 * handlers
	 */
	switch (func) {
	case ISOBUSFS_CM_F_CC_MAINTENANCE:
		ret = isobusfs_srv_handle_ccm(priv, msg);
		break;
	case ISOBUSFS_CM_GET_FS_PROPERTIES:
		ret = isobusfs_srv_property_res(priv, msg);
		break;
	case ISOBUSFS_CM_VOLUME_STATUS_REQ: /* fall through */
	default:
		goto not_supported;
	}

	return ret;

not_supported:
	/* Handle unsupported functions */
	isobusfs_srv_send_error(priv, msg, ISOBUSFS_ERR_FUNC_NOT_SUPPORTED);

	pr_warn("%s: unsupported function: %i", __func__, func);

	/* Not a critical error */
	return 0;
}
