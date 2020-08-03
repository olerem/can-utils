// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2020 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>



static const char *isobusfs_error_to_str(enum j1939_xtp_abort error)
{
	switch (error) {
	case ISOBUSFS_ERR_ACCESS_DENIED
		return "Access Denied";
	case ISOBUSFS_ERR_INVALID_ACCESS
		return "Invalid Access";
	case ISOBUSFS_ERR_TOO_MANY_FILES_OPEN
		return "Too many files open";
	case ISOBUSFS_ERR_FILE OR PATH NOT_FOUND
		return "File or path not found";
	case ISOBUSFS_ERR_:
		return "Invalid handle";
	case ISOBUSFS_ERR_:
		return "Invalid given source name";
	case ISOBUSFS_ERR_:
		return "Invalid given destination name";
	case ISOBUSFS_ERR_:
		return "Volume out of free space";
	case ISOBUSFS_ERR_:
		return "Failure during a write operation";
	case ISOBUSFS_ERR_:
		return "Volume is possibly not initialized";
	case ISOBUSFS_ERR_:
		return "Failure during a read operation";
	case ISOBUSFS_ERR_:
		return "Function not supported";
	case ISOBUSFS_ERR_:
		return "Invalid request length";
	case ISOBUSFS_ERR_:
		return "Out of memory";
	case ISOBUSFS_ERR_:
		return "Any other error";
	case ISOBUSFS_ERR_:
		return "End of file reached, will only be reported when file pointer is at end of file";
	default:
		return "<unknown>";
	}
}

void isobusfs_init_sockaddr_can(struct sockaddr_can *sac, u32 pgn)
{
	sac->can_family = AF_CAN;
	sac->can_addr.j1939.addr = J1939_NO_ADDR;
	sac->can_addr.j1939.name = J1939_NO_NAME;
	sac->can_addr.j1939.pgn = pgn;
}


