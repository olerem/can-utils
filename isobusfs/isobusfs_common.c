

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


