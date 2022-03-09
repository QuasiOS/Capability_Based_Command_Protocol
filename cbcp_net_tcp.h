#ifndef CBCP_NET_TCP_H
#define CBCP_NET_TCP_H

#include <cbcp.h>

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CBCP_Net_Tcp_Address {
	struct in_addr ipv4;
	uint16_t command_port;
	uint16_t control_port;
} CBCP_Net_Tcp_Address;

typedef struct CBCP_Net_Tcp_Connection {
	int file_descriptor;
} CBCP_Net_Tcp_Connection;

typedef struct CBCP_Net_Tcp_State {
	int server_command_socket;
	int server_control_socket;
	CBCP_Net_Tcp_Address *self_address;
} CBCP_Net_Tcp_State;

CBCP_NET_INIT_FUNC(cbcp_net_tcp_init_own_address);
CBCP_NET_PARSE_ADDRESS_STRING_FUNC(cbcp_net_tcp_parse_address_string);
CBCP_NET_SEND_FUNC(cbcp_net_tcp_send);
CBCP_NET_RECEIVE_FUNC(cbcp_net_tcp_receive);
CBCP_NET_CLIENT_OPEN_CONNECTION_FUNC(cbcp_net_tcp_client_open_connection);
CBCP_NET_SERVER_ACCEPT_CONNECTION_FUNC(cbcp_net_tcp_server_accept_connection);
CBCP_NET_CLOSE_CONNECTION_FUNC(cbcp_net_tcp_close_connection);
CBCP_Net_Implementation *cbcp_net_tcp_init(CBCP_Net_Tcp_State *implementation_state);

#ifdef __cplusplus
}
#endif

#endif // CBCP_NET_TCP_H
#ifdef CBCP_NET_TCP_IMPLEMENTATION
#undef CBCP_NET_TCP_IMPLEMENTATION

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#include <stdarg.h>

#ifndef CBCP_VERBOSE
static void CBCP_DEBUG_PRINT(const char *format, ...) {
	(void)format;
}
#else
static void CBCP_DEBUG_PRINT(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}
#endif


static CBCP_Status
_cbcp_net_tcp_parse_port_number(
	char **at_pointer,
	char *end,
	uint16_t *out_port_numeric)
{
	// Parse port number
	uint32_t parsed_port = 0;


	char *at = *at_pointer;

	if (at >= end) {
		return CBCP_STATUS_ERROR;
	}

	for (;;) {
		uint8_t digit = *at - '0';

		if (digit > 9) break;
		parsed_port *= 10;
		parsed_port += digit;

		++at;

		if (at >= end) break;

	}

	const unsigned int max_port_number = 65535;

	if (parsed_port > max_port_number) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: The port number supplied in address string is larger than the maximum of 65535.\n");
		return CBCP_STATUS_ERROR;
	}

	*at_pointer = at;
	*out_port_numeric = (uint16_t) parsed_port;

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
_cbcp_net_tcp_modify_file_descriptor_flags(int fd, int enable_flags, int disable_flags) {

	int socket_flags = fcntl(fd, F_GETFL, 0);

	if(socket_flags < 0) {
		CBCP_DEBUG_PRINT("Error using fcntl");
		return CBCP_STATUS_ERROR;
	}

	socket_flags |= enable_flags;
	socket_flags &= ~(disable_flags);

	if(fcntl(fd, F_SETFL, socket_flags) < 0) {
		CBCP_DEBUG_PRINT("Error using fcntl");
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}


static CBCP_Status
_cbcp_net_tcp_init_socket(int *out_socket, uint16_t port)
{

	int result_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (result_socket == -1) {
		return CBCP_STATUS_ERROR;
	}

	int so_reuseaddr = 1;

	if(setsockopt(
		result_socket,
		SOL_SOCKET,
		SO_REUSEADDR,
		&so_reuseaddr,
		sizeof(so_reuseaddr)) == -1
	) {
		return CBCP_STATUS_ERROR;
	}

	if (result_socket == -1) {
		return CBCP_STATUS_ERROR;
	}

	if (_cbcp_net_tcp_modify_file_descriptor_flags(result_socket, O_NONBLOCK, 0) < 0) {
		return CBCP_STATUS_ERROR;
	}

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(port);

	if (bind(result_socket, (struct sockaddr *)&address, sizeof(address)) == -1) {
		return CBCP_STATUS_ERROR;
	}

	// NOTE(jakob): We don't have a good reason for this particular value for
	// the listen backlog.
	int listen_backlog = 32;

	if (listen(result_socket, listen_backlog) == -1) {
		return CBCP_STATUS_ERROR;
	}

	*out_socket = result_socket;

	return CBCP_STATUS_SUCCESS;
}


CBCP_NET_INIT_FUNC(cbcp_net_tcp_init_own_address) {
	CBCP_Net_Tcp_State *state = (CBCP_Net_Tcp_State *)implementation_state;
	assert(state != NULL);

	state->self_address =
		(CBCP_Net_Tcp_Address *)own_address;

	if (_cbcp_net_tcp_init_socket(
		&state->server_command_socket,
		state->self_address->command_port) == -1
	) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: Could not init command socket.\n");
		return CBCP_STATUS_ERROR;
	}

	if (_cbcp_net_tcp_init_socket(
		&state->server_control_socket,
		state->self_address->control_port) == -1
	) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: Could not init control socket.\n");
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}

CBCP_NET_PARSE_ADDRESS_STRING_FUNC(cbcp_net_tcp_parse_address_string) {
	CBCP_Net_Tcp_Address *out_address = (CBCP_Net_Tcp_Address *)address_memory;

	CBCP_Net_Tcp_Address result = CBCP_ZERO_INITIALIZER;

	// len("255.255.255.255:65535:65535") == 27 < 32
	char address[32] = CBCP_ZERO_INITIALIZER;
	char *address_end = &address[address_string_length];

	if (address_string_length > 32) {
		CBCP_DEBUG_PRINT(
			"cbcp_net_tcp: Address string too long,\n"
			"it should not be exceed 27 characters.\n"
			"I.e. no longer than: \"255.255.255.255:65535:65535\"");
		return CBCP_STATUS_ERROR;
	}

	unsigned int address_length = address_string_length;
	strncpy(address, address_string, address_string_length);
	char *address_port = NULL;

	//
	// Parse address format for this host (self) from .cbcp-config file
	//

	for (unsigned int i = 0; i < address_length; ++i) {
		if (address[i] == ':') {
			address[i] = '\0';
			address_port = address + i + 1;
			break;
		}
	}

	if (!address_port) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: Could not parse port part of address string.\n");
		return CBCP_STATUS_ERROR;
	}

	// Parse address
	// by specification, there should not be whitespace preceding the address
	// 1. Get IPv4 address
	// 2. Get port number

	if (inet_pton(AF_INET, address, &result.ipv4.s_addr) != 1) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: Could not parse address string.\n");
		return CBCP_STATUS_ERROR;
	}

	char *port_at = address_port;
	uint16_t parsed_port;

	if (_cbcp_net_tcp_parse_port_number(
		&port_at,
		address_end,
		&parsed_port) == -1
	) {
		CBCP_DEBUG_PRINT("cbcp_net_tcp: Could not parse port number string.\n");
		return CBCP_STATUS_ERROR;
	}
	else {
		result.command_port = parsed_port;
	}

	++port_at; // Increment past ':' if the control port is explicitly defined

	if (_cbcp_net_tcp_parse_port_number(
		&port_at,
		address_end,
		&parsed_port) == -1
	) {
		if (result.command_port == 65535) {
			CBCP_DEBUG_PRINT(
				"cbcp_net_tcp: When the command port is specified as 65535,\n"
				"the control port must also be explicitly specified.");
			return CBCP_STATUS_ERROR;
		}
		else {
			result.control_port = result.command_port + 1;
		}
	}
	else {
		result.control_port = parsed_port;
	}

	*out_address = result;
	CBCP_DEBUG_PRINT("cbcp_net_tcp: Return success\n");
	return CBCP_STATUS_SUCCESS;
}

CBCP_NET_SEND_FUNC(cbcp_net_tcp_send) {
	(void)implementation_state;

	CBCP_Net_Tcp_Connection *connection = (CBCP_Net_Tcp_Connection *)connection_state;

	ssize_t send_count = send(
		connection->file_descriptor,
		send_buffer,
		send_buffer_length,
		MSG_NOSIGNAL);

	if(send_count == -1) {
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}

CBCP_NET_RECEIVE_FUNC(cbcp_net_tcp_receive) {
	(void)implementation_state;

	CBCP_Net_Tcp_Connection *connection = (CBCP_Net_Tcp_Connection *)connection_state;

	ssize_t read_count = read(connection->file_descriptor, receive_buffer, receive_buffer_length);

	*out_amount_received = read_count;

	if (read_count == -1) {
		if(errno == EAGAIN) {
			// NOTE(jakob & jørn): No data on non-blocking read => we have to try again.
			return CBCP_STATUS_SUCCESS;
		}
		else {
			return CBCP_STATUS_ERROR;
		}
	}
	else {
		return CBCP_STATUS_SUCCESS;
	}
}

CBCP_NET_CLIENT_OPEN_CONNECTION_FUNC(cbcp_net_tcp_client_open_connection) {
	(void)implementation_state;

	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (socket_fd == -1) {
		return CBCP_STATUS_ERROR;
	}

#if 0
	struct timeval timeout = CBCP_ZERO_INITIALIZER;
	timeout.tv_sec = 10;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout) == -1) {
		close(socket_fd);
		return CBCP_STATUS_ERROR;
	}
#endif

	uint16_t port;

	CBCP_Net_Tcp_Address *address =
		(CBCP_Net_Tcp_Address *)impl_address;

	if (is_control) {
		port = address->control_port;
	}
	else {
		port = address->command_port;
	}

	struct sockaddr_in socket_address;
	socket_address.sin_family = AF_INET;
	// NOTE(Patrick): The ipv4 address given by pton is already in network byte order.
	socket_address.sin_addr.s_addr = address->ipv4.s_addr;
	socket_address.sin_port = htons(port);
	socklen_t address_length = sizeof(socket_address);

	int connection = connect(
		socket_fd,
		(struct sockaddr*) &socket_address,
		address_length);

	if(connection == -1)
	{
		close(socket_fd);
		return CBCP_STATUS_ERROR;
	}

	struct pollfd connection_pollfd = CBCP_ZERO_INITIALIZER;
	connection_pollfd.fd = connection,
	connection_pollfd.events = POLLOUT;
	connection_pollfd.revents = 0;

	int poll_retval = poll(&connection_pollfd, 1, 1000);
	if (poll_retval < 1)
	{
		CBCP_DEBUG_PRINT("%s.\n", poll_retval == -1 ? "Retval error" : "Retval timeout");
		close(connection);
		return CBCP_STATUS_ERROR;
	}

	if ((connection_pollfd.revents & POLLERR) || (connection_pollfd.revents & POLLHUP))
	{
		CBCP_DEBUG_PRINT("poll bad revents.\n");
	}

	CBCP_Net_Tcp_Connection *connection_state = (CBCP_Net_Tcp_Connection *)connection_state_memory;
	connection_state->file_descriptor = socket_fd;

	return CBCP_STATUS_SUCCESS;
}

CBCP_NET_SERVER_ACCEPT_CONNECTION_FUNC(cbcp_net_tcp_server_accept_connection) {

	CBCP_Net_Tcp_State *state = (CBCP_Net_Tcp_State *)implementation_state;

	struct sockaddr_in client_address;
	socklen_t client_address_length = sizeof(client_address);

	int socket;

	if (is_control) {
		socket = state->server_control_socket;
	}
	else {
		socket = state->server_command_socket;
	}


	int connection = accept(socket, (struct sockaddr *)&client_address, &client_address_length);


	if (connection == -1) {
		if(errno != EAGAIN && errno != EWOULDBLOCK) {
			return CBCP_STATUS_ERROR;
		}
		else {
			*out_should_try_again = 1;
			return CBCP_STATUS_SUCCESS;
		}
	}

	struct pollfd connection_pollfd = CBCP_ZERO_INITIALIZER;
	connection_pollfd.fd = connection,
	connection_pollfd.events = POLLIN,
	connection_pollfd.revents = 0;

	// NOTE(Patrick): return value
	// ret >   0 : r is the number of fd with .revents != 0
	// ret ==  0 : poll timed out
	// ret == -1 : error
	int poll_retval = poll(&connection_pollfd, 1, 1000);
	if(poll_retval < 1)
	{
		CBCP_DEBUG_PRINT("%s.\n", poll_retval == -1 ? "Retval error" : "Retval timeout");
		close(connection);
		return CBCP_STATUS_ERROR;
	}

	if((connection_pollfd.revents & POLLERR) ||
	   (connection_pollfd.revents & POLLHUP))
	{
		CBCP_DEBUG_PRINT("poll bad revents.\n");
		close(connection);
		return CBCP_STATUS_ERROR;
	}

	CBCP_Net_Tcp_Connection *connection_state = (CBCP_Net_Tcp_Connection *)connection_state_memory;
	connection_state->file_descriptor = connection;

	*out_should_try_again = 0;

	return CBCP_STATUS_SUCCESS;
}

CBCP_NET_CLOSE_CONNECTION_FUNC(cbcp_net_tcp_close_connection) {
	(void)implementation_state;

	CBCP_Net_Tcp_Connection *connection = (CBCP_Net_Tcp_Connection *)connection_state;

	close(connection->file_descriptor);

	return CBCP_STATUS_SUCCESS;
}


CBCP_Net_Implementation *
cbcp_net_tcp_init(CBCP_Net_Tcp_State *implementation_state) {

	static CBCP_Net_Tcp_State internal_state;

	CBCP_Net_Implementation impl;

	impl.implementation_state             = (void *)(implementation_state ? implementation_state : &internal_state);
	impl.init_own_address                 = cbcp_net_tcp_init_own_address;
	impl.parse_address_string             = cbcp_net_tcp_parse_address_string;
	impl.send                             = cbcp_net_tcp_send;
	impl.receive                          = cbcp_net_tcp_receive;
	impl.client_open_connection           = cbcp_net_tcp_client_open_connection;
	impl.server_accept_connection         = cbcp_net_tcp_server_accept_connection;
	impl.close_connection                 = cbcp_net_tcp_close_connection;

	impl.name                             = (char *)"TCP";
	impl.name_length                      = sizeof("TCP") - 1;
	impl.size_of_address                  = sizeof(CBCP_Net_Tcp_Address);
	impl.size_of_connection               = sizeof(CBCP_Net_Tcp_Connection);
	impl.size_of_additional_packet_header = 0;

	return cbcp_net_add_impl(impl);
}

#endif // CBCP_NET_TCP_IMPLEMENTATION
