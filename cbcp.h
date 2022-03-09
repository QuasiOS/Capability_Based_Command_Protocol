#ifndef CBCP_H
#define CBCP_H

#include <stdint.h>

#define CBCP_STRINGIFY_(s) CBCP_STRINGIFY(s)
#define CBCP_STRINGIFY(s) #s

#define CBCP_MAJOR_VERSION 0
#define CBCP_MINOR_VERSION 1
#define CBCP_VERSION_STRING "CBCP " CBCP_STRINGIFY_(CBCP_MAJOR_VERSION) "." CBCP_STRINGIFY_(CBCP_MINOR_VERSION) ""
#define CBCP_VERSION_STRING_LENGTH ((int)sizeof(CBCP_VERSION_STRING)-1)

#define CBCP_LIBRARY_MAJOR_VERSION 0
#define CBCP_LIBRARY_MINOR_VERSION 1
#define CBCP_LIBRARY_MICRO_VERSION 0
#define CBCP_LIBRARY_VERSION_STRING "QuasiOS-CBCP Library " CBCP_STRINGIFY_(CBCP_LIBRARY_MAJOR_VERSION) "." CBCP_STRINGIFY_(CBCP_LIBRARY_MINOR_VERSION) "." CBCP_STRINGIFY_(CBCP_LIBRARY_MICRO_VERSION) ""
#define CBCP_LIBRARY_VERSION_STRING_LENGTH ((int)sizeof(CBCP_LIBRARY_VERSION_STRING)-1)

#define CBCP_DATABASE_MAJOR_VERSION 0
#define CBCP_DATABASE_MINOR_VERSION 7
#define CBCP_DATABASE_VERSION_STRING "CBCP Database " CBCP_STRINGIFY_(CBCP_DATABASE_MAJOR_VERSION) "." CBCP_STRINGIFY_(CBCP_DATABASE_MINOR_VERSION) ""
#define CBCP_DATABASE_VERSION_STRING_LENGTH ((int)sizeof(CBCP_DATABASE_VERSION_STRING)-1)

#ifdef __cplusplus
extern "C" {
#define CBCP_ZERO_INITIALIZER {}
#define CBCP_C_LITERAL(TYPE)
#define CBCP_FLEXIBLE_ARRAY_COUNT(X,Y) X > Y ? 1 : Y
// NOTE(Patrick): The sizeof magic here is used to get the same sizeof behavior as for C.
// The problem is padding and/or the lack thereof.
// The use of long is because it supersedes the size of the word size.
#define CBCP_FLEXIBLE_ARRAY(TYPE, NAME) TYPE NAME[CBCP_FLEXIBLE_ARRAY_COUNT(sizeof(__typeof__(TYPE)),sizeof(long int))]
#define CBCP_FLEXIBLE_SIZEOF(X, FLEXIBLE_ARRAY_MEMBER) (sizeof(X) - sizeof((__typeof__(X)*)NULL)->FLEXIBLE_ARRAY_MEMBER)
#else
#define CBCP_ZERO_INITIALIZER {0}
#define CBCP_C_LITERAL(TYPE) (TYPE)
#define CBCP_FLEXIBLE_ARRAY(TYPE, NAME) TYPE NAME[]
#define CBCP_FLEXIBLE_SIZEOF(X, FLEXIBLE_ARRAY_MEMBER) (sizeof(X))
#endif

#define CBCP_ZERO_LITERAL(TYPE) CBCP_C_LITERAL(TYPE)CBCP_ZERO_INITIALIZER

#define CBCP_FIELD_OFFSET(TYPE, FIELD) ((size_t)&(((TYPE *)0)->FIELD))


#ifdef __cplusplus
#define CBCP_STATUS(type, value) {type ## __ ## value}
#else
#define CBCP_STATUS(type, value) ((type){type ## __ ## value})
#endif

typedef enum {
	CBCP_STATUS_SUCCESS = 0,
	CBCP_STATUS_ERROR = -1
} CBCP_Status;

typedef int CBCP_Bool;
enum {
	CBCP_FALSE = 0,
	CBCP_TRUE = 1
};

typedef uint16_t CBCP_Sequence_Number;
enum { CBCP_INVALID_SEQUENCE_NUMBER = ((CBCP_Sequence_Number)(~0)) };

typedef struct CBCP_Own_Command CBCP_Own_Command;
typedef struct CBCP_Remote_Command CBCP_Remote_Command;
typedef struct CBCP_Command CBCP_Command;
typedef struct CBCP_Remote_Interface CBCP_Remote_Interface;
typedef struct CBCP_Own_Interface CBCP_Own_Interface;
typedef struct CBCP_Group CBCP_Group;
typedef struct CBCP_RSA_Key CBCP_RSA_Key;
typedef struct CBCP_License CBCP_License;
typedef struct CBCP_Additional_Authenticated_Data CBCP_Additional_Authenticated_Data;
typedef struct CBCP_Net_Implementation CBCP_Net_Implementation;
typedef struct CBCP_Net_Address CBCP_Net_Address;
typedef struct CBCP_Host CBCP_Host;
typedef struct CBCP_Connection CBCP_Connection;
typedef struct CBCP_State CBCP_State;

typedef struct {
	CBCP_Bool success;
	void *payload;
	unsigned int payload_length;
} CBCP_Response;

typedef struct {
	void *payload;
	unsigned int payload_length;
	void *response_payload;
	unsigned int response_payload_length;
	unsigned int response_payload_max_length;
	void *host_user_data;
	void *user_data;
	CBCP_State *cbcp;
} CBCP_Command_Args;

typedef struct {
	CBCP_Response response;
	void *user_data;
} CBCP_Response_Args;

typedef enum {
	CBCP_COMMAND_REJECTED_REASON_PACKET_TOO_SMALL = 0x1,
	CBCP_COMMAND_REJECTED_REASON_INVALID_HOST_ID = 0x2,
	CBCP_COMMAND_REJECTED_REASON_OPENSSL_ERROR = 0x3,
	CBCP_COMMAND_REJECTED_REASON_HEADER_DECRYPTION_FAILED = 0x4,
	CBCP_COMMAND_REJECTED_REASON_PAYLOAD_EXCEEDS_RECEIVE_BUFFER = 0x5,
	CBCP_COMMAND_REJECTED_REASON_PAYLOAD_DECRYPTION_FAILED = 0x6,
	CBCP_COMMAND_REJECTED_REASON_INVALID_INTERFACE_ID = 0x7,
	CBCP_COMMAND_REJECTED_REASON_INVALID_CAPABILITY_ID = 0x8,
	CBCP_COMMAND_REJECTED_REASON_INVALID_COMMAND_ID = 0x9,
	CBCP_COMMAND_REJECTED_REASON_COMMAND_NOT_IMPLEMENTED = 0xA,
	CBCP_COMMAND_REJECTED_REASON_RESPONSE_BUFFER_TOO_SMALL = 0xB,
	CBCP_COMMAND_REJECTED_REASON_INVALID_CAPABILITY = 0xC
} CBCP_Command_Rejected_Reason;

typedef struct {
	void *user_data;
	CBCP_Command_Rejected_Reason reason;
} CBCP_Command_Rejected_Args;

typedef void (* CBCP_Command_Callback)(CBCP_Command_Args *args);
typedef void (* CBCP_Response_Callback)(CBCP_Response_Args *args);
typedef void (* CBCP_Command_Rejected_Callback)(CBCP_Command_Rejected_Args args);

#define CBCP_NET_INIT_FUNC(name) CBCP_Status name(void *implementation_state, void *own_address)
typedef CBCP_NET_INIT_FUNC(CBCP_Net_Init_Own_Address_Func);

#define CBCP_NET_PARSE_ADDRESS_STRING_FUNC(name) CBCP_Status name(char *address_string, unsigned int address_string_length, void *address_memory)
typedef CBCP_NET_PARSE_ADDRESS_STRING_FUNC(CBCP_Net_Parse_Address_String_Func);

#define CBCP_NET_SEND_FUNC(name) CBCP_Status name(void *implementation_state, void *connection_state, char *send_buffer, unsigned int send_buffer_length)
typedef CBCP_NET_SEND_FUNC(CBCP_Net_Send_Func);

#define CBCP_NET_RECEIVE_FUNC(name) CBCP_Status name(void *implementation_state, void *connection_state, char *receive_buffer, unsigned int receive_buffer_length, int *out_amount_received) // NOTE(jakob & jørn): -1 means no packet available
typedef CBCP_NET_RECEIVE_FUNC(CBCP_Net_Receive_Func);

#define CBCP_NET_CLIENT_OPEN_CONNECTION_FUNC(name) CBCP_Status name(void *implementation_state, void *impl_address, CBCP_Bool is_control, void *connection_state_memory)
typedef CBCP_NET_CLIENT_OPEN_CONNECTION_FUNC(CBCP_Net_Client_Open_Connection_Func);

#define CBCP_NET_SERVER_ACCEPT_CONNECTION_FUNC(name) CBCP_Status name(void *implementation_state, CBCP_Bool is_control, void *connection_state_memory, CBCP_Bool *out_should_try_again)
typedef CBCP_NET_SERVER_ACCEPT_CONNECTION_FUNC(CBCP_Net_Server_Accept_Connection_Func);

#define CBCP_NET_CLOSE_CONNECTION_FUNC(name) CBCP_Status name(void *implementation_state, void *connection_state)
typedef CBCP_NET_CLOSE_CONNECTION_FUNC(CBCP_Net_Close_Connection_Func);


struct CBCP_Net_Implementation {
	void *implementation_state;
	CBCP_Net_Init_Own_Address_Func *init_own_address;
	CBCP_Net_Parse_Address_String_Func *parse_address_string;
	CBCP_Net_Send_Func *send;
	CBCP_Net_Receive_Func *receive;
	CBCP_Net_Client_Open_Connection_Func *client_open_connection;
	CBCP_Net_Server_Accept_Connection_Func *server_accept_connection;
	CBCP_Net_Close_Connection_Func *close_connection;

	char *name;
	unsigned int name_length;
	unsigned int size_of_address;
	unsigned int size_of_connection;
	unsigned int size_of_additional_packet_header;
};

typedef struct CBCP_Command_Result {
	void *response_buffer;
	uint16_t response_payload_length;
} CBCP_Command_Result;

/*
** High-level API
*/

CBCP_State              *cbcp_init(const char *cbcp_database_filepath);
CBCP_Command            *cbcp_client_init_command(CBCP_State *cbcp,  const char *host_name, const char *interface_name, const char *command_name);
// TODO(jakob): How do we pick the license to use? Maybe we can use a hash table
// to map from (interface pointer + command number) to the first valid
// license?
CBCP_Response            cbcp_client_send_command(CBCP_Command *command, void *payload, unsigned int payload_length, void *response_buffer, unsigned int response_buffer_length);
void                     cbcp_client_send_command_async(CBCP_Command *command, void *payload, unsigned int payload_length, void *response_buffer, unsigned int response_buffer_length, void *user_data, CBCP_Response_Callback response_callback);
CBCP_Own_Command        *cbcp_server_init_command(CBCP_State *cbcp, const char *interface_name, const char *command_name, CBCP_Command_Callback command_callback, void *user_data, unsigned int max_response_payload_length);
void                     cbcp_server_start(CBCP_State *cbcp);
void                     cbcp_server_start_async(CBCP_State *cbcp);
void                     cbcp_server_wait(CBCP_State *cbcp);

// TODO(Patrick): Jakob might have an opinion as to where this should live
void                     cbcp_set_host_user_data(CBCP_Host *host, void *user_data);

/*
** Low-level API
*/

CBCP_Status              cbcp_load_state(CBCP_State *cbcp, unsigned int cbcp_size, char *cbcp_db_contents, unsigned int cbcp_db_contents_length);
void                     cbcp_debug_print_state(CBCP_State *cbcp);
CBCP_Host               *cbcp_get_remote_host(CBCP_State *cbcp, const char *host_name, unsigned int host_name_length);
CBCP_Remote_Interface   *cbcp_get_remote_interface(CBCP_State *cbcp, const char *remote_interface_name, unsigned int remote_interface_name_length);
CBCP_License            *cbcp_get_remote_interface_license(CBCP_Host *host, CBCP_Remote_Interface *remote_interface);
CBCP_Remote_Command     *cbcp_get_remote_command(CBCP_Remote_Interface *remote_interface, const char *command_name, unsigned int command_name_length);
CBCP_Own_Interface      *cbcp_get_own_interface(CBCP_State *cbcp, char *interface_name, unsigned int interface_name_length);
CBCP_Own_Command        *cbcp_get_own_command(CBCP_Own_Interface *own_interface, char *command_name, unsigned int command_name_length);
CBCP_Net_Implementation *cbcp_get_net_implementation_for_host(CBCP_Host *host);
void                     cbcp_server_set_command_callback(CBCP_Own_Command *own_command, CBCP_Command_Callback command_callback, void *user_data, void *response_buffer, unsigned int response_buffer_length);
void                     cbcp_server_set_command_rejected_callback(CBCP_State *cbcp, CBCP_Command_Rejected_Callback command_rejected_callback, void *user_data);
void                     cbcp_server_disable_command_for_all(CBCP_Own_Command *own_command);
CBCP_Bool                cbcp_is_connection_valid(CBCP_Connection *connection);
CBCP_Status              cbcp_client_handshake(CBCP_State *cbcp, CBCP_Host *host);
CBCP_Status              cbcp_client_connect(CBCP_State *cbcp, CBCP_Host *host, CBCP_Connection *connection);
CBCP_Sequence_Number     cbcp_client_send_command_packet(CBCP_Remote_Command *remote_command, CBCP_License *license, char *packet, unsigned int payload_length, CBCP_Connection *connection);
CBCP_Sequence_Number     cbcp_client_get_command_response(char *response_buffer, unsigned int response_buffer_length, CBCP_Connection *connection, unsigned int *out_response_length);
CBCP_Status              cbcp_server_handshake(CBCP_State *cbcp, CBCP_Net_Implementation *net);
CBCP_Status              cbcp_server_accept_connection(CBCP_Net_Implementation *net_impl, CBCP_Connection *connection, CBCP_Bool *out_should_try_again);
CBCP_Status              cbcp_server_handle_command(CBCP_State *cbcp, char *receive_buffer, unsigned int receive_buffer_length, CBCP_Connection *connection, CBCP_Command_Result *out_command_result);
CBCP_Status              cbcp_server_send_command_response(CBCP_Connection *connection, CBCP_Command_Result command_result);
CBCP_Status              cbcp_close_connection(CBCP_Connection *connection);
CBCP_Net_Implementation *cbcp_net_add_impl(CBCP_Net_Implementation impl);
unsigned int             cbcp_offset_to_command_payload(CBCP_Net_Implementation *net_impl);
unsigned int             cbcp_offset_to_response_payload(CBCP_Net_Implementation *net_impl);
unsigned int             cbcp_size_of_command_packet(unsigned int payload_size, CBCP_Net_Implementation *net_impl);
unsigned int             cbcp_size_of_response_packet(unsigned int payload_size, CBCP_Net_Implementation *net_impl);
unsigned int             cbcp_size_of_connection(CBCP_Net_Implementation *net_impl);
int                      cbcp_size_of_loaded_state(char *cbcp_db_contents, unsigned int cbcp_db_contents_length);
// unsigned int           cbcp_size_of_command_receive_buffer(CBCP_Host *host, unsigned int payload_size);

#ifdef __cplusplus
}
#endif

#endif // CBCP_H
