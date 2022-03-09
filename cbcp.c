#include <cbcp.h>

#include <alloca.h>
#include <assert.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>

#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>


#if !defined(CBCP_MALLOC)
#define CBCP_MALLOC(size) malloc(size)
#endif

#if !defined(CBCP_REALLOC)
#define CBCP_REALLOC(pointer, new_size) realloc((pointer), (new_size))
#endif

#if !defined(CBCP_FREE)
#define CBCP_FREE(pointer) free(pointer)
#endif

#define CBCP_AES_BLOCK_SIZE 16
#define CBCP_AES_GCM_TAG_SIZE CBCP_AES_BLOCK_SIZE
#define CBCP_AES_INITIAL_VECTOR_SIZE CBCP_AES_BLOCK_SIZE

#define CBCP_CAPABILITY_SECRET_SIZE 16
#define CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT 4
#define CBCP_CAPABILITY_KEY_SIZE 128

#define CBCP_MAX_NET_IMPLEMENTATIONS 8

#define CBCP_BYTE_SWAP_64(v) (\
    ((((v) >> 56) & 0xff) <<  0) | \
    ((((v) >> 48) & 0xff) <<  8) | \
    ((((v) >> 40) & 0xff) << 16) | \
    ((((v) >> 32) & 0xff) << 24) | \
    ((((v) >> 24) & 0xff) << 32) | \
    ((((v) >> 16) & 0xff) << 40) | \
    ((((v) >>  8) & 0xff) << 48) | \
    ((((v) >>  0) & 0xff) << 56))

#define CBCP_BYTE_SWAP_32(v) (\
    ((((v) >> 24) & 0xff) <<  0) | \
    ((((v) >> 16) & 0xff) <<  8) | \
    ((((v) >>  8) & 0xff) << 16) | \
    ((((v) >>  0) & 0xff) << 24))

#define CBCP_BYTE_SWAP_16(v) (\
    ((((v) >>  8) & 0xff) << 0) | \
    ((((v) >>  0) & 0xff) << 8))

#if defined(CBCP_LITTLE_ENDIAN) && !defined(CBCP_BIG_ENDIAN)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_64(v) (v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_32(v) (v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_16(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_64(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_32(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_16(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_16(v) CBCP_BYTE_SWAP_16(v)
#elif defined(CBCP_BIG_ENDIAN) && !defined(CBCP_LITTLE_ENDIAN)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_64(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_32(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_16(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_64(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_32(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_16(v) (v)
#else
#error Specify either little endian or big endian (CBCP_LITTLE_ENDIAN or CBCP_BIG_ENDIAN)
#endif

#define CBCP_BYTE_SWAP_64(v) (\
    ((((v) >> 56) & 0xff) <<  0) | \
    ((((v) >> 48) & 0xff) <<  8) | \
    ((((v) >> 40) & 0xff) << 16) | \
    ((((v) >> 32) & 0xff) << 24) | \
    ((((v) >> 24) & 0xff) << 32) | \
    ((((v) >> 16) & 0xff) << 40) | \
    ((((v) >>  8) & 0xff) << 48) | \
    ((((v) >>  0) & 0xff) << 56))

#define CBCP_BYTE_SWAP_32(v) (\
    ((((v) >> 24) & 0xff) <<  0) | \
    ((((v) >> 16) & 0xff) <<  8) | \
    ((((v) >>  8) & 0xff) << 16) | \
    ((((v) >>  0) & 0xff) << 24))

#define CBCP_BYTE_SWAP_16(v) (\
    ((((v) >>  8) & 0xff) << 0) | \
    ((((v) >>  0) & 0xff) << 8))

#if defined(CBCP_LITTLE_ENDIAN) && !defined(CBCP_BIG_ENDIAN)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_64(v) (v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_32(v) (v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_16(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_64(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_32(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_16(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_16(v) CBCP_BYTE_SWAP_16(v)
#elif defined(CBCP_BIG_ENDIAN) && !defined(CBCP_LITTLE_ENDIAN)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_LITTLE_FROM_HOST_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_BIG_FROM_HOST_64(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_32(v) (v)
#define CBCP_ENDIAN_BIG_FROM_HOST_16(v) (v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_64(v) CBCP_BYTE_SWAP_64(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_32(v) CBCP_BYTE_SWAP_32(v)
#define CBCP_ENDIAN_HOST_FROM_LITTLE_16(v) CBCP_BYTE_SWAP_16(v)
#define CBCP_ENDIAN_HOST_FROM_BIG_64(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_32(v) (v)
#define CBCP_ENDIAN_HOST_FROM_BIG_16(v) (v)
#else
#error Specify either little endian or big endian (CBCP_LITTLE_ENDIAN or CBCP_BIG_ENDIAN)
#endif

static void cbcp_serialize_u64(char **destination, uint64_t value)
{
	value = CBCP_ENDIAN_LITTLE_FROM_HOST_64(value);
	memcpy(*destination, &value, sizeof(value));
	*destination += sizeof(value);
}

static uint64_t cbcp_deserialize_u64(char **source)
{
	uint64_t result;
	memcpy(&result, *source, sizeof(result));
	result = CBCP_ENDIAN_HOST_FROM_LITTLE_64(result);
	*source += sizeof(result);

	return result;
}

static void cbcp_serialize_u32(char **destination, uint32_t value)
{
	value = CBCP_ENDIAN_LITTLE_FROM_HOST_32(value);
	memcpy(*destination, &value, sizeof(value));
	*destination += sizeof(value);
}

static uint32_t cbcp_deserialize_u32(char **source)
{
	uint32_t result;
	memcpy(&result, *source, sizeof(result));
	result = CBCP_ENDIAN_HOST_FROM_LITTLE_32(result);
	*source += sizeof(result);

	return result;
}

static void cbcp_serialize_u16(char **destination, uint16_t value)
{
	value = CBCP_ENDIAN_LITTLE_FROM_HOST_16(value);
	memcpy(*destination, &value, sizeof(value));
	*destination += sizeof(value);
}

static uint16_t cbcp_deserialize_u16(char **source)
{
	uint16_t result;
	memcpy(&result, *source, sizeof(result));
	result = CBCP_ENDIAN_HOST_FROM_LITTLE_16(result);
	*source += sizeof(result);

	return result;
}

static void cbcp_serialize_u8(char **destination, uint8_t value)
{
	**destination = value;
	*destination += sizeof(value);
}

static uint8_t cbcp_deserialize_u8(char **source)
{
	uint8_t result;
	result = **source;
	*source += sizeof(result);
	return result;
}

static void cbcp_serialize_byte_array(char **destination, char *source, unsigned int length)
{
	memcpy(*destination, source, length);
	*destination += length;
}

static void cbcp_deserialize_byte_array(char **source, char *destination, unsigned int length)
{
	memcpy(destination, *source, length);
	*source += length;
}

static void cbcp_serialize_length_byte_array_8(char **destination, char *byte_array, unsigned int length)
{
	cbcp_serialize_u8(destination, (uint8_t) length);
	cbcp_serialize_byte_array(destination, byte_array, length);
}

static void cbcp_serialize_length_byte_array_16(char **destination, char *byte_array, unsigned int length)
{
	cbcp_serialize_u16(destination, (uint16_t) length);
	cbcp_serialize_byte_array(destination, byte_array, length);
}

static void cbcp_serialize_zero_bytes(char **destination, unsigned int count)
{
	memset(*destination, 0, count);
	*destination += count;
}


typedef struct CBCP_Capability {
	uint64_t capability_mask;
} CBCP_Capability;

typedef struct CBCP_Capability_Entry {
	CBCP_Capability original_capability;
	CBCP_Capability capability;
} CBCP_Capability_Entry;

typedef union CBCP_Capability_Secret {
	uint8_t secret_8[CBCP_CAPABILITY_SECRET_SIZE/sizeof(uint8_t)];
	uint16_t secret_16[CBCP_CAPABILITY_SECRET_SIZE/sizeof(uint16_t)];
	uint32_t secret_32[CBCP_CAPABILITY_SECRET_SIZE/sizeof(uint32_t)];
	uint64_t secret_64[CBCP_CAPABILITY_SECRET_SIZE/sizeof(uint64_t)];
} CBCP_Capability_Secret;

typedef int CBCP_Verify_Secret_Sizes[
	(
		sizeof(((CBCP_Capability_Secret *)0)->secret_64) == sizeof(((CBCP_Capability_Secret *)0)->secret_32) &&
		sizeof(((CBCP_Capability_Secret *)0)->secret_64) == sizeof(((CBCP_Capability_Secret *)0)->secret_16) &&
		sizeof(((CBCP_Capability_Secret *)0)->secret_64) == sizeof(((CBCP_Capability_Secret *)0)->secret_8)
	)
	? 1 : -1
];

typedef struct CBCP_Capability_Reduction_Field {
	CBCP_Capability subfields[CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT];
} CBCP_Capability_Reduction_Field;


typedef struct {
	uint16_t client_id_at_server;
	char initial_vector[CBCP_AES_INITIAL_VECTOR_SIZE];
	char tag[CBCP_AES_GCM_TAG_SIZE];
} CBCP_Command_Packet_Unencrypted_Header;

typedef struct {
	uint16_t client_id_at_server;

	// Below this comment will be encrypted using symmetric encryption
	uint16_t sequence_number;
	uint16_t client_group_id;
	uint16_t interface_id_at_server;
	uint16_t capability_id;
	uint16_t payload_length;
	uint8_t command_id;
	uint8_t _reserved[3];

	CBCP_Capability_Reduction_Field reduction_field;
	CBCP_Capability_Secret secret;
} CBCP_Command_Packet_Header;

typedef struct {
	char initial_vector[CBCP_AES_INITIAL_VECTOR_SIZE];
	char tag[CBCP_AES_GCM_TAG_SIZE];
} CBCP_Response_Packet_Unencrypted_Header;

typedef struct {
	uint16_t sequence_number;
	uint16_t response_payload_length;
	uint8_t _reserved[12];
} CBCP_Response_Packet_Header;


#define CBCP_UNENCRYPTED_COMMAND_PACKET_HEADER_SIZE (\
	sizeof(((CBCP_Command_Packet_Unencrypted_Header*)0)->client_id_at_server) + \
	sizeof(((CBCP_Command_Packet_Unencrypted_Header*)0)->initial_vector) + \
	sizeof(((CBCP_Command_Packet_Unencrypted_Header*)0)->tag))

#define CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE (\
	sizeof(((CBCP_Command_Packet_Header*)0)->client_id_at_server) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->sequence_number) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->client_group_id) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->interface_id_at_server) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->capability_id) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->payload_length) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->command_id) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->_reserved) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->reduction_field) + \
	sizeof(((CBCP_Command_Packet_Header*)0)->secret))

#define CBCP_UNENCRYPTED_RESPONSE_PACKET_HEADER_SIZE (\
	sizeof(((CBCP_Response_Packet_Unencrypted_Header*)0)->initial_vector) + \
	sizeof(((CBCP_Response_Packet_Unencrypted_Header*)0)->tag))

#define CBCP_ENCRYPTED_RESPONSE_PACKET_HEADER_SIZE (\
	sizeof(((CBCP_Response_Packet_Header*)0)->sequence_number) + \
	sizeof(((CBCP_Response_Packet_Header*)0)->response_payload_length) + \
	sizeof(((CBCP_Response_Packet_Header*)0)->_reserved))


enum CBCP_Connection_State {
	CBCP_CONNECTION_DOWN = 0,
	CBCP_CONNECTION_HANDSHAKE_IN_PROGRESS = 1,
	CBCP_CONNECTION_UP = 2
};

struct CBCP_RSA_Key {
	RSA *key;
};

struct CBCP_License {
	CBCP_Remote_Interface *remote_interface;
	uint16_t interface_id_at_server;
	uint16_t client_group_id;

	CBCP_Capability_Reduction_Field reduction_field;
	CBCP_Capability_Secret secret;
	uint64_t capability_id;
};


struct CBCP_Group {
	char *name;
	uint8_t name_length;
};

struct CBCP_Net_Address {
	void *impl_address;
};

struct CBCP_Host {
	char *name;
	uint8_t name_length;

	void *user_data;

	CBCP_Net_Address net_address;
	CBCP_Net_Implementation *net_impl;
	void *net_control_connection_state;

	CBCP_Bool is_connection_valid;
	unsigned char aes_key[32];
	CBCP_RSA_Key public_key;

	uint16_t client_id_at_server;

	CBCP_Connection *connection;

	unsigned int license_count;
	CBCP_FLEXIBLE_ARRAY(CBCP_License, licenses);
};

struct CBCP_Own_Command {
	CBCP_Command_Callback callback;
	void *user_data;
	void *response_buffer;
	char *name;
	CBCP_Own_Interface *interface;
	unsigned int name_length;
	unsigned int response_buffer_length;
	uint8_t command_id;
};

struct CBCP_Command {
	// TODO(jakob): Add possiblility of addressing groups of hosts as well as
	// just a single host.
	CBCP_State *cbcp;
	CBCP_Host *host;
	CBCP_Remote_Interface *remote_interface;
	CBCP_License *license;
	CBCP_Remote_Command *remote_command;
};

struct CBCP_Own_Interface {
	// Commands this interface must provide according to db
	unsigned int name_length;
	char        *name;

	CBCP_Capability_Secret master_secret;
	uint16_t               capability_entry_count;
	CBCP_Capability_Entry *capability_table;

	unsigned int command_count;
	CBCP_FLEXIBLE_ARRAY(CBCP_Own_Command, commands);
};


struct CBCP_Remote_Command {
	char *name;
	unsigned int name_length;
	unsigned int remote_command_number;
};

struct CBCP_Remote_Interface {
	unsigned int name_length;
	char *name;
	unsigned int command_count;
	CBCP_FLEXIBLE_ARRAY(CBCP_Remote_Command, commands);
};

struct CBCP_Connection {
	CBCP_Net_Implementation *net_impl;
	CBCP_Host *connected_host;
	unsigned int sequence_number;
	CBCP_FLEXIBLE_ARRAY(char, net_connection_memory);
};

typedef struct CBCP_Net_Impl_Server {
	pthread_t handshake_thread;
	pthread_t command_thread;
	CBCP_Net_Implementation *net_impl;
} CBCP_Net_Impl_Server;

struct CBCP_State {

	char *self_name;
	uint8_t self_name_length;
	CBCP_RSA_Key self_public_key;
	CBCP_RSA_Key self_private_key;

	unsigned int self_address_count;
	CBCP_Net_Address *self_addresses;

	unsigned int max_response_packet_header_size;

	unsigned int group_count;
	CBCP_Group **groups;

	unsigned int own_interface_count;
	CBCP_Own_Interface **own_interfaces;

	unsigned int remote_interface_count;
	CBCP_Remote_Interface **remote_interfaces;

	unsigned int host_count;
	CBCP_Host **hosts;

	unsigned int net_implementation_count;
	CBCP_Net_Implementation *net_implementations;
	CBCP_Net_Impl_Server *net_impl_servers;

	unsigned int memory_length;

	pthread_t *server_thread_handle;

	CBCP_Command_Rejected_Callback command_rejected_callback;
	void *command_rejected_callback_user_data;

	// NOTE(jakob): memory is used passed the end of this struct, but we
	// can not use flexible array members in C++
	//char memory[CBCP_FLEXIBLE_ARRAY_LENGTH];
	char padding[4]; // NOTE(Patrick): This is used to obtain 8-byte alignment when not using C11
	CBCP_FLEXIBLE_ARRAY(char, memory);
};

struct CBCP_Init_Context {
	CBCP_State *cbcp;
	size_t memory_size;
	char  *memory_head;
	char  *memory_tail;
	union {
		struct {
			uint16_t group_counter;
			uint16_t interface_counter;
			uint16_t capability_entry_counter;
			uint8_t  command_counter;
			uint8_t  net_address_counter;
		} self_section;
		struct {
			uint16_t interface_counter;
			uint8_t  command_counter;
		} remote_interfaces_section;
		struct {
			uint16_t host_counter;
			uint16_t license_counter;
			uint8_t  net_address_counter;
		} hosts_section;
	} counters;
};

struct CBCP_Calculate_Size_Context {
	unsigned int out_size;
	CBCP_Net_Implementation *net_implementations;
	unsigned int net_implementation_count;
};


//
// GLOBALS
//

static unsigned int cbcp_global_net_implementation_count;
static CBCP_Net_Implementation cbcp_global_net_implementations[CBCP_MAX_NET_IMPLEMENTATIONS];




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


//
// CBCP_CAPABILITIES
//

CBCP_Capability_Secret
cbcp_capability_generate_master_secret(void) {
	CBCP_Capability_Secret result;
	RAND_bytes((unsigned char *)&result.secret_8, sizeof(result));

	return result;
}

CBCP_Capability_Secret
cbcp_capability_compute_secret(
	CBCP_Capability_Secret *master_secret,
	CBCP_Capability_Reduction_Field *reduction_field,
	uint16_t capability_id)
{
	// Recursively check if password is correct.
	CBCP_Capability_Secret result;
	CBCP_Capability_Secret buffer = CBCP_ZERO_INITIALIZER;

	result = *master_secret;

	uint16_t canonical_capability_id = CBCP_ENDIAN_LITTLE_FROM_HOST_16(capability_id);

	// NOTE(jakob): Casting a (uint64_t *) to a (uint32_t *) is defined in the C
	// standard; the alignment requirements of a uint32_t are less strict than
	// the alignment requirements of a uint64_t.
	// From the C99 Standard, Section 6.3.2.3:
	// > A pointer to an object or incomplete type may be converted to a pointer
	// > to a different object or incomplete type. If the resulting pointer is
	// > not correctly aligned 50) for the pointed-to type, the behavior is
	// > undefined. __Otherwise, when converted back again, the result shall
	// > compare equal to the original pointer__.
	buffer.secret_16[0] = canonical_capability_id;

	AES_KEY aes_key;
	AES_set_encrypt_key(
		(const unsigned char *) &result.secret_8,
		CBCP_CAPABILITY_KEY_SIZE,
		&aes_key);

	// NOTE(jørn): We can use ECB here because we are only doing a single block.
	AES_ecb_encrypt(
		(const unsigned char *) &buffer.secret_8,
		(unsigned char *) &result.secret_8,
		&aes_key,
		AES_ENCRYPT);

	for (unsigned int subfield_index = 0;
		subfield_index < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT;
		++subfield_index)
	{
		// Check if the subfield is all ones, then break
		if (~reduction_field->subfields[subfield_index].capability_mask == 0)
		{
			break;
		}

		buffer.secret_64[0] = reduction_field->subfields[subfield_index].capability_mask;
		assert(buffer.secret_64[1] == 0);

		AES_set_encrypt_key(
			(const unsigned char *) &result.secret_8,
			CBCP_CAPABILITY_KEY_SIZE,
			&aes_key);

		AES_ecb_encrypt(
			(const unsigned char *) &buffer.secret_8,
			(unsigned char *) &result.secret_8,
			&aes_key,
			AES_ENCRYPT);
	}
	return result;
}

CBCP_Capability
cbcp_capability_aggregate_reduction_field_and_command(
	uint8_t command_id,
	CBCP_Capability_Reduction_Field *reduction_field)
{

	CBCP_Capability aggregate;
	aggregate.capability_mask = ((uint64_t)1) << command_id;

	for (int i = 0; i < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT - 1; ++i)
	{
		aggregate.capability_mask &= reduction_field->subfields[i].capability_mask;
	}

	return aggregate;
}

CBCP_Bool
cbcp_capability_validate_secret(
	uint8_t command_id,
	CBCP_Capability_Secret *secret,
	CBCP_Capability_Secret *master_secret,
	CBCP_Capability_Reduction_Field *reduction_field,
	uint16_t capability_id,
	CBCP_Capability capability)
{
	CBCP_DEBUG_PRINT(
		"command_id: %u\n"
		"secret: %lx_%lx\n"
		"master_secret: %lx_%lx\n"
		"reduction_field: %lx_%lx_%lx_%lx\n"
		"capability_id: %u\n"
		"capability: %lx\n",
		command_id,
		secret->secret_64[0], secret->secret_64[1],
		master_secret->secret_64[0], master_secret->secret_64[1],
		reduction_field->subfields[0].capability_mask,
			reduction_field->subfields[1].capability_mask,
			reduction_field->subfields[2].capability_mask,
			reduction_field->subfields[3].capability_mask,
		capability_id,
		capability.capability_mask);

	CBCP_Capability aggregate =
		cbcp_capability_aggregate_reduction_field_and_command(command_id, reduction_field);

	if (!(aggregate.capability_mask & capability.capability_mask)) {
		CBCP_DEBUG_PRINT("!(aggregate.capability_mask & capability.capability_mask & command.capability_mask)\n");
		return CBCP_FALSE;
	}

	CBCP_Capability_Secret computed_secret =
			cbcp_capability_compute_secret(master_secret, reduction_field, capability_id);

	if (
		(secret->secret_64[0] != computed_secret.secret_64[0]) ||
		(secret->secret_64[1] != computed_secret.secret_64[1])
	) {
		CBCP_DEBUG_PRINT("(secret->secret_64[0] != computed_secret.secret_64[0]) || (secret->secret_64[1] != computed_secret.secret_64[1])\n");
		return CBCP_FALSE;
	}

	return CBCP_TRUE;
}

//
// END CBCP_CAPABILITIES
//



static void *
cbcp_state_allocate_head(
	struct CBCP_Init_Context *init_context,
	unsigned int size)
{
	char *memory_head = init_context->memory_head;
	char *memory_tail = init_context->memory_tail;

	if((memory_head+size) > memory_tail)
	{
		return NULL;
	}

	init_context->memory_head = memory_head + size;
	return memory_head;
}

static void *
cbcp_state_allocate_tail(
	struct CBCP_Init_Context *init_context,
	unsigned int size)
{
	char *memory_head = init_context->memory_head;
	char *memory_tail = init_context->memory_tail;

	if(memory_head > (memory_tail-size))
	{
		return NULL;
	}

	init_context->memory_tail = memory_tail - size;
	return init_context->memory_tail; // NOTE(Patrick): Memory begins at new tail.
}

static char *
cbcp_internal_allocate_cstring(
	struct CBCP_Init_Context *init_context,
	char *string,
	unsigned int string_length)
{
	CBCP_DEBUG_PRINT("Allocating cstring of length %d: %.*s\n", string_length, string_length, string);

	char *allocated_string = (char*)cbcp_state_allocate_tail(
		init_context,
		string_length);

	if (allocated_string) {
		memcpy(allocated_string, string, string_length);
	}

	return allocated_string;
}

static CBCP_RSA_Key
cbcp_internal_allocate_rsa_key(
	struct CBCP_Init_Context *init_context,
	char *key_data,
	uint32_t key_length,
	CBCP_Bool is_private_key)
{
	(void)init_context;

	assert(key_data != NULL);
	CBCP_DEBUG_PRINT("Allocating RSA key of length %d\n", key_length);

	char *at = key_data;

	CBCP_RSA_Key key = CBCP_ZERO_INITIALIZER;
	key.key = RSA_new();

	// Perform DER deserialization of key
	if (is_private_key) {
		if (NULL == d2i_RSAPrivateKey(&key.key, (const uint8_t **)&at, key_length)) {
			CBCP_DEBUG_PRINT("Could not d2i PrivateKey\n");
		}
	}
	else {
		if (NULL == d2i_RSAPublicKey(&key.key, (const uint8_t **)&at, key_length)) {
			CBCP_DEBUG_PRINT("Could not d2i PublicKey\n");
		}
	}

	return key;
}


typedef struct CBCP_Internal_Db_Self_Section
{
	uint8_t name_length;
	char *name;
	uint8_t address_count;
	uint16_t group_count;
	uint16_t own_interface_count;
	uint16_t private_rsa_key_length;
	char *public_rsa_key;
	uint16_t public_rsa_key_length;
	char *private_rsa_key;
} CBCP_Internal_Db_Self_Section;

typedef struct CBCP_Internal_Db_Net_Address
{
	uint8_t protocol_length;
	char *protocol;
	uint16_t address_length;
	char *address;
} CBCP_Internal_Db_Net_Address;

typedef struct CBCP_Internal_Db_Group
{
	uint8_t name_length;
	char *name;
} CBCP_Internal_Db_Group;

typedef struct CBCP_Internal_Db_Interface
{
	char *name;
	uint8_t name_length;
	CBCP_Capability_Secret master_secret;
	uint16_t capability_entry_count;
	uint8_t command_count;
} CBCP_Internal_Db_Interface;

typedef struct CBCP_Internal_Db_Capability_Entry
{
	uint64_t capability_mask;
} CBCP_Internal_Db_Capability_Entry;

typedef struct CBCP_Internal_Db_Command
{
	char *name;
	uint8_t name_length;
	uint8_t command_id;
} CBCP_Internal_Db_Command;


typedef struct CBCP_Internal_Db_Remote_Interfaces_Section
{
	unsigned int number_of_remote_interfaces;
} CBCP_Internal_Db_Remote_Interfaces_Section;

typedef struct CBCP_Internal_Db_Remote_Interface
{
	char *name;
	uint8_t name_length;
	uint8_t number_of_commands;
} CBCP_Internal_Db_Remote_Interface;

typedef struct CBCP_Internal_Db_Remote_Command
{
	char *name;
	uint8_t name_length;
	uint8_t command_id;
} CBCP_Internal_Db_Remote_Command;

typedef struct CBCP_Internal_Db_Hosts_Section
{
	unsigned int number_of_hosts;
} CBCP_Internal_Db_Hosts_Section;

typedef struct CBCP_Internal_Db_Host
{
	char *name;
	uint8_t name_length;
	char *address_protocol;
	uint8_t address_protocol_length;
	char *address;
	uint16_t address_length;
	char *public_rsa_key;
	uint16_t public_rsa_key_length;
	uint16_t number_of_licenses;
} CBCP_Internal_Db_Host;

typedef struct CBCP_Internal_Db_License
{
	uint16_t interface_id_at_client;
	uint16_t interface_id_at_server;
	uint16_t client_group_id;

	CBCP_Capability_Reduction_Field reduction_field;
	CBCP_Capability_Secret secret;
	uint64_t capability_id;
} CBCP_Internal_Db_License;

typedef struct CBCP_Database_Visitors
{
	CBCP_Status (*self_section)(void *custom_data, CBCP_Internal_Db_Self_Section *);
	CBCP_Status (*self_section_interface)(void *custom_data, CBCP_Internal_Db_Interface *);
	CBCP_Status (*self_section_capability_entry)(void *custom_data, CBCP_Internal_Db_Capability_Entry *);
	CBCP_Status (*self_section_command)(void *custom_data, CBCP_Internal_Db_Command *);
	CBCP_Status (*self_section_net_address)(void* custom_data, CBCP_Internal_Db_Net_Address *);
	CBCP_Status (*self_section_group)(void *custom_data, CBCP_Internal_Db_Group *);

	CBCP_Status (*remote_interfaces_section)(void *custom_data, CBCP_Internal_Db_Remote_Interfaces_Section *);
	CBCP_Status (*remote_interface)(void *custom_data, CBCP_Internal_Db_Remote_Interface *);
	CBCP_Status (*remote_command)(void *custom_data, CBCP_Internal_Db_Remote_Command *);

	CBCP_Status (*hosts_section)(void *custom_data, CBCP_Internal_Db_Hosts_Section *);
	CBCP_Status (*host)(void *custom_data, CBCP_Internal_Db_Host *);
	CBCP_Status (*license)(void *custom_data, CBCP_Internal_Db_License *);
} CBCP_Database_Visitors;

static CBCP_Bool
cbcp_length_strings_are_equal(
	char *string1,
	unsigned int string1_length,
	char *string2,
	unsigned int string2_length)
{
	if (string1_length == string2_length) {
		if (strncmp(string1, string2, string1_length) == 0) {
			return CBCP_TRUE;
		}
	}

	return CBCP_FALSE;
}

static CBCP_Net_Implementation *
cbcp_net_implementation_from_name(
	CBCP_Net_Implementation *net_implementations,
	unsigned int net_implementation_count,
	char *name,
	unsigned int name_length)
{
	for (unsigned int i = 0; i < net_implementation_count; ++i) {
		CBCP_Net_Implementation *net_impl = &net_implementations[i];
		if (cbcp_length_strings_are_equal(
			net_impl->name,
			net_impl->name_length,
			name,
			name_length)
		) {
			return net_impl;
		}
	}

	return NULL;
}

static CBCP_Status
cbcp_internal_load_database
(
	char *cbcp_db_contents,
	unsigned int cbcp_db_contents_length,
	void *custom_data,
	CBCP_Database_Visitors *visitors);


// CBCP SIZE VISITORS
static CBCP_Status
cbcp_internal_calculate_size_visit_self_section(
	void *custom_data,
	CBCP_Internal_Db_Self_Section *self_section)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int size = CBCP_FLEXIBLE_SIZEOF(CBCP_State, memory);

	size += self_section->name_length;
	size += self_section->own_interface_count * sizeof(CBCP_Own_Interface*);
	size += self_section->address_count * sizeof(CBCP_Net_Address);
	size += self_section->group_count * sizeof(CBCP_Group*);
	CBCP_DEBUG_PRINT("self section allocation size: %d\n", size);
	calculate_size_context->out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_interface(
	void *custom_data,
	CBCP_Internal_Db_Interface *interface)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += CBCP_FLEXIBLE_SIZEOF(CBCP_Own_Interface, commands);
	size += interface->name_length;
	size += interface->capability_entry_count * sizeof(CBCP_Capability_Entry);
	size += interface->command_count * sizeof(CBCP_Own_Command);
	CBCP_DEBUG_PRINT("interface allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_command(
	void *custom_data,
	CBCP_Internal_Db_Command *command)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += command->name_length;
	CBCP_DEBUG_PRINT("command allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_vist_self_net_address(
	void *custom_data,
	CBCP_Internal_Db_Net_Address *db_net_address)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	CBCP_Net_Implementation *net_implementations = calculate_size_context->net_implementations;
	unsigned int net_implementation_count = calculate_size_context->net_implementation_count;
	unsigned int size = 0;

	CBCP_Net_Implementation *net_impl = cbcp_net_implementation_from_name(
		net_implementations,
		net_implementation_count,
		db_net_address->protocol,
		db_net_address->protocol_length);

	if (net_impl == NULL) {
		CBCP_DEBUG_PRINT("Required network implementation not found: '%.*s'.\n",
			db_net_address->protocol_length,
			db_net_address->protocol);
		return CBCP_STATUS_ERROR;
	}

	size += net_impl->size_of_address;

	CBCP_DEBUG_PRINT("net address allocation size: %d\n", size);
	calculate_size_context->out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_self_group(
	void *custom_data,
	CBCP_Internal_Db_Group *db_group)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += sizeof(CBCP_Group);
	size += db_group->name_length;
	CBCP_DEBUG_PRINT("group allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_remote_interfaces_section(
	void *custom_data,
	CBCP_Internal_Db_Remote_Interfaces_Section *remote_interfaces)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += remote_interfaces->number_of_remote_interfaces * sizeof(CBCP_Remote_Interface*);
	CBCP_DEBUG_PRINT("remote interfaces section allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_remote_interface(
	void *custom_data,
	CBCP_Internal_Db_Remote_Interface *remote_interface)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += CBCP_FLEXIBLE_SIZEOF(CBCP_Remote_Interface, commands);
	size += remote_interface->name_length;
	size += remote_interface->number_of_commands * sizeof(CBCP_Remote_Command);
	CBCP_DEBUG_PRINT("remote interface allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_remote_command(
	void *custom_data,
	CBCP_Internal_Db_Remote_Command *remote_command)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += remote_command->name_length;
	CBCP_DEBUG_PRINT("remote command allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_hosts_section(
	void *custom_data,
	CBCP_Internal_Db_Hosts_Section *hosts)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	unsigned int *out_size = &calculate_size_context->out_size;
	unsigned int size = 0;
	size += hosts->number_of_hosts * sizeof(CBCP_Host*);
	CBCP_DEBUG_PRINT("hosts section allocation size: %d\n", size);
	*out_size += size;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_calculate_size_visit_host(
	void *custom_data,
	CBCP_Internal_Db_Host *host)
{
	struct CBCP_Calculate_Size_Context *calculate_size_context = (struct CBCP_Calculate_Size_Context *)custom_data;
	CBCP_Net_Implementation *net_implementations = calculate_size_context->net_implementations;
	unsigned int net_implementation_count = calculate_size_context->net_implementation_count;
	CBCP_Net_Implementation *net_impl =
		cbcp_net_implementation_from_name(
			net_implementations,
			net_implementation_count,
			host->address_protocol,
			host->address_protocol_length);

	if (net_impl == NULL) {
		return CBCP_STATUS_ERROR;
	}

	unsigned int size = CBCP_FLEXIBLE_SIZEOF(CBCP_Host, licenses);

	size += host->name_length;
	size += net_impl->size_of_address;
	//size += 2 * net_impl->connection_size; // times two because: One control connection, one command connection
	size += 1 * net_impl->size_of_connection; // NOTE(Patrick): the command connection is getting externalized.
	size += cbcp_size_of_connection(net_impl); // For host->connection
	size += host->number_of_licenses * sizeof(CBCP_License);
	CBCP_DEBUG_PRINT("host allocation size: %d\n", size);
	calculate_size_context->out_size += size;
	return CBCP_STATUS_SUCCESS;
}



// CBCP ALLOCATION VISITORS
static CBCP_Status
cbcp_internal_init_visit_self_section(
	void *custom_data,
	CBCP_Internal_Db_Self_Section *self_section)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	cbcp->self_name = cbcp_internal_allocate_cstring(
		init_context,
		self_section->name,
		self_section->name_length);

	if (cbcp->self_name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->self_name_length = self_section->name_length;

	cbcp->self_public_key = cbcp_internal_allocate_rsa_key(
		init_context,
		self_section->public_rsa_key,
		self_section->public_rsa_key_length,
		CBCP_FALSE);

	if (cbcp->self_public_key.key == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->self_private_key = cbcp_internal_allocate_rsa_key(
		init_context,
		self_section->private_rsa_key,
		self_section->private_rsa_key_length,
		CBCP_TRUE);

	if (cbcp->self_private_key.key == NULL) {
		return CBCP_STATUS_ERROR;
	}


	cbcp->own_interface_count = self_section->own_interface_count;
	cbcp->own_interfaces = (CBCP_Own_Interface **)cbcp_state_allocate_head(
		init_context,
		self_section->own_interface_count * sizeof(CBCP_Own_Interface*));

	if (cbcp->own_interfaces == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->self_address_count = self_section->address_count;
	cbcp->self_addresses = (CBCP_Net_Address *)cbcp_state_allocate_head(
		init_context,
		self_section->address_count * sizeof(CBCP_Net_Address));

	if (cbcp->self_addresses == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->group_count = self_section->group_count;
	cbcp->groups = (CBCP_Group **)cbcp_state_allocate_head(
		init_context,
		self_section->group_count * sizeof(CBCP_Group*));

	if (cbcp->groups == NULL) {
		return CBCP_STATUS_ERROR;
	}

	init_context->counters.self_section.interface_counter = 0;
	init_context->counters.self_section.command_counter = 0;
	init_context->counters.self_section.group_counter = 0;
	init_context->counters.self_section.net_address_counter = 0;
	init_context->counters.self_section.capability_entry_counter = 0;

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_interface(
	void *custom_data,
	CBCP_Internal_Db_Interface *db_interface)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Own_Interface *interface = (CBCP_Own_Interface *)cbcp_state_allocate_head(
		init_context,
		CBCP_FLEXIBLE_SIZEOF(CBCP_Own_Interface, commands)
			+ (db_interface->command_count * sizeof(CBCP_Own_Command)));

	if (interface == NULL) {
		return CBCP_STATUS_ERROR;
	}

	interface->name = cbcp_internal_allocate_cstring(
		init_context,
		db_interface->name,
		db_interface->name_length);
	interface->name_length = db_interface->name_length;
	interface->command_count = db_interface->command_count;

	if (interface->name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	interface->master_secret = db_interface->master_secret;
	interface->capability_entry_count = db_interface->capability_entry_count;
	interface->capability_table = (CBCP_Capability_Entry *)cbcp_state_allocate_head(
		init_context,
		db_interface->capability_entry_count * sizeof(CBCP_Capability_Entry));

	if(interface->capability_table == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->own_interfaces[init_context->counters.self_section.interface_counter] = interface;
	++(init_context->counters.self_section.interface_counter);
	init_context->counters.self_section.command_counter = 0;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_capability_entry(
	void *custom_data,
	CBCP_Internal_Db_Capability_Entry *db_capability_entry)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Own_Interface *interface =
		cbcp->own_interfaces[init_context->counters.self_section.interface_counter-1];
	assert(init_context->counters.self_section.capability_entry_counter
		< interface->capability_entry_count);
	CBCP_Capability_Entry *capability_entry =
		&(interface->capability_table[init_context->counters.self_section.capability_entry_counter]);

	uint64_t cap_mask = db_capability_entry->capability_mask;

	capability_entry->original_capability.capability_mask = cap_mask;
	capability_entry->capability.capability_mask = cap_mask;

	++(init_context->counters.self_section.capability_entry_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_command(
	void *custom_data,
	CBCP_Internal_Db_Command *db_command)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Own_Interface *interface =
		cbcp->own_interfaces[init_context->counters.self_section.interface_counter-1];
	assert(init_context->counters.self_section.command_counter < interface->command_count);
	CBCP_Own_Command *command =
		&(interface->commands[init_context->counters.self_section.command_counter]);

	command->name = cbcp_internal_allocate_cstring(
		init_context,
		db_command->name,
		db_command->name_length);

	if (command->name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	command->name_length = db_command->name_length;

	command->interface = interface;

	command->callback = NULL;
	command->user_data = NULL;
	command->command_id = db_command->command_id;

	++(init_context->counters.self_section.command_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_self_net_address(
	void *custom_data,
	CBCP_Internal_Db_Net_Address *db_net_address)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Net_Implementation *net_implementations = init_context->cbcp->net_implementations;
	unsigned int net_implementation_count = init_context->cbcp->net_implementation_count;

	CBCP_Net_Implementation *net_impl = cbcp_net_implementation_from_name(
		net_implementations,
		net_implementation_count,
		db_net_address->protocol,
		db_net_address->protocol_length);

	if (net_impl == NULL) {
		CBCP_DEBUG_PRINT("Required network implementation not found: '%.*s'.\n",
			db_net_address->protocol_length,
			db_net_address->protocol);
		return CBCP_STATUS_ERROR;
	}

	CBCP_Net_Address net_address = CBCP_ZERO_INITIALIZER;

	net_address.impl_address =
		cbcp_state_allocate_head(
			init_context,
			net_impl->size_of_address);

	if (net_address.impl_address == NULL) {
		return CBCP_STATUS_ERROR;
	}

	if (net_impl->parse_address_string(
		db_net_address->address,
		db_net_address->address_length,
		net_address.impl_address) == -1
	) {
		CBCP_DEBUG_PRINT("Could not parse network address in self section: '%.*s%s'\n",
			db_net_address->address_length > 8 ? 5 : db_net_address->address_length,
			db_net_address->address,
			db_net_address->address_length > 8 ? "..." : "");
		return CBCP_STATUS_ERROR;
	}

	if (net_impl->init_own_address(
		net_impl->implementation_state,
		net_address.impl_address) == -1
	) {
		CBCP_DEBUG_PRINT("Could not initialize network address in self section, '%.*s%s'\n",
			db_net_address->address_length > 8 ? 5 : db_net_address->address_length,
			db_net_address->address,
			db_net_address->address_length > 8 ? "..." : "");
		return CBCP_STATUS_ERROR;
	}

	cbcp->self_addresses[init_context->counters.self_section.net_address_counter] = net_address;
	++(init_context->counters.self_section.net_address_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_self_group(
	void *custom_data,
	CBCP_Internal_Db_Group *db_group)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Group *group = (CBCP_Group *)cbcp_state_allocate_head(
		init_context,
		sizeof(CBCP_Group));

	if (group == NULL) {
		return CBCP_STATUS_ERROR;
	}

	group->name = cbcp_internal_allocate_cstring(
		init_context,
		db_group->name,
		db_group->name_length);
	group->name_length = db_group->name_length;

	if (group->name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	cbcp->groups[init_context->counters.self_section.group_counter] = group;
	++(init_context->counters.self_section.group_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_remote_interfaces_section(
	void *custom_data,
	CBCP_Internal_Db_Remote_Interfaces_Section *remote_interfaces)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	cbcp->remote_interface_count = remote_interfaces->number_of_remote_interfaces;
	cbcp->remote_interfaces = (CBCP_Remote_Interface **)cbcp_state_allocate_head(
		init_context,
		remote_interfaces->number_of_remote_interfaces * sizeof(CBCP_Remote_Interface*));

	if (cbcp->remote_interfaces == NULL) {
		return CBCP_STATUS_ERROR;
	}

	init_context->counters.remote_interfaces_section.interface_counter = 0;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_remote_interface(
	void *custom_data,
	CBCP_Internal_Db_Remote_Interface *db_remote_interface)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Remote_Interface *remote_interface = (CBCP_Remote_Interface *)cbcp_state_allocate_head(
		init_context,
		CBCP_FLEXIBLE_SIZEOF(CBCP_Remote_Interface, commands)
			+ (db_remote_interface->number_of_commands * sizeof(CBCP_Remote_Command)));

	if (remote_interface == NULL) {
		return CBCP_STATUS_ERROR;
	}

	remote_interface->name = cbcp_internal_allocate_cstring(
		init_context,
		db_remote_interface->name,
		db_remote_interface->name_length);
	remote_interface->name_length = db_remote_interface->name_length;
	remote_interface->command_count = db_remote_interface->number_of_commands;

	cbcp->remote_interfaces[init_context->counters.remote_interfaces_section.interface_counter] = remote_interface;
	++(init_context->counters.remote_interfaces_section.interface_counter);
	init_context->counters.remote_interfaces_section.command_counter = 0;

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_remote_command(
	void *custom_data,
	CBCP_Internal_Db_Remote_Command *db_remote_command)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	unsigned int command_counter = init_context->counters.remote_interfaces_section.command_counter;

	CBCP_Remote_Interface *remote_interface =
		cbcp->remote_interfaces[init_context->counters.remote_interfaces_section.interface_counter-1];
	assert(command_counter < remote_interface->command_count);
	CBCP_Remote_Command *remote_command = &(remote_interface->commands[command_counter]);

	remote_command->name = cbcp_internal_allocate_cstring(
		init_context,
		db_remote_command->name,
		db_remote_command->name_length);

	if (remote_command->name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	remote_command->name_length = db_remote_command->name_length;

	remote_command->remote_command_number = db_remote_command->command_id;

	++(init_context->counters.remote_interfaces_section.command_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_hosts_section(
	void *custom_data,
	CBCP_Internal_Db_Hosts_Section *hosts)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	cbcp->host_count = hosts->number_of_hosts;
	cbcp->hosts = (CBCP_Host **)cbcp_state_allocate_head(
		init_context,
		hosts->number_of_hosts * sizeof(CBCP_Host*));

	if (cbcp->hosts == NULL) {
		return CBCP_STATUS_ERROR;
	}

	init_context->counters.hosts_section.host_counter = 0;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_host(
	void *custom_data,
	CBCP_Internal_Db_Host *db_host)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Net_Implementation *net_implementations = init_context->cbcp->net_implementations;
	unsigned int net_implementation_count = init_context->cbcp->net_implementation_count;

	CBCP_Net_Implementation *net_impl = cbcp_net_implementation_from_name(
		net_implementations,
		net_implementation_count,
		db_host->address_protocol,
		db_host->address_protocol_length);

	if (net_impl == NULL) {
		CBCP_DEBUG_PRINT("Required network implementation not found: '%.*s'.\n",
			db_host->address_protocol_length,
			db_host->address_protocol);
		return CBCP_STATUS_ERROR;
	}

	CBCP_Net_Address net_address = CBCP_ZERO_INITIALIZER;

	net_address.impl_address =
		cbcp_state_allocate_head(
			init_context,
			net_impl->size_of_address);

	if (net_address.impl_address == NULL) {
		return CBCP_STATUS_ERROR;
	}

	if (net_impl->parse_address_string(
		db_host->address,
		db_host->address_length,
		net_address.impl_address) == -1
	) {
		CBCP_DEBUG_PRINT("Could not parse network address: '%.*s%s'\n",
			db_host->address_length > 8 ? 5 : db_host->address_length,
			db_host->address,
			db_host->address_length > 8 ? "..." : "");
		return CBCP_STATUS_ERROR;
	}

	CBCP_Host *host = (CBCP_Host *)cbcp_state_allocate_head(
		init_context,
		CBCP_FLEXIBLE_SIZEOF(CBCP_Host, licenses)
			+ (db_host->number_of_licenses * sizeof(CBCP_License)));

	if (host == NULL) {
		return CBCP_STATUS_ERROR;
	}

	// NOTE(jakob & patrick): {
	// this does not work in C++ because of the flexible array member:
	// *host = CBCP_ZERO_LITERAL(CBCP_Host);
	// Instead we must do this:
	memset((void *)host, 0, CBCP_FLEXIBLE_SIZEOF(CBCP_Host, licenses));
	// }

	host->name = cbcp_internal_allocate_cstring(
		init_context,
		db_host->name,
		db_host->name_length);

	if (host->name == NULL) {
		return CBCP_STATUS_ERROR;
	}

	host->name_length = db_host->name_length;
	host->net_address = net_address;
	host->net_impl = net_impl;
	host->net_control_connection_state =
		cbcp_state_allocate_head(
			init_context,
			net_impl->size_of_connection);

	host->connection = (CBCP_Connection *)
		cbcp_state_allocate_head(
			init_context,
			cbcp_size_of_connection(net_impl));

	memset(host->connection, 0, cbcp_size_of_connection(net_impl));

	host->connection->connected_host = host;
	host->connection->net_impl = net_impl;

	host->public_key = cbcp_internal_allocate_rsa_key(
		init_context,
		db_host->public_rsa_key,
		db_host->public_rsa_key_length,
		CBCP_FALSE);

	if (host->public_key.key == NULL) {
		return CBCP_STATUS_ERROR;
	}


	host->license_count = db_host->number_of_licenses;

	cbcp->hosts[init_context->counters.hosts_section.host_counter] = host;
	++(init_context->counters.hosts_section.host_counter);
	init_context->counters.hosts_section.license_counter = 0;

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_init_visit_license(
	void *custom_data,
	CBCP_Internal_Db_License *db_license)
{
	struct CBCP_Init_Context *init_context =
		(struct CBCP_Init_Context *)custom_data;
	CBCP_State *cbcp = init_context->cbcp;

	CBCP_Host *host = cbcp->hosts[init_context->counters.hosts_section.host_counter-1];

	assert(init_context->counters.hosts_section.license_counter < host->license_count);
	CBCP_License *license = &(host->licenses[init_context->counters.hosts_section.license_counter]);

	CBCP_Remote_Interface *remote_interface = cbcp->remote_interfaces[db_license->interface_id_at_client];

	license->remote_interface = remote_interface;
	license->interface_id_at_server = db_license->interface_id_at_server;
	license->client_group_id = db_license->client_group_id;
	license->reduction_field = db_license->reduction_field;
	license->secret = db_license->secret;
	license->capability_id = db_license->capability_id;

	++(init_context->counters.hosts_section.license_counter);
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Bool
cbcp_is_little_endian() {
	uint16_t two_bytes = 1;
	char *first_byte_address = (char *)&two_bytes;
	char first_byte = *first_byte_address;
	return first_byte == 1;
}

static CBCP_Status
cbcp_internal_cbcpdb_get_byte_array_reference_8
(
	char **cursor_pointer,
	char *end,
	uint8_t *out_length,
	char **out_string)
{
	char *cursor = *cursor_pointer;

	uint8_t length = cbcp_deserialize_u8(&cursor);

	if (cursor + length > end) {
		return CBCP_STATUS_ERROR;
	}

	CBCP_DEBUG_PRINT("Read string of length: %d\n", length);
	char *string = cursor;
	CBCP_DEBUG_PRINT("\tstring: %.*s\n", length, string);
	cursor += length;

	*out_length = length;
	*out_string = string;

	*cursor_pointer = cursor;
	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_internal_cbcpdb_get_byte_array_reference_16
(
	char **cursor_pointer,
	char *end,
	uint16_t *out_length,
	char **out_data)
{
	char *cursor = *cursor_pointer;

	uint16_t length = cbcp_deserialize_u16(&cursor);

	if(cursor + length > end) {
		return CBCP_STATUS_ERROR;
	}

	char *data = cursor;
	cursor += length;

	*out_length = length;
	*out_data = data;
	*cursor_pointer = cursor;
	return CBCP_STATUS_SUCCESS;
}



static CBCP_Status
cbcp_internal_load_database
(
	char *cbcp_db_contents,
	unsigned int cbcp_db_contents_length,
	void *custom_data,
	CBCP_Database_Visitors *visitors)
{
	char *cursor = cbcp_db_contents;
	char *end = cbcp_db_contents + cbcp_db_contents_length;
	char *cursor_test = NULL;

	if(visitors == NULL)
	{
		assert(0);return CBCP_STATUS_ERROR;
	}

	unsigned int size_of_header = 28; // @By_Spec

	//NOTE(Patrick): With this check we know that we do not need to check if we get errors when reading the header fields in.
	if(cbcp_db_contents_length < size_of_header)
	{
		assert(0);return CBCP_STATUS_ERROR;
	}

	const char *cbcp_magic_signature = "cbcpdata";
	unsigned int cbcp_magic_signature_length = sizeof("cbcpdata")-1;

	// Correct filetype?
	if(strncmp(cbcp_db_contents, cbcp_magic_signature, cbcp_magic_signature_length) != 0)
	{
		assert(0);return CBCP_STATUS_ERROR;
	}

	cursor += cbcp_magic_signature_length;

	// Version compatibility check
	uint16_t db_major_version = cbcp_deserialize_u16(&cursor);
	uint16_t db_minor_version = cbcp_deserialize_u16(&cursor);

	if ((db_major_version != CBCP_DATABASE_MAJOR_VERSION) ||
		(db_minor_version != CBCP_DATABASE_MINOR_VERSION)
	) {
		assert(0);return CBCP_STATUS_ERROR;
	}

	// Checksum check
	uint32_t checksum = cbcp_deserialize_u32(&cursor);
	uint32_t self_section_start = cbcp_deserialize_u32(&cursor);
	uint32_t remote_interfaces_start = cbcp_deserialize_u32(&cursor);
	uint32_t host_records_start = cbcp_deserialize_u32(&cursor);

	#ifndef NDEBUG
	CBCP_DEBUG_PRINT(
		"Header information:\n"
		"Magic: %.*s\n"
		"Major version: %d\n"
		"Minor version: %d\n"
		"Checksum: %x\n"
		"Self section start:          %d\n"
		"Host records start:          %d\n"
		"Remote interfaces start:     %d\n",
		8,cbcp_db_contents,
		db_major_version,
		db_minor_version,
		checksum,
		self_section_start,
		host_records_start,
		remote_interfaces_start
		);
	#endif

	if ((self_section_start >= cbcp_db_contents_length) ||
	    (host_records_start >= cbcp_db_contents_length) ||
	    (remote_interfaces_start >= cbcp_db_contents_length))
	{
		assert(0);return CBCP_STATUS_ERROR;
	}

	// Self section
	{
		cursor = cbcp_db_contents + self_section_start;
		assert(cursor < cbcp_db_contents+cbcp_db_contents_length);

		CBCP_Internal_Db_Self_Section self_section = CBCP_ZERO_INITIALIZER;

		if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
			&cursor,
			end,
			&self_section.name_length,
			&self_section.name) == -1)
		{
			assert(0);return CBCP_STATUS_ERROR;
		}

		cursor_test = cursor +
			sizeof(self_section.address_count) +
			sizeof(self_section.group_count) +
			sizeof(self_section.own_interface_count);

		if (cursor_test < end)
		{
			self_section.address_count = cbcp_deserialize_u8(&cursor);
			self_section.group_count = cbcp_deserialize_u16(&cursor);
			self_section.own_interface_count = cbcp_deserialize_u16(&cursor);
		}
		else {
			assert(0);return CBCP_STATUS_ERROR;
		}

		if(cbcp_internal_cbcpdb_get_byte_array_reference_16(
			&cursor,
			end,
			&self_section.public_rsa_key_length,
			&self_section.public_rsa_key) == -1)
		{
			assert(0);return CBCP_STATUS_ERROR;
		}

		if(cbcp_internal_cbcpdb_get_byte_array_reference_16(
			&cursor,
			end,
			&self_section.private_rsa_key_length,
			&self_section.private_rsa_key) == -1)
		{
			assert(0);return CBCP_STATUS_ERROR;
		}


		CBCP_DEBUG_PRINT(
			"Self section contents:\n"
			"hostname length: %d\n"
			"hostname: %.*s\n"
			"Self address count: %d\n"
			"Group count: %d\n"
			"Interface count: %d\n"
			"public RSA key length: %d\n"
			"private RSA key length: %d\n",
			self_section.name_length,
			self_section.name_length, self_section.name,
			self_section.address_count,
			self_section.group_count,
			self_section.own_interface_count,
			self_section.public_rsa_key_length,
			self_section.private_rsa_key_length
			);

		if(visitors->self_section != NULL) {
			if (visitors->self_section(custom_data, &self_section) == -1) {
				CBCP_DEBUG_PRINT("Deserializer failed on self_section_visitor.\n");
				assert(0);return CBCP_STATUS_ERROR;
			}
		}

		for(unsigned int i = 0; i < self_section.address_count; ++i)
		{
			CBCP_Internal_Db_Net_Address net_address = CBCP_ZERO_INITIALIZER;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&net_address.protocol_length,
				&net_address.protocol) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}
			if(cbcp_internal_cbcpdb_get_byte_array_reference_16(
				&cursor,
				end,
				&net_address.address_length,
				&net_address.address) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			if(visitors->self_section_net_address != NULL) {
				if (visitors->self_section_net_address(custom_data, &net_address) == -1) {
					CBCP_DEBUG_PRINT("Deserializer failed on self_section_net_address.\n");
					assert(0);return CBCP_STATUS_ERROR;
				}
			}
		}

		for(unsigned int i = 0; i < self_section.group_count; ++i)
		{
			CBCP_Internal_Db_Group group = CBCP_ZERO_INITIALIZER;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&group.name_length,
				&group.name) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			if(visitors->self_section_group != NULL) {
				if (visitors->self_section_group(custom_data, &group) == -1) {
					CBCP_DEBUG_PRINT("Deserializer failed on self_section_group.\n");
					assert(0);return CBCP_STATUS_ERROR;
				}
			}
		}

		for(unsigned int i = 0; i < self_section.own_interface_count; ++i)
		{
			CBCP_Internal_Db_Interface interface = CBCP_ZERO_INITIALIZER;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&interface.name_length,
				&interface.name) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			cursor_test = cursor +
				sizeof(interface.master_secret) +
				sizeof(interface.capability_entry_count) +
				sizeof(interface.command_count);

			if (cursor_test > end) {
				assert(0);return CBCP_STATUS_ERROR;
			}

			cbcp_deserialize_byte_array(
				&cursor,
				(char*)&interface.master_secret.secret_8[0],
				sizeof(interface.master_secret));

			interface.capability_entry_count = cbcp_deserialize_u16(&cursor);
			interface.command_count = cbcp_deserialize_u8(&cursor);

			CBCP_DEBUG_PRINT(
				"  Interface %d contents:\n"
				"  Interface name: %.*s\n"
				"  Something about CAP-OBJ\n"
				"  Something about OWN-CAP\n"
				"  Command count: %d\n",
				i,
				interface.name_length, interface.name,
				interface.command_count
				);

			if(visitors->self_section_interface != NULL) {
				if (visitors->self_section_interface(custom_data, &interface) == -1) {
					CBCP_DEBUG_PRINT("Deserializer failed on self_section_interface.\n");
					assert(0);return CBCP_STATUS_ERROR;
				}
			}

			cursor_test = cursor + interface.capability_entry_count * sizeof(uint64_t);

			if (cursor_test > end) {
				assert(0);return CBCP_STATUS_ERROR;
			}

			for(unsigned int capability_entry_index = 0;
				capability_entry_index < interface.capability_entry_count;
				++capability_entry_index)
			{
				CBCP_Internal_Db_Capability_Entry capability_entry = CBCP_ZERO_INITIALIZER;

				capability_entry.capability_mask = cbcp_deserialize_u64(&cursor);

				if(visitors->self_section_capability_entry != NULL) {
					if (visitors->self_section_capability_entry(
						custom_data,
						&capability_entry) == -1
					) {
						CBCP_DEBUG_PRINT("Deserializer failed on self_section_capability_entry.\n");
						assert(0);return CBCP_STATUS_ERROR;
					}
				}
			}

			for(unsigned int command_id = 0;
				command_id < interface.command_count;
				++command_id)
			{
				CBCP_Internal_Db_Command command = CBCP_ZERO_INITIALIZER;

				if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
					&cursor,
					end,
					&command.name_length,
					&command.name) == -1)
				{
					assert(0);return CBCP_STATUS_ERROR;
				}

				command.command_id = command_id;

				CBCP_DEBUG_PRINT("  Command %d: %s\n", command_id, command.name);
				if(visitors->self_section_command != NULL) {
					if (visitors->self_section_command(custom_data, &command) == -1) {
						CBCP_DEBUG_PRINT("Deserializer failed on self_section_command.\n");
						assert(0);return CBCP_STATUS_ERROR;
					}
				}
			}
		}
	}

	{
		CBCP_DEBUG_PRINT("Remote interfaces section contents:\n");
		cursor = cbcp_db_contents + remote_interfaces_start;
		assert(cursor <= end);

		CBCP_Internal_Db_Remote_Interfaces_Section remote_interfaces
			= CBCP_ZERO_INITIALIZER;

		cursor_test = cursor + sizeof(remote_interfaces.number_of_remote_interfaces);

		if (cursor_test > end) {
			assert(0);return CBCP_STATUS_ERROR;
		}

		remote_interfaces.number_of_remote_interfaces = cbcp_deserialize_u32(&cursor);

		CBCP_DEBUG_PRINT(
			"\n\nRemote interface count: %d\n",
			remote_interfaces.number_of_remote_interfaces
			);

		if(visitors->remote_interfaces_section != NULL) {
			if (visitors->remote_interfaces_section(custom_data, &remote_interfaces) == -1) {
				CBCP_DEBUG_PRINT("Deserializer failed on remote_interfaces_section.\n");
				assert(0);return CBCP_STATUS_ERROR;
			}
		}

		for(unsigned int i = 0; i < remote_interfaces.number_of_remote_interfaces; ++i)
		{
			CBCP_Internal_Db_Remote_Interface remote_interface = CBCP_ZERO_INITIALIZER;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&remote_interface.name_length,
				&remote_interface.name) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			cursor_test = cursor + sizeof(remote_interface.number_of_commands);

			if (cursor_test > end) {
				assert(0);return CBCP_STATUS_ERROR;
			}

			remote_interface.number_of_commands = cbcp_deserialize_u8(&cursor);

			CBCP_DEBUG_PRINT(
				"\n"
				"  Remote interface %d contents:\n"
				"  Remote interface name: %.*s\n"
				"  Number of commands: %d\n",
				i,
				remote_interface.name_length, remote_interface.name,
				remote_interface.number_of_commands
				);

			if(visitors->remote_interface != NULL) {
				if (visitors->remote_interface(custom_data, &remote_interface) == -1) {
					CBCP_DEBUG_PRINT("Deserializer failed on remote_interface.\n");
					assert(0);return CBCP_STATUS_ERROR;
				}
			}

			for(unsigned int command_index = 0;
				command_index < remote_interface.number_of_commands;
				++command_index)
			{
				CBCP_Internal_Db_Remote_Command remote_command;

				cursor_test = cursor + sizeof(uint8_t);

				if (cursor_test > end) {
					assert(0);return CBCP_STATUS_ERROR;
				}

				remote_command.command_id = cbcp_deserialize_u8(&cursor);

				if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
					&cursor,
					end,
					&remote_command.name_length,
					&remote_command.name) == -1)
				{
					assert(0);return CBCP_STATUS_ERROR;
				}

				CBCP_DEBUG_PRINT(
					"  Command %d: %d | %.*s\n",
					command_index,
					remote_command.command_id,
					remote_command.name_length,
					remote_command.name);

				if(visitors->remote_command != NULL) {
					if (visitors->remote_command(custom_data, &remote_command) == -1) {
						CBCP_DEBUG_PRINT("Deserializer failed on remote_command.\n");
						assert(0);return CBCP_STATUS_ERROR;
					}
				}
			}
		}
	}

	{
		CBCP_DEBUG_PRINT("\n\nHosts section contents:\n");
		cursor = cbcp_db_contents + host_records_start;
		assert(cursor <= end);
		//size += CBCP_FLEXIBLE_SIZEOF(CBCP_Host, interface_datas) + sizeof(CBCP_Host*);

		CBCP_Internal_Db_Hosts_Section hosts = CBCP_ZERO_INITIALIZER;

		cursor_test = cursor + sizeof(hosts.number_of_hosts);

		if (cursor_test > end) {
			assert(0);return CBCP_STATUS_ERROR;
		}

		hosts.number_of_hosts = cbcp_deserialize_u32(&cursor);

		if(visitors->hosts_section != NULL) {
			if (visitors->hosts_section(custom_data, &hosts) == -1) {
				CBCP_DEBUG_PRINT("Deserializer failed on hosts_section.\n");
				assert(0);return CBCP_STATUS_ERROR;
			}
		}

		for(unsigned int host_index = 0; host_index < hosts.number_of_hosts; ++host_index)
		{
			CBCP_Internal_Db_Host host = CBCP_ZERO_INITIALIZER;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&host.name_length,
				&host.name) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			if(cbcp_internal_cbcpdb_get_byte_array_reference_8(
				&cursor,
				end,
				&host.address_protocol_length,
				&host.address_protocol) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			if(cbcp_internal_cbcpdb_get_byte_array_reference_16(
				&cursor,
				end,
				&host.address_length,
				&host.address) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}

			cursor_test = cursor + sizeof(uint16_t);

			if (cursor_test > end) {
				assert(0);return CBCP_STATUS_ERROR;
			}

			uint16_t license_count = cbcp_deserialize_u16(&cursor);
			host.number_of_licenses = license_count;

			if(cbcp_internal_cbcpdb_get_byte_array_reference_16(
				&cursor,
				end,
				&host.public_rsa_key_length,
				&host.public_rsa_key) == -1)
			{
				assert(0);return CBCP_STATUS_ERROR;
			}


			CBCP_DEBUG_PRINT(
				"\n"
				"  Host %d contents:\n"
				"  Hostname: %.*s\n"
				"  Public RSA key length: %d\n"
				"  Number of licenses: %d\n",
				host_index,
				host.name_length, host.name,
				host.public_rsa_key_length,
				license_count
				);

			//size += number_of_licenses * sizeof(CBCP_License);

			if(visitors->host != NULL) {
				if (visitors->host(custom_data, &host) == -1) {
					CBCP_DEBUG_PRINT("Deserializer failed on host.\n");
					assert(0);return CBCP_STATUS_ERROR;
				}
			}

			unsigned int serialized_licence_record_size = (
				sizeof(uint16_t) + // interface_id_at_client
				sizeof(uint16_t) + // interface_id_at_server
				sizeof(uint16_t) + // client_group_id
				sizeof(CBCP_Capability_Reduction_Field) + // reduction_field
				sizeof(CBCP_Capability_Secret) + // secret
				sizeof(uint64_t)); // capability_id

			cursor_test = cursor + license_count*serialized_licence_record_size;

			if (cursor_test > end) {
				assert(0);return CBCP_STATUS_ERROR;
			}

			for(unsigned int license_index = 0; license_index < license_count; ++license_index)
			{
				CBCP_Internal_Db_License license = CBCP_ZERO_INITIALIZER;

				license.interface_id_at_client = cbcp_deserialize_u16(&cursor);
				license.interface_id_at_server = cbcp_deserialize_u16(&cursor);
				license.client_group_id = cbcp_deserialize_u16(&cursor);
				for(size_t i = 0; i < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT; ++i)
				{
					license.reduction_field.subfields[i].capability_mask = cbcp_deserialize_u64(&cursor);
				}
				cbcp_deserialize_byte_array(&cursor, (char*)&license.secret.secret_8[0], CBCP_CAPABILITY_SECRET_SIZE);
				license.capability_id = cbcp_deserialize_u64(&cursor);


				CBCP_DEBUG_PRINT(
					"  License %d: %d; %d; %d\n",
					license_index,
					license.interface_id_at_client,
					license.interface_id_at_server,
					license.client_group_id);

				if(visitors->license != NULL) {
					if (visitors->license(custom_data, &license) == -1) {
						CBCP_DEBUG_PRINT("Deserializer failed on license.\n");
						assert(0);return CBCP_STATUS_ERROR;
					}
				}
			}
		}
	}

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_host_id_from_name(
	CBCP_State *cbcp,
	const char *host_name,
	unsigned int host_name_length,
	uint16_t *out_host_id)
{
	for (uint16_t i = 0; i < cbcp->host_count; ++i) {
		CBCP_Host *host = cbcp->hosts[i];

		if (cbcp_length_strings_are_equal(
			(char *)host_name, host_name_length,
			host->name, host->name_length)
		) {
			*out_host_id = i;
			return CBCP_STATUS_SUCCESS;
		}
	}

	return CBCP_STATUS_ERROR;
}

#define CBCP_RSA_PADDING_SCHEME RSA_PKCS1_OAEP_PADDING
#define CBCP_RSA_PADDING_SCHEME_RESERVED_BYTES 42

enum {
	CBCP_HANDSHAKE_STATUS_ERROR = -1,
	CBCP_HANDSHAKE_STATUS_SUCCESS = 0,
	CBCP_HANDSHAKE_STATUS_ALREADY_IN_PROGRESS = 1
};

CBCP_Status
cbcp_client_handshake(CBCP_State *cbcp, CBCP_Host *host) {

	//
	// CBCP 4-step handshake (CBCP v1.0):
	// STEP 1. client -> [ major_version | minor_version | challenge_1 | name_length | name ] -> server
	// STEP 2. client <- [ challenge_1_proof | challenge_2 ]                                  <- server
	// STEP 3. client -> [ challenge_2_proof | challenge_3 | aes_key ]                        -> server
	// STEP 4. client <- [ challenge_3_proof | client_id_at_server ]                          <- server
	//

	CBCP_Net_Implementation *net = host->net_impl;

	void *net_control_connection_state = host->net_control_connection_state;

	// NOTE(jakob): 512 should be large enough for all encrypted control messages.
	char cipher_buffer[512];
	char plaintext_buffer[512];

	assert(RSA_size(host->public_key.key) >= 0);
	assert(sizeof(cipher_buffer) >= (unsigned int)RSA_size(host->public_key.key)); // NOTE(jakob & patrick): from the OpenSSL man page

	//
	// STEP 1. Initiate handshake by sending a challenge to the server,
	// identifying ourselves (the client) by name
	//
	// Packet to SEND:
	//   { u16 major_version; u16 minor_versionu; u64 challenge_1; u8 name_length; char name[name_length] }
	//

	char *at = plaintext_buffer;

	uint64_t challenge_1;
	RAND_bytes((unsigned char *)&challenge_1, sizeof(challenge_1));

	const uint16_t cbcp_major_version = CBCP_MAJOR_VERSION;
	const uint16_t cbcp_minor_version = CBCP_MINOR_VERSION;

	cbcp_serialize_u16(&at, cbcp_major_version);
	cbcp_serialize_u16(&at, cbcp_minor_version);
	cbcp_serialize_byte_array(&at, (char *)&challenge_1, sizeof(challenge_1));
	cbcp_serialize_length_byte_array_8(&at, cbcp->self_name, cbcp->self_name_length);

	// NOTE(jakob & patrick): From the OpenSSL man page:
	// "flen must not be more than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes, not more
	// than ___RSA_size(rsa) - 42 for CBCP_RSA_PADDING_SCHEME___

	unsigned int maximum_allowed_encryption_size =
		RSA_size(host->public_key.key) - CBCP_RSA_PADDING_SCHEME_RESERVED_BYTES;
	unsigned int amount_to_encrypt = (unsigned int)(at - plaintext_buffer);

	assert(amount_to_encrypt == (
		sizeof(cbcp_major_version) +
		sizeof(cbcp_minor_version) +
		sizeof(challenge_1) +
		sizeof(uint8_t) +
		cbcp->self_name_length * sizeof(char)));

	assert(amount_to_encrypt < maximum_allowed_encryption_size);

	int amount_encrypted = RSA_public_encrypt(
		amount_to_encrypt,
		(const unsigned char *)plaintext_buffer,
		(unsigned char *)cipher_buffer,
		host->public_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_encrypted < 0) {
		//ERR_get_error();
		goto error_return_cleanup_1;
	}

	assert((unsigned int)amount_encrypted <= sizeof(cipher_buffer));

	if (net->client_open_connection(
		net->implementation_state,
		host->net_address.impl_address,
		CBCP_TRUE,
		net_control_connection_state) == -1
	) {
		goto error_return_cleanup_1;
	}

	if (net->send(
		net->implementation_state,
		net_control_connection_state,
		cipher_buffer,
		amount_encrypted) == -1
	) {
		goto error_return_cleanup_2;
	}

	//
	// STEP 2. Receive challenge proof and a new challenge from server.
	// Verify the proof sent by the server and prove the new challenge
	//
	// Packet to RECEIVE:
	//   { u64 challenge_1_proof; u64 challenge_2 }
	//

	int amount_received;

	// Receive //

	if (net->receive(
		net->implementation_state,
		net_control_connection_state,
		cipher_buffer,
		sizeof(cipher_buffer),
		&amount_received) == -1
	) {
		goto error_return_cleanup_2;
	}

	if (amount_received == -1) {
		goto error_return_cleanup_2;
	}

	if ((unsigned int)amount_received > sizeof(cipher_buffer)) {
		goto error_return_cleanup_2;
	}

	// Decrypt //

	int amount_decrypted;
	amount_decrypted = RSA_private_decrypt(
		amount_received,
		(unsigned char *)cipher_buffer,
		(unsigned char *)plaintext_buffer,
		cbcp->self_private_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_decrypted < 0) {
		goto error_return_cleanup_2;
	}

	at = plaintext_buffer;

	// Verify challenge_1_proof //

	uint64_t challenge_1_proof;
	cbcp_deserialize_byte_array(&at, (char *)&challenge_1_proof, sizeof(challenge_1_proof));

	if (challenge_1_proof != challenge_1) {
		goto error_return_cleanup_2;
	}

	// Get challenge_2 from server //

	uint64_t challenge_2;
	cbcp_deserialize_byte_array(&at, (char *)&challenge_2, sizeof(challenge_2));


	//
	// STEP 3. Send proof of decryption of challenge_2 received from the server in STEP 2.
	// Make and send next challenge (challenge_3) for server.
	// Also generate and send the shared AES key to be used for command communication.
	//
	// Packet to SEND:
	//   { u64 challenge_2_proof; u64 challenge_3; AES_KEY aes_key }
	//

	at = plaintext_buffer;

	uint64_t challenge_2_proof;
	challenge_2_proof = challenge_2;

	cbcp_serialize_byte_array(&at, (char *)&challenge_2_proof, sizeof(challenge_2_proof));

	uint64_t challenge_3;
	RAND_bytes((unsigned char *)&challenge_3, sizeof(challenge_3));
	cbcp_serialize_byte_array(&at, (char *)&challenge_3, sizeof(challenge_3));

	// generate AES key //
	RAND_bytes((unsigned char *)&host->aes_key, sizeof(host->aes_key));
	cbcp_serialize_byte_array(&at, (char *)host->aes_key, sizeof(host->aes_key));

	// Encrypt //

	amount_to_encrypt = (unsigned int)(at - plaintext_buffer);

	assert(amount_to_encrypt == sizeof(challenge_2_proof) + sizeof(challenge_3) + sizeof(host->aes_key));
	assert(amount_to_encrypt < maximum_allowed_encryption_size);

	amount_encrypted = RSA_public_encrypt(
		amount_to_encrypt,
		(const unsigned char *)plaintext_buffer,
		(unsigned char *)cipher_buffer,
		host->public_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_encrypted < 0) {
		//ERR_get_error();
		goto error_return_cleanup_2;
	}

	assert((unsigned int)amount_encrypted <= sizeof(cipher_buffer));

	if (net->send(
		net->implementation_state,
		net_control_connection_state,
		cipher_buffer,
		amount_encrypted) == -1
	) {
		goto error_return_cleanup_2;
	}

	//
	// STEP 4. Receive and verify challenge_3_proof.
	// Get client_id_at_server for using in future command packets for the server
	//
	// Packet to RECEIVE:
	//   { u64 challenge_3_proof; u16 client_id_at_server }
	//

	// Receive //

	if (net->receive(
		net->implementation_state,
		net_control_connection_state,
		cipher_buffer,
		sizeof(cipher_buffer),
		&amount_received) == -1
	) {
		goto error_return_cleanup_2;
	}

	if (amount_received == -1) {
		goto error_return_cleanup_2;
	}

	if ((unsigned int)amount_received > sizeof(cipher_buffer)) {
		goto error_return_cleanup_2;
	}

	// Decrypt //

	amount_decrypted = RSA_private_decrypt(
		amount_received,
		(unsigned char *)cipher_buffer,
		(unsigned char *)plaintext_buffer,
		cbcp->self_private_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_decrypted < 0) {
		goto error_return_cleanup_2;
	}

	at = plaintext_buffer;

	uint64_t challenge_3_proof;
	cbcp_deserialize_byte_array(&at, (char *)&challenge_3_proof, sizeof(challenge_3_proof));

	// Verify challenge_3_proof

	if (challenge_3_proof != challenge_3) {
		goto error_return_cleanup_2;
	}

	host->client_id_at_server = cbcp_deserialize_u16(&at);

	return CBCP_STATUS_SUCCESS;

error_return_cleanup_2:

	net->close_connection(net->implementation_state, net_control_connection_state);

error_return_cleanup_1:

	return CBCP_STATUS_ERROR;
}


static CBCP_Status
cbcp_gcm_encrypt_in_place(
	unsigned char *plaintext, int plaintext_length,
	unsigned char *additional_authenticated_data, int additional_authenticated_data_length,
	unsigned char *key,
	unsigned char *initial_vector, int initial_vector_length,
	unsigned char *out_tag,
	unsigned int  *out_ciphertext_length)
{
#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("AAD:\n");
	BIO_dump_fp (stdout, (const char *)additional_authenticated_data, additional_authenticated_data_length);
	CBCP_DEBUG_PRINT("\n");

	CBCP_DEBUG_PRINT("KEY:\n");
	BIO_dump_fp (stdout, (const char *)key, 32);
	CBCP_DEBUG_PRINT("\n");

	CBCP_DEBUG_PRINT("IV:\n");
	BIO_dump_fp (stdout, (const char *)initial_vector, 16);
	CBCP_DEBUG_PRINT("\n");
#endif

	EVP_CIPHER_CTX *context;
	int length;
	int ciphertext_length;

	// Create and initialise the context
	if(!(context = EVP_CIPHER_CTX_new())) {
		return CBCP_STATUS_ERROR;
	}

	// Initialise the encryption operation.
	if(1 != EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		goto clean_up_and_return_error;
	}

	// Disable padding
	if(1 != EVP_CIPHER_CTX_set_padding(context, 0)) {
		goto clean_up_and_return_error;
	}

	//Set IV length if default 12 bytes (96 bits) is not appropriate
	if(1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, initial_vector_length, NULL)) {
		goto clean_up_and_return_error;
	}

	// Initialise key and IV
	if(1 != EVP_EncryptInit_ex(context, NULL, NULL, key, initial_vector)) {
		goto clean_up_and_return_error;
	}

	//Provide any AAD data. This can be called zero or more times as
	// required
	if(1 != EVP_EncryptUpdate(context, NULL, &length, additional_authenticated_data, additional_authenticated_data_length)) {
		goto clean_up_and_return_error;
	}

	//Provide the message to be encrypted, and obtain the encrypted output.
	//EVP_EncryptUpdate can be called multiple times if necessary
	if(1 != EVP_EncryptUpdate(context, plaintext, &length, plaintext, plaintext_length)) {
		goto clean_up_and_return_error;
	}
	ciphertext_length = length;

	//Finalise the encryption. Normally ciphertext bytes may be written at
	//this stage, but this does not occur in GCM mode
	if(1 != EVP_EncryptFinal_ex(context, plaintext + length, &length)) {
		goto clean_up_and_return_error;
	}
	ciphertext_length += length;

	// Get the tag
	if(1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, out_tag)) {
		goto clean_up_and_return_error;
	}

	// Clean up
	EVP_CIPHER_CTX_free(context);
	*out_ciphertext_length = ciphertext_length;
	return CBCP_STATUS_SUCCESS;

	clean_up_and_return_error:
	EVP_CIPHER_CTX_free(context);
	return CBCP_STATUS_ERROR;
}

static CBCP_Status
cbcp_gcm_decrypt_cbcp_packet_header(
	EVP_CIPHER_CTX *context,
	unsigned char *cipherheader,
	unsigned char *additional_authenticated_data, int additional_authenticated_data_length,
	unsigned char *key,
	unsigned char *initial_vector, int initial_vector_length,
	int header_length)
{
	#if 0
	CBCP_DEBUG_PRINT("AAD:\n");
	BIO_dump_fp (stdout, (const char *)additional_authenticated_data, additional_authenticated_data_length);
	CBCP_DEBUG_PRINT("\n");

	CBCP_DEBUG_PRINT("KEY:\n");
	BIO_dump_fp (stdout, (const char *)key, 32);
	CBCP_DEBUG_PRINT("\n");

	CBCP_DEBUG_PRINT("IV:\n");
	BIO_dump_fp (stdout, (const char *)initial_vector, 16);
	CBCP_DEBUG_PRINT("\n");
	#endif

	int length;

	// Initialise the decryption operation.
	if(!EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		return CBCP_STATUS_ERROR;
	}

	// Disable padding
	if(1 != EVP_CIPHER_CTX_set_padding(context, 0)) {
		return CBCP_STATUS_ERROR;
	}

	// Set IV length. Not necessary if this is 12 bytes (96 bits)
	if(!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, initial_vector_length, NULL)) {
		return CBCP_STATUS_ERROR;
	}

	// Initialise key and IV
	if(!EVP_DecryptInit_ex(context, NULL, NULL, key, initial_vector)) {
		return CBCP_STATUS_ERROR;
	}

	//Provide any AAD data. This can be called zero or more times as
	//required
	if(!EVP_DecryptUpdate(context, NULL, &length, additional_authenticated_data, additional_authenticated_data_length)) {
		return CBCP_STATUS_ERROR;
	}

	//Provide the message to be decrypted, and obtain the plaintext output.
	//EVP_DecryptUpdate can be called multiple times if necessary
	if(!EVP_DecryptUpdate(context, cipherheader, &length, cipherheader, header_length)) {
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}

static CBCP_Status
cbcp_gcm_decrypt_cbcp_packet_payload(
	EVP_CIPHER_CTX *context,
	unsigned char *cipherpayload, int cipherpayload_length,
	unsigned char *tag)
{
	int length;
	//Provide the message to be decrypted, and obtain the plaintext output.
	//EVP_DecryptUpdate can be called multiple times if necessary
	if(!EVP_DecryptUpdate(
		context,
		cipherpayload,
		&length,
		cipherpayload,
		cipherpayload_length)
	) {
		return CBCP_STATUS_ERROR;
	}

	// Set expected tag value. Works in OpenSSL 1.0.1d and later
	if(!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		return CBCP_STATUS_ERROR;
	}

	//Finalise the decryption. A positive return value indicates success,
	//anything else is a failure - the plaintext is not trustworthy.
	if(EVP_DecryptFinal_ex(context, cipherpayload + length, &length) <= 0) {
		return CBCP_STATUS_ERROR;
	}


	return CBCP_STATUS_SUCCESS;
}

static void
cbcp_serialize_command_packet_header(char **destination, CBCP_Command_Packet_Header *header)
{
	cbcp_serialize_u16(destination, header->client_id_at_server);
	cbcp_serialize_u16(destination, header->sequence_number);
	cbcp_serialize_u16(destination, header->client_group_id);
	cbcp_serialize_u16(destination, header->interface_id_at_server);
	cbcp_serialize_u16(destination, header->capability_id);
	cbcp_serialize_u16(destination, header->payload_length);
	cbcp_serialize_u8(destination, header->command_id);
	cbcp_serialize_zero_bytes(destination, sizeof(header->_reserved));

	for (unsigned int i = 0; i < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT; ++i) {
		cbcp_serialize_u64(destination, header->reduction_field.subfields[i].capability_mask);
	}
	cbcp_serialize_byte_array(destination, (char *)&header->secret, sizeof(header->secret));
}

static void
cbcp_deserialize_command_packet_header(char **source, CBCP_Command_Packet_Header *header)
{
	header->client_id_at_server = cbcp_deserialize_u16(source);
	header->sequence_number = cbcp_deserialize_u16(source);
	header->client_group_id = cbcp_deserialize_u16(source);
	header->interface_id_at_server = cbcp_deserialize_u16(source);
	header->capability_id = cbcp_deserialize_u16(source);
	header->payload_length = cbcp_deserialize_u16(source);
	header->command_id = cbcp_deserialize_u8(source);
	cbcp_deserialize_byte_array(source, (char *)&header->_reserved, sizeof(header->_reserved));

	for (unsigned int i = 0; i < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT; ++i) {
		header->reduction_field.subfields[i].capability_mask = cbcp_deserialize_u64(source);
	}
	cbcp_deserialize_byte_array(source, (char *)&header->secret, sizeof(header->secret));

}

static void
cbcp_serialize_response_packet_header(char **destination, CBCP_Response_Packet_Header *header)
{
	cbcp_serialize_u16(destination, header->sequence_number);
	cbcp_serialize_u16(destination, header->response_payload_length);
	cbcp_serialize_zero_bytes(destination, sizeof(header->_reserved));
}

static void
cbcp_deserialize_response_packet_header(char **source, CBCP_Response_Packet_Header *header)
{
	header->sequence_number = cbcp_deserialize_u16(source);
	header->response_payload_length = cbcp_deserialize_u16(source);
	cbcp_deserialize_byte_array(source, (char *)&header->_reserved, sizeof(header->_reserved));
}

static unsigned int
cbcp_round_up_to_nearest_encryption_block_size(unsigned int value)
{
	unsigned int result = ((value + (CBCP_AES_BLOCK_SIZE-1)) / CBCP_AES_BLOCK_SIZE) * CBCP_AES_BLOCK_SIZE;
	return result;
}

static CBCP_Status
cbcp_read_entire_file(
	const char *filename,
	char **file_contents_out,
	unsigned int *file_length_out)
{
	FILE *file = fopen(filename, "r");

	if (!file) {
		return CBCP_STATUS_ERROR;
	}

	fseek(file, 0, SEEK_END);
	long file_length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *file_contents = (char *)malloc(file_length+1+7);

	if (fread(file_contents, file_length, 1, file) != 1) {
		fclose(file);
		return CBCP_STATUS_ERROR;
	}

	file_contents[file_length] = '\0';

	fclose(file);

	*file_contents_out = file_contents;
	*file_length_out = file_length;
	return CBCP_STATUS_SUCCESS;
}



////////////////////////////////////////////////////////////////////////////////
//                                 API below                                  //
////////////////////////////////////////////////////////////////////////////////

CBCP_State *
cbcp_init(const char *filename)
{
	char *cbcp_db_contents;
	unsigned int cbcp_db_contents_length;

	if (cbcp_read_entire_file(filename, &cbcp_db_contents, &cbcp_db_contents_length) < 0) {
		return NULL;
	}

	unsigned int cbcp_size = cbcp_size_of_loaded_state(cbcp_db_contents, cbcp_db_contents_length);

	CBCP_State *cbcp = (CBCP_State *)CBCP_MALLOC(cbcp_size);

	if (!cbcp) {
		return NULL;
	}

	if (cbcp_load_state(cbcp, cbcp_size, cbcp_db_contents, cbcp_db_contents_length) < 0) {
		return NULL;
	}

	return cbcp;
}

CBCP_Command *
cbcp_client_init_command(
	CBCP_State *cbcp,
	const char *host_name,
	const char *interface_name,
	const char *command_name)
{
	CBCP_Host *host;
	CBCP_Remote_Interface *remote_interface;
	CBCP_Remote_Command *remote_command;
	CBCP_License *license;
	CBCP_Command *result;

	host = cbcp_get_remote_host(cbcp, host_name, strlen(host_name));
	if (!host) return NULL;

	remote_interface = cbcp_get_remote_interface(cbcp, interface_name, strlen(interface_name));
	if (!remote_interface) return NULL;

	remote_command = cbcp_get_remote_command(remote_interface, command_name, strlen(command_name));
	if (!remote_command) return NULL;

	license = cbcp_get_remote_interface_license(host, remote_interface);
	if (!license) return NULL;

	result = (CBCP_Command *)CBCP_MALLOC(sizeof(*result));

	result->cbcp = cbcp;
	result->host = host;
	result->remote_interface = remote_interface;
	result->license = license;
	result->remote_command = remote_command;

	return result;
}

CBCP_Response
cbcp_client_send_command(
	CBCP_Command *command,
	void *payload,
	unsigned int payload_length,
	void *response_buffer,
	unsigned int response_buffer_length)
{
	CBCP_Status status;
	CBCP_State *cbcp = command->cbcp;
	CBCP_Host *host = command->host;
	CBCP_Net_Implementation *net_impl = host->net_impl;
	CBCP_Connection *connection = host->connection;

	CBCP_Response response;
	response.success = CBCP_FALSE;
	response.payload = NULL;
	response.payload_length = 0;

	status = cbcp_client_handshake(cbcp, host);

	if (status == CBCP_STATUS_ERROR) {
		return response;
	}

 	status = net_impl->client_open_connection(
		net_impl->implementation_state,
		host->net_address.impl_address,
		CBCP_FALSE,
		(void *)connection->net_connection_memory);

	if (status == CBCP_STATUS_ERROR) {
		return response;
	}

	// Fill out packet

	unsigned int offset_to_payload = cbcp_offset_to_command_payload(net_impl);
	unsigned int packet_size = cbcp_size_of_command_packet(payload_length, net_impl);
	char *packet = (char *)CBCP_MALLOC(packet_size);

	memcpy(packet + offset_to_payload, payload, payload_length);

	// Send packet
	CBCP_Sequence_Number sent_sequence_number;

	sent_sequence_number = cbcp_client_send_command_packet(
		command->remote_command, command->license, packet, payload_length, host->connection);

	CBCP_FREE(packet);

	if (sent_sequence_number == CBCP_INVALID_SEQUENCE_NUMBER) {
		return response;
	}

	int user_provided_response_buffer = response_buffer != NULL;

	if (!user_provided_response_buffer) {
		response_buffer_length = 4096;
		response_buffer = CBCP_MALLOC(response_buffer_length); // TODO(jakob): Get rid of this @hardcode
	}

	//
	// wait for response
	//
	CBCP_Sequence_Number received_sequence_number;

	unsigned int response_payload_length;

	received_sequence_number = cbcp_client_get_command_response(
		(char *)response_buffer,
		response_buffer_length,
		connection,
		&response_payload_length);

	if (received_sequence_number != sent_sequence_number) {
		return response;
	}

	if (user_provided_response_buffer) {
		response.payload = (void *)((char *)response_buffer + cbcp_offset_to_response_payload(net_impl));
		response.payload_length = response_payload_length;
	}
	else {
		CBCP_FREE(response_buffer);
	}

	response.success = CBCP_TRUE;

	return response;
}

struct CBCP_Internal_Client_Send_Command_Thread_Args {
	CBCP_Command *command;
	void *payload;
	unsigned int payload_length;
	void *response_buffer;
	unsigned int response_buffer_length;
	void *user_data;
	CBCP_Response_Callback response_callback;
};

static void *
cbcp_internal_client_send_command_thread(void *_args)
{
	struct CBCP_Internal_Client_Send_Command_Thread_Args *args =
		(struct CBCP_Internal_Client_Send_Command_Thread_Args *)_args;

	CBCP_Response response;

	response = cbcp_client_send_command(
		args->command,
		args->payload,
		args->payload_length,
		args->response_buffer,
		args->response_buffer_length);

	if (args->response_buffer && args->response_buffer_length && args->response_callback) {
		CBCP_Response_Args callback_args;

		callback_args.response = response;
		callback_args.user_data = args->user_data;

		args->response_callback(&callback_args);
	}

	CBCP_FREE(args);

	return NULL;
}

void
cbcp_client_send_command_async(
	CBCP_Command *command,
	void *payload,
	unsigned int payload_length,
	void *response_buffer,
	unsigned int response_buffer_length,
	void *user_data,
	CBCP_Response_Callback response_callback)
{
	struct CBCP_Internal_Client_Send_Command_Thread_Args *args;

	args = (struct CBCP_Internal_Client_Send_Command_Thread_Args *)CBCP_MALLOC(sizeof(*args));
	args->command = command;
	args->payload = payload;
	args->payload_length = payload_length;
	args->response_buffer = response_buffer;
	args->response_buffer_length = response_buffer_length;
	args->user_data = user_data;
	args->response_callback = response_callback;

	pthread_t thread;
	if (pthread_create(&thread, NULL, cbcp_internal_client_send_command_thread, args)) {
		// TODO(jakob): error handling
		CBCP_FREE(args);
	}
}

CBCP_Own_Command *
cbcp_server_init_command(
	CBCP_State *cbcp,
	const char *interface_name,
	const char *command_name,
	CBCP_Command_Callback command_callback,
	void *user_data,
	unsigned int max_response_payload_length)
{
	CBCP_Own_Interface *own_interface = cbcp_get_own_interface(cbcp, (char *)interface_name, strlen(interface_name));
	if (!own_interface) {
		return NULL;
	}
	CBCP_Own_Command *own_command = cbcp_get_own_command(own_interface, (char *)command_name, strlen(command_name));
	if (!own_command) {
		return NULL;
	}

	unsigned int response_buffer_length = cbcp->max_response_packet_header_size + max_response_payload_length;
	void *response_buffer = CBCP_MALLOC(response_buffer_length);
	cbcp_server_set_command_callback(own_command, command_callback, user_data, response_buffer, response_buffer_length);

	return own_command;
}

void
cbcp_server_start(CBCP_State *cbcp) {
	cbcp_server_start_async(cbcp);
	cbcp_server_wait(cbcp);
}

struct CBCP_Internal_Net_Impl_Command_Server_Thread_Args {
	CBCP_State *cbcp;
	CBCP_Net_Implementation *net_impl;
};

static void cbcp_sleep_microseconds(unsigned int seconds, unsigned int useconds) {
	struct timeval tv;
	tv.tv_sec = seconds;
	tv.tv_usec = useconds;
	select(0, NULL, NULL, NULL, &tv);
}

static void *
cbcp_internal_net_impl_command_server_thread(void *_args)
{
	struct CBCP_Internal_Net_Impl_Command_Server_Thread_Args *args =
		(struct CBCP_Internal_Net_Impl_Command_Server_Thread_Args *)_args;

	CBCP_State *cbcp = args->cbcp;
	CBCP_Net_Implementation *net_impl = args->net_impl;

	// Allocate enough buffer space for
	CBCP_Connection *connection = (CBCP_Connection *)CBCP_MALLOC(cbcp_size_of_connection(net_impl));
	assert(connection);

	// TODO(jakob): Remove @hardcode
	unsigned int receive_buffer_length = 1<<20; // 1 MB Receive buffer
	char *receive_buffer = (char *)CBCP_MALLOC(receive_buffer_length);
	assert(receive_buffer);

	CBCP_Command_Result command_result;

	for (;; cbcp_sleep_microseconds(0, 100000)) {
		CBCP_Bool should_try_again;
		if (cbcp_server_accept_connection(net_impl, connection, &should_try_again) == -1)
			continue;
		if (should_try_again)
			continue;
		if (cbcp_server_handle_command(cbcp, receive_buffer, receive_buffer_length, connection, &command_result) == -1)
			continue;
		if (cbcp_server_send_command_response(connection, command_result) == -1)
			continue;
		cbcp_close_connection(connection);
	}

	return NULL;
}

struct CBCP_Internal_Net_Impl_Handshake_Server_Thread_Args {
	CBCP_State *cbcp;
	CBCP_Net_Implementation *net_impl;
};

static void *
cbcp_internal_net_impl_handshake_server_thread(void *_args)
{
	struct CBCP_Internal_Net_Impl_Handshake_Server_Thread_Args *args =
		(struct CBCP_Internal_Net_Impl_Handshake_Server_Thread_Args *)_args;

	CBCP_State *cbcp = args->cbcp;
	CBCP_Net_Implementation *net_impl = args->net_impl;

	for (;; cbcp_sleep_microseconds(0, 100000)) {
		cbcp_server_handshake(cbcp, net_impl);
	}

	return NULL;
}

void
cbcp_server_start_async(CBCP_State *cbcp)
{
	for (unsigned int i = 0; i < cbcp->net_implementation_count; i++) {
		CBCP_Net_Implementation *net_impl = &cbcp->net_implementations[i];
		CBCP_Net_Impl_Server *net_impl_server = &cbcp->net_impl_servers[i];

		net_impl_server->net_impl = net_impl;

		struct CBCP_Internal_Net_Impl_Handshake_Server_Thread_Args *args_handshake =
			(struct CBCP_Internal_Net_Impl_Handshake_Server_Thread_Args *)CBCP_MALLOC(sizeof(*args_handshake));

		struct CBCP_Internal_Net_Impl_Command_Server_Thread_Args *args_command =
			(struct CBCP_Internal_Net_Impl_Command_Server_Thread_Args *)CBCP_MALLOC(sizeof(*args_command));

		args_handshake->cbcp = cbcp;
		args_handshake->net_impl = net_impl;

		args_command->cbcp = cbcp;
		args_command->net_impl = net_impl;

		if (pthread_create(&net_impl_server->handshake_thread, NULL, cbcp_internal_net_impl_handshake_server_thread, args_handshake)) {
		}

		if (pthread_create(&net_impl_server->command_thread, NULL, cbcp_internal_net_impl_command_server_thread, args_command)) {
		}
	}
	(void)cbcp;
}

void
cbcp_server_wait(CBCP_State *cbcp)
{
	for (unsigned int i = 0; i < cbcp->net_implementation_count; i++) {
		CBCP_Net_Impl_Server *net_impl_server = &cbcp->net_impl_servers[i];

		int status;

		status = pthread_join(net_impl_server->handshake_thread, NULL);
		assert(status == 0);

		status = pthread_join(net_impl_server->command_thread, NULL);
		assert(status == 0);
	}
}


int
cbcp_size_of_loaded_state(
	char *cbcp_db_contents,
	unsigned int cbcp_db_contents_length)
{
#ifdef CBCP_LITTLE_ENDIAN
	if(! cbcp_is_little_endian())
	{
		assert(!"CBCP has been compiled against the wrong endianness: Little endian CBCP on big endian machine!");
		return -1;
	}
#elif defined(CBCP_BIG_ENDIAN)
	if(cbcp_is_little_endian())
	{
		assert(!"CBCP has been compiled against the wrong endianness: Big endian CBCP on little endian machine!");
		return -1;
	}
#endif
	CBCP_Database_Visitors size_visitors = CBCP_ZERO_INITIALIZER;
	size_visitors.self_section = cbcp_internal_calculate_size_visit_self_section;
	size_visitors.self_section_interface = cbcp_internal_calculate_size_visit_interface;
	size_visitors.self_section_capability_entry = NULL;
		//= cbcp_internal_calculate_size_visit_capability_entry;
	size_visitors.self_section_command = cbcp_internal_calculate_size_visit_command;
	size_visitors.self_section_net_address = cbcp_internal_calculate_size_vist_self_net_address;
	size_visitors.self_section_group = cbcp_internal_calculate_size_visit_self_group;

	size_visitors.remote_interfaces_section = cbcp_internal_calculate_size_visit_remote_interfaces_section;
	size_visitors.remote_interface = cbcp_internal_calculate_size_visit_remote_interface;
	size_visitors.remote_command = cbcp_internal_calculate_size_visit_remote_command;

	size_visitors.hosts_section = cbcp_internal_calculate_size_visit_hosts_section;
	size_visitors.host = cbcp_internal_calculate_size_visit_host;
	size_visitors.license = NULL; // Nothing to allocate for this one.

	struct CBCP_Calculate_Size_Context calculate_size_context;

	calculate_size_context.out_size = 0;
	calculate_size_context.net_implementations = cbcp_global_net_implementations;
	calculate_size_context.net_implementation_count = cbcp_global_net_implementation_count;

	CBCP_Status status = cbcp_internal_load_database(
		cbcp_db_contents,
		cbcp_db_contents_length,
		(void *)&calculate_size_context,
		&size_visitors);

	if (status == -1) {
		return -1;
	}

	return calculate_size_context.out_size;
}


CBCP_Status
cbcp_load_state(
	CBCP_State *cbcp,
	unsigned int cbcp_size,
	char *cbcp_db_contents,
	unsigned int cbcp_db_contents_length)
{
	// NOTE(Patrick): What happens here is that we are checking for 8-byte alignment.
	// This requires that the last three bits are 0.

	uintptr_t address = (uintptr_t)(void *)cbcp;

	// Test for 8-byte alignment
	if((address & 0x7) != 0)
	{
		return CBCP_STATUS_ERROR;
	}

	memset(cbcp, 0, cbcp_size);

	cbcp->own_interface_count = 0;
	cbcp->remote_interface_count = 0;

	cbcp->command_rejected_callback = NULL;
	cbcp->command_rejected_callback_user_data = NULL;

	cbcp->memory_length = cbcp_size - CBCP_FLEXIBLE_SIZEOF(CBCP_State, memory);

	// TODO(jakob): Consider removing globals
	cbcp->net_implementations = cbcp_global_net_implementations;
	cbcp->net_implementation_count = cbcp_global_net_implementation_count;
	unsigned int net_impl_servers_size =
		cbcp->net_implementation_count * sizeof(cbcp->net_impl_servers[0]);
	cbcp->net_impl_servers = (CBCP_Net_Impl_Server *)CBCP_MALLOC(net_impl_servers_size);
	memset(cbcp->net_impl_servers, 0, net_impl_servers_size);
	assert(cbcp->net_impl_servers != NULL);

	cbcp->max_response_packet_header_size = 0;

	for (unsigned int i = 0; i < cbcp->net_implementation_count; ++i) {
		CBCP_Net_Implementation *net_impl = &cbcp->net_implementations[i];

		unsigned int response_header_size = cbcp_size_of_response_packet(0, net_impl);

		if (response_header_size > cbcp->max_response_packet_header_size) {
			cbcp->max_response_packet_header_size = response_header_size;
		}
	}

	struct CBCP_Init_Context init_context;
	init_context.cbcp = cbcp;
	init_context.memory_head = cbcp->memory;
	init_context.memory_tail = cbcp->memory + cbcp->memory_length;
	init_context.memory_size = cbcp->memory_length;

	CBCP_Database_Visitors visitors = CBCP_ZERO_INITIALIZER;
	visitors.self_section = cbcp_internal_init_visit_self_section;
	visitors.self_section_interface = cbcp_internal_init_visit_interface;
	visitors.self_section_capability_entry = cbcp_internal_init_visit_capability_entry;
	visitors.self_section_command = cbcp_internal_init_visit_command;
	visitors.self_section_net_address = cbcp_internal_init_visit_self_net_address;
	visitors.self_section_group = cbcp_internal_init_visit_self_group;

	visitors.remote_interfaces_section = cbcp_internal_init_visit_remote_interfaces_section;
	visitors.remote_interface = cbcp_internal_init_visit_remote_interface;
	visitors.remote_command = cbcp_internal_init_visit_remote_command;

	visitors.hosts_section = cbcp_internal_init_visit_hosts_section;
	visitors.host = cbcp_internal_init_visit_host;
	visitors.license = cbcp_internal_init_visit_license;

	CBCP_Status deserialization_status = cbcp_internal_load_database(
		cbcp_db_contents,
		cbcp_db_contents_length,
		&init_context,
		&visitors);

	CBCP_DEBUG_PRINT(
		"DEBUG INITIALIZATION:\n"
		"Memory available: %zu\n"
		"Memory allocated from head: %zu\n"
		"Memory allocated from tail: %zu\n"
		"Total allocated space: %zu\n",
		(size_t)cbcp->memory_length,
		(size_t)(init_context.memory_head - (&cbcp->memory[0])),
		(size_t)((&cbcp->memory[0]) + cbcp->memory_length - init_context.memory_tail),
		(size_t)(((size_t)(init_context.memory_head - (&cbcp->memory[0])))
			+((size_t)((&cbcp->memory[0]) + cbcp->memory_length - init_context.memory_tail))));
	fflush(stdout);

	if (init_context.memory_tail != init_context.memory_head) {
		CBCP_DEBUG_PRINT("The total amount allocated by CBCP does not match the bulk allocation:\n   %p\n - %p\n = %ld\n",
			init_context.memory_tail,
			init_context.memory_head,
			(int64_t)(init_context.memory_tail - init_context.memory_head));
		// NOTE(Patrick): This assert covers all errors with whether or not there is
		// enough space I can think of.
		assert(init_context.memory_tail == init_context.memory_head);
		return CBCP_STATUS_ERROR;
	}
	return deserialization_status;
}

void cbcp_debug_print_state(CBCP_State *cbcp)
{
#ifndef CBCP_VERBOSE
	(void)cbcp;
#else
	printf("CBCP State:\n");
	printf("name: %s\n", cbcp->self_name);
	printf("interface_count: %d\n", cbcp->own_interface_count);
	printf("interfaces: %p\n", (void*)cbcp->own_interfaces);
	printf("remote_interface_count: %d\n", cbcp->remote_interface_count);
	printf("remote_interfaces: %p\n", (void*)cbcp->remote_interfaces);
	printf("host_count: %d\n", cbcp->host_count);
	printf("hosts: %p\n", (void*)cbcp->hosts);
	printf("memory_length: %d\n", cbcp->memory_length);

	for(unsigned int i = 0; i < cbcp->own_interface_count; i++)
	{
		CBCP_Own_Interface *interface = cbcp->own_interfaces[i];
		printf("  Interface: %p\n", (void*)interface);
		printf("  name length: %d\n", interface->name_length);
		printf("  name: %.*s\n", interface->name_length, interface->name);
		printf("  command count: %d\n", interface->command_count);

		for(unsigned int j = 0; j < interface->command_count; j++)
		{
			CBCP_Own_Command *command = &interface->commands[j];
			printf("    Command: %p\n", (void*)command);
			printf("    name length: %d\n", command->name_length);
			printf("    name: %.*s\n", command->name_length, command->name);
			printf("    callback: %p\n", __extension__(void*)command->callback);
			printf("    persistent data: %p\n", command->user_data);
		}
	}

	for(unsigned int i = 0; i < cbcp->remote_interface_count; i++)
	{
		CBCP_Remote_Interface *interface = cbcp->remote_interfaces[i];
		printf("  Remote Interface: %p\n", (void*)interface);
		printf("  name length: %d\n", interface->name_length);
		printf("  name: %.*s\n", interface->name_length, interface->name);
		printf("  command count: %d\n", interface->command_count);

		for(unsigned int j = 0; j < interface->command_count; j++)
		{
			CBCP_Remote_Command *command = &interface->commands[j];
			printf("    Remote Command: %p\n", (void*)command);
			printf("    name length: %d\n", command->name_length);
			printf("    name: %.*s\n", command->name_length, command->name);
			printf("    remote command number: %d\n", command->remote_command_number);
		}
	}

	for(unsigned int i = 0; i < cbcp->host_count; ++i)
	{
		CBCP_Host *host = cbcp->hosts[i];
		printf("  Host: %p\n", (void*)host);
		printf("  name length: %d\n", host->name_length);
		printf("  name: %.*s\n", host->name_length, host->name);
		printf("  license_count: %d\n", host->license_count);

		for(unsigned int j = 0; j < host->license_count; ++j)
		{
			CBCP_License *license = &host->licenses[j];
			printf("    Interface Data: %p\n", (void*)license);
			printf("    remote_interface: %p\n", (void *)license->remote_interface);
			printf("    interface_id_at_server: %u\n", license->interface_id_at_server);
		}
	}

	printf("Protocol version string: %.*s\n", CBCP_VERSION_STRING_LENGTH, CBCP_VERSION_STRING);
	printf("Library version string: %.*s\n", CBCP_LIBRARY_VERSION_STRING_LENGTH, CBCP_LIBRARY_VERSION_STRING);
#endif
}

// TODO(Patrick): Jakob might have an opinion as to where this should live
void cbcp_set_host_user_data(
	CBCP_Host *host,
	void *user_data)
{
	host->user_data = user_data;
}

CBCP_Own_Interface *
cbcp_get_own_interface(
	CBCP_State *cbcp,
	char *interface_name,
	unsigned int interface_name_length)
{

	for (unsigned int i = 0; i < cbcp->own_interface_count; ++i) {
		CBCP_Own_Interface *interface = cbcp->own_interfaces[i];

		if (cbcp_length_strings_are_equal(
			interface_name, interface_name_length,
			interface->name, interface->name_length)
		) {
			return interface;
		}
	}

	return NULL;
}


CBCP_Remote_Interface *
cbcp_get_remote_interface(
	CBCP_State *cbcp,
	const char *remote_interface_name,
	unsigned int remote_interface_name_length)
{
	for (unsigned int i = 0; i < cbcp->remote_interface_count; ++i)
	{
		CBCP_Remote_Interface *remote_interface = cbcp->remote_interfaces[i];

		if(cbcp_length_strings_are_equal(
			(char *)remote_interface_name, remote_interface_name_length,
			remote_interface->name, remote_interface->name_length)
		) {
			return remote_interface;
		}
	}
	return NULL;
}

CBCP_Host *
cbcp_get_remote_host(
	CBCP_State *cbcp,
	const char *host_name,
	unsigned int host_name_length)
{
	uint16_t host_id;
	if (cbcp_host_id_from_name(cbcp, host_name, host_name_length, &host_id) == -1) {
		return NULL;
	}

	return cbcp->hosts[host_id];
}

CBCP_Own_Command *
cbcp_get_own_command(
	CBCP_Own_Interface *interface,
	char *command_name,
	unsigned int command_name_length)
{
	// NOTE(jakob): This implementation relies on the cbcp_load_state function
	// pre-populating the command names.

	CBCP_Own_Command *commands = interface->commands;

	for (unsigned int i = 0; i < interface->command_count; ++i) {
		CBCP_Own_Command *command = &commands[i];

		if (cbcp_length_strings_are_equal(
			command->name, command->name_length,
			command_name, command_name_length)
		) {
			return command;
		}
	}

	return NULL;
}

CBCP_Remote_Command *
cbcp_get_remote_command(
	CBCP_Remote_Interface *remote_interface,
	const char *command_name,
	unsigned int command_name_length)
{
	// NOTE(jakob): This implementation relies on the cbcp_load_state function
	// pre-populating the command names.

	CBCP_Remote_Command *remote_commands = remote_interface->commands;

	for (unsigned int i = 0; i < remote_interface->command_count; ++i) {
		CBCP_Remote_Command *remote_command = &remote_commands[i];

		if (cbcp_length_strings_are_equal(
			remote_command->name, remote_command->name_length,
			(char *)command_name, command_name_length)
		) {
			return remote_command;
		}
	}

	return NULL;
}


void
cbcp_server_set_command_callback(
	CBCP_Own_Command *own_command,
	CBCP_Command_Callback command_callback,
	void *user_data,
	void *response_buffer,
	unsigned int response_buffer_length)
{
	own_command->callback = command_callback;
	own_command->user_data = user_data;
	own_command->response_buffer = response_buffer;
	own_command->response_buffer_length = response_buffer_length;
}


void
cbcp_server_set_command_rejected_callback(
	CBCP_State *cbcp,
	CBCP_Command_Rejected_Callback command_rejected_callback,
	void *user_data)
{
	cbcp->command_rejected_callback = command_rejected_callback;
	cbcp->command_rejected_callback_user_data = user_data;
}

void
cbcp_server_disable_command_for_all(
	CBCP_Own_Command *own_command)
{
	CBCP_Own_Interface *own_interface = own_command->interface;

	uint64_t negagtive_mask = ~(1 << own_command->command_id);

	for (unsigned int i = 0; i < own_interface->capability_entry_count; ++i) {
		CBCP_Capability_Entry *entry = &own_interface->capability_table[i];
		entry->capability.capability_mask &= negagtive_mask;
	}
}

CBCP_License *
cbcp_get_remote_interface_license(
	CBCP_Host *host,
	CBCP_Remote_Interface *remote_interface)
{
	// Linear search
	for(unsigned int i = 0; i < host->license_count; i++)
	{
		CBCP_License *license = &host->licenses[i];
		if(license->remote_interface == remote_interface)
		{
			return license;
		}
	}
	return NULL;
}

CBCP_Net_Implementation *
cbcp_get_net_implementation_for_host(CBCP_Host *host)
{
	return host->net_impl;
}

unsigned int
cbcp_size_of_connection(CBCP_Net_Implementation *net_impl)
{
	unsigned int size =
		CBCP_FLEXIBLE_SIZEOF(CBCP_Connection, net_connection_memory)
		+ net_impl->size_of_connection;
	return size;
}

CBCP_Status
cbcp_client_connect(
	CBCP_State *cbcp,
	CBCP_Host *host,
	CBCP_Connection *connection)
{
	if (cbcp_client_handshake(cbcp, host) == -1) {
		return CBCP_STATUS_ERROR;
	}

	CBCP_Net_Implementation *net_impl = host->net_impl;
	connection->net_impl = net_impl;
	connection->connected_host = host;
	connection->sequence_number = 0;

	//@critical
	// We also need to guarantee that it won't overlap in range with other generated IVs
	// We can use larger IVs if necessary.

	CBCP_Status status = net_impl->client_open_connection(
		net_impl->implementation_state,
		host->net_address.impl_address,
		CBCP_FALSE,
		(void *)connection->net_connection_memory);

	if (status == -1) {
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}

CBCP_Status
cbcp_close_connection(
	CBCP_Connection *connection)
{
	CBCP_Net_Implementation *net_impl = connection->net_impl;

	CBCP_Status status = net_impl->close_connection(
		net_impl->implementation_state,
		(void *)&connection->net_connection_memory);

	return status;
}

CBCP_Net_Implementation *
cbcp_net_add_impl(CBCP_Net_Implementation impl)
{
	if (cbcp_global_net_implementation_count > CBCP_MAX_NET_IMPLEMENTATIONS) {
		return NULL;
	}

	CBCP_Net_Implementation *result = &cbcp_global_net_implementations[cbcp_global_net_implementation_count];
	cbcp_global_net_implementation_count++;
	*result = impl;

	return result;
}


CBCP_Sequence_Number
cbcp_client_send_command_packet(
	CBCP_Remote_Command *remote_command,
	CBCP_License *license,
	char *packet,
	unsigned int payload_length,
	CBCP_Connection *connection)
{
	assert(license != NULL);

	CBCP_Capability aggregate =
		cbcp_capability_aggregate_reduction_field_and_command(
			remote_command->remote_command_number,
			&license->reduction_field);

	if (!aggregate.capability_mask) {
		return -1;
	}

	CBCP_Host *host = connection->connected_host;
	CBCP_Net_Implementation *net_impl = connection->net_impl;

	char *at = packet;

	//
	// Additional authenticated data (AAD)
	//
	unsigned char *additional_authenticated_data = (unsigned char *)at;

	uint16_t client_id_at_server = host->client_id_at_server;
	cbcp_serialize_u16(&at, client_id_at_server);

	unsigned char *initial_vector = (unsigned char *)at;
	RAND_bytes(initial_vector, CBCP_AES_INITIAL_VECTOR_SIZE);
	at += CBCP_AES_INITIAL_VECTOR_SIZE;

	unsigned int additional_authenticated_data_length;
	additional_authenticated_data_length = at - packet;

	//
	// GCM Tag
	//
	unsigned char *tag = (unsigned char *)at;
	cbcp_serialize_zero_bytes(&at, CBCP_AES_GCM_TAG_SIZE);

	//
	// Command packet header
	//
	CBCP_Command_Packet_Header packet_header = CBCP_ZERO_INITIALIZER;
	packet_header.client_id_at_server = client_id_at_server;
	packet_header.sequence_number = connection->sequence_number;
	packet_header.client_group_id = license->client_group_id;
	packet_header.interface_id_at_server = license->interface_id_at_server;
	packet_header.capability_id = license->capability_id;
	packet_header.payload_length = payload_length;
	packet_header.command_id = remote_command->remote_command_number;
	packet_header.reduction_field = license->reduction_field;
	packet_header.secret = license->secret;

	unsigned char *packet_header_location = (unsigned char *)at;

	cbcp_serialize_command_packet_header(&at, &packet_header);


	// CBCP_DEBUG_PRINT("packet: %p, end of header: %p\n", packet, packet+CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE+CBCP_ADDITIONAL_AUTHENTICATED_DATA_SIZE+CBCP_AES_GCM_TAG_SIZE+net_impl->additional_packet_header_space);
	// CBCP_DEBUG_PRINT("additional_authenticated_data_location: %p\n", additional_authenticated_data_location);
	// CBCP_DEBUG_PRINT("additional_authenticated_data_length: %ld\n", CBCP_ADDITIONAL_AUTHENTICATED_DATA_SIZE);
	// CBCP_DEBUG_PRINT("packet_header_location: %p\n", packet_header_location);
	// CBCP_DEBUG_PRINT("payload_length: %d\n", payload_length);

	// CBCP_DEBUG_PRINT("Pre-encryption dump:\n");
	// BIO_dump_fp (stdout, (const char *)packet, 0x72);
	// CBCP_DEBUG_PRINT("\n");

	unsigned int packet_length;
	unsigned int amount_to_encrypt;
	{
		unsigned int unpadded_amount_to_encrypt = (
			CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE +
			net_impl->size_of_additional_packet_header +
			payload_length);

		amount_to_encrypt = cbcp_round_up_to_nearest_encryption_block_size(unpadded_amount_to_encrypt);
		unsigned int padding = amount_to_encrypt - unpadded_amount_to_encrypt;
		memset(packet_header_location + unpadded_amount_to_encrypt, 0, padding);

		packet_length = amount_to_encrypt + CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE;
	}

	// CBCP_DEBUG_PRINT("amount_to_encrypt: %d\n", amount_to_encrypt);

	unsigned int encrypted_length = 0;

	if(cbcp_gcm_encrypt_in_place(
		packet_header_location,
		amount_to_encrypt,
		additional_authenticated_data,
		additional_authenticated_data_length,
		host->aes_key,
		initial_vector, CBCP_AES_INITIAL_VECTOR_SIZE,
		tag,
		&encrypted_length) == -1)
	{
		CBCP_DEBUG_PRINT("Failed to encrypt the packet.\n");
		return -1;
	}
#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("\nencryptED_length: %d\n", encrypted_length);
	CBCP_DEBUG_PRINT("TAG:\n");
	BIO_dump_fp (stdout, (const char *)tag, CBCP_AES_GCM_TAG_SIZE);
	CBCP_DEBUG_PRINT("\n");
	CBCP_DEBUG_PRINT("Packet length: %d\n", packet_length);

	BIO_dump_fp (stdout, (const char *)packet, packet_length);
#endif

	CBCP_Status status;
	status = net_impl->send(
		net_impl->implementation_state,
		connection->net_connection_memory,
		packet,
		packet_length);

	if (status == -1) {
		CBCP_DEBUG_PRINT("cbcp_client_send_command: Net implementation send failed.\n");
		return -1;
	}

	CBCP_Sequence_Number sequence_number = connection->sequence_number;

	++connection->sequence_number;

	return sequence_number;
}


CBCP_Sequence_Number
cbcp_client_get_command_response(
	char *response_buffer,
	unsigned int response_buffer_length,
	CBCP_Connection *connection,
	unsigned int *out_response_length)
{
	assert(response_buffer && response_buffer_length);

	CBCP_Net_Implementation *net_impl = connection->net_impl;

	int amount_received;
	if(net_impl->receive(
		net_impl->implementation_state,
		connection->net_connection_memory,
		response_buffer,
		response_buffer_length,
		&amount_received) == -1
	) {
		goto clean_up_and_return_error_1;
	}

	assert(amount_received >= 0);

	char *at;
	at = response_buffer;

	if ((unsigned int)amount_received < cbcp_offset_to_response_payload(net_impl)) {
		goto clean_up_and_return_error_1;
	}

#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("Response pre-decryption packet:\n");
	BIO_dump_fp (stdout, (const char *)response_buffer, amount_received);
#endif

	//
	// Additinoal authenticated data
	//
	unsigned char *additional_authenticated_data;
	additional_authenticated_data = (unsigned char *) at;

	unsigned char *iv;
	iv = (unsigned char *)at;
	at += CBCP_AES_INITIAL_VECTOR_SIZE;

	unsigned int additional_authenticated_data_length;
	additional_authenticated_data_length = at - response_buffer;

	//
	// GCM TAG
	//

	unsigned char *tag;
	tag = (unsigned char*)at;
#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("TAG:\n");
	BIO_dump_fp (stdout, (const char *)tag, CBCP_AES_GCM_TAG_SIZE);
#endif
	at += CBCP_AES_GCM_TAG_SIZE;

	EVP_CIPHER_CTX *cipher_context;
	if(!(cipher_context = EVP_CIPHER_CTX_new())) {
		CBCP_DEBUG_PRINT("Failed to create new openssl cipher context.\n");
		goto clean_up_and_return_error_2;
	}

	unsigned char *decryption_location;
	decryption_location = (unsigned char *)at;

	// Decrypt only the header first.

	if(cbcp_gcm_decrypt_cbcp_packet_header(
		cipher_context,
		decryption_location,
		additional_authenticated_data,
		additional_authenticated_data_length,
		connection->connected_host->aes_key,
		iv, CBCP_AES_INITIAL_VECTOR_SIZE,
		CBCP_ENCRYPTED_RESPONSE_PACKET_HEADER_SIZE) == -1)
	{
		CBCP_DEBUG_PRINT("Error during decryption of packet header.\n");
		goto clean_up_and_return_error_2;
	}

	CBCP_Response_Packet_Header packet_header;
	cbcp_deserialize_response_packet_header(&at, &packet_header);


	unsigned int payload_decryption_amount;
	payload_decryption_amount = packet_header.response_payload_length;
	payload_decryption_amount = cbcp_round_up_to_nearest_encryption_block_size(
		payload_decryption_amount);


	unsigned int rest_of_response_buffer_length;
	rest_of_response_buffer_length = response_buffer_length - (at - response_buffer);

	if (payload_decryption_amount > rest_of_response_buffer_length) {
		CBCP_DEBUG_PRINT("Packet payload exceeds receive buffer size.\n");
		// TODO: Better error handling here.
		goto clean_up_and_return_error_2;
	}

	if(cbcp_gcm_decrypt_cbcp_packet_payload(
		cipher_context,
		(unsigned char*)at, payload_decryption_amount,
		tag) == -1)
	{
		CBCP_DEBUG_PRINT("Error during decryption of payload.\n");
		// TODO: Better error handling here.
		goto clean_up_and_return_error_2;
	}


#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("Response post-decryption packet:\n");
	BIO_dump_fp (stdout, (const char *)response_buffer, amount_received);
#endif


	*out_response_length = packet_header.response_payload_length;
	return packet_header.sequence_number;

clean_up_and_return_error_2:
	EVP_CIPHER_CTX_free(cipher_context);

clean_up_and_return_error_1:
	net_impl->close_connection(net_impl->implementation_state, connection->net_connection_memory);
	return CBCP_INVALID_SEQUENCE_NUMBER;
}

CBCP_Status
cbcp_server_handshake(
	CBCP_State *cbcp,
	CBCP_Net_Implementation *net)
{

	void *control_connection_state = alloca(net->size_of_connection);

	CBCP_Bool should_try_again = CBCP_FALSE;
	CBCP_Status status;

	status = net->server_accept_connection(
		net->implementation_state,
		CBCP_TRUE, // Serve control messages
		control_connection_state,
		&should_try_again);

	if (status == -1) {
		return CBCP_STATUS_ERROR;
	}
	else if (should_try_again) {
		return CBCP_STATUS_SUCCESS;
	}

	//
	// CBCP 4-step handshake (CBCP v1.0):
	// STEP 1. client -> [ major_version | minor_version | challenge_1 | name_length | name ] -> server
	// STEP 2. client <- [ challenge_1_proof | challenge_2 ]                                  <- server
	// STEP 3. client -> [ challenge_2_proof | challenge_3 | aes_key ]                        -> server
	// STEP 4. client <- [ challenge_3_proof | client_id_at_server ]                          <- server
	//

	// NOTE(jakob): 512 should be large enough for all encrypted control messages.
	char cipher_buffer[512];
	char plaintext_buffer[512];

	char *at;

	//
	// STEP 1. receive handshake request from client,
	// looking up their id by name
	//
	// Packet to RECEIVE:
	//   { u16 major_version; u16 minor_versionu; u64 challenge_1; u8 name_length; char name[name_length] }
	//

	// Receive //
	int amount_received;

	if (net->receive(
		net->implementation_state,
		control_connection_state,
		cipher_buffer,
		sizeof(cipher_buffer),
		&amount_received) == -1
	) {
		return CBCP_STATUS_ERROR;
	}

	if (amount_received == -1) {
		return CBCP_STATUS_ERROR;
	}

	if ((unsigned int)amount_received > sizeof(cipher_buffer)) {
		return CBCP_STATUS_ERROR;
	}

	// Decrypt //

	int amount_decrypted;
	amount_decrypted = RSA_private_decrypt(
		amount_received,
		(unsigned char *)cipher_buffer,
		(unsigned char *)plaintext_buffer,
		cbcp->self_private_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_decrypted < 0) {
		char error_buffer[256];
		ERR_error_string(ERR_get_error(), (char *)error_buffer);
		CBCP_DEBUG_PRINT("OpenSSL ERROR: %.*s\n", (int)sizeof(error_buffer), error_buffer);
		return CBCP_STATUS_ERROR;
	}

	at = plaintext_buffer;

	// Verify challenge_1_proof //

	uint16_t cbcp_major_version = cbcp_deserialize_u16(&at);
	uint16_t cbcp_minor_version = cbcp_deserialize_u16(&at);

	if ((cbcp_major_version != CBCP_MAJOR_VERSION) &&
		(cbcp_minor_version != CBCP_MINOR_VERSION)
	) {
		return CBCP_STATUS_ERROR;
	}

	uint64_t challenge_1;
	uint8_t name_length;
	char name[256];

	cbcp_deserialize_byte_array(&at, (char *)&challenge_1, sizeof(challenge_1));

	name_length = cbcp_deserialize_u8(&at);
	cbcp_deserialize_byte_array(&at, (char *)name, name_length);

	// Lookup host by name //

	uint16_t client_id_at_server;
	if (cbcp_host_id_from_name(cbcp, name, name_length, &client_id_at_server) == -1) {
		return CBCP_STATUS_ERROR;
	}

	CBCP_Host *host = cbcp->hosts[client_id_at_server];

	//
	// STEP 2. Send challenge proof and a new challenge for the client.
	//
	// Packet to RECEIVE:
	//   { u64 challenge_1_proof; u64 challenge_2 }
	//

	at = plaintext_buffer;

	uint64_t challenge_1_proof = challenge_1;

	uint64_t challenge_2;
	RAND_bytes((unsigned char *)&challenge_2, sizeof(challenge_2));

	cbcp_serialize_byte_array(&at, (char *)&challenge_1_proof, sizeof(challenge_1_proof));
	cbcp_serialize_byte_array(&at, (char *)&challenge_2, sizeof(challenge_2));

	unsigned int maximum_allowed_encryption_size =
		RSA_size(host->public_key.key) - CBCP_RSA_PADDING_SCHEME_RESERVED_BYTES;
	unsigned int amount_to_encrypt = (unsigned int)(at - plaintext_buffer);

	assert(amount_to_encrypt == sizeof(challenge_1_proof) + sizeof(challenge_2));

	assert(amount_to_encrypt < maximum_allowed_encryption_size);

	int amount_encrypted = RSA_public_encrypt(
		amount_to_encrypt,
		(const unsigned char *)plaintext_buffer,
		(unsigned char *)cipher_buffer,
		host->public_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_encrypted < 0) {
		//ERR_get_error();
		return CBCP_STATUS_ERROR;
	}

	assert((unsigned int)amount_encrypted <= sizeof(cipher_buffer));

	if (net->send(
		net->implementation_state,
		control_connection_state,
		cipher_buffer,
		amount_encrypted) == -1
	) {
		return CBCP_STATUS_ERROR;
	}

	//
	// STEP 3. Receive proof of decryption of challenge_2 sent in STEP 2.
	// Decrypt next challenge (challenge_3) created by the client.
	// Also receive the shared AES key to be used for command communication.
	//
	// Packet to RECEIVE:
	//   { u64 challenge_2_proof; u64 challenge_3; AES_KEY aes_key }
	//

	// Receive //

	if (net->receive(
		net->implementation_state,
		control_connection_state,
		cipher_buffer,
		sizeof(cipher_buffer),
		&amount_received) == -1
	) {
		return CBCP_STATUS_ERROR;
	}

	if (amount_received != RSA_size(cbcp->self_private_key.key)) {
		return CBCP_STATUS_ERROR;
	}

	if ((unsigned int)amount_received > sizeof(cipher_buffer)) {
		return CBCP_STATUS_ERROR;
	}

	// Decrypt //

	amount_decrypted = RSA_private_decrypt(
		amount_received,
		(unsigned char *)cipher_buffer,
		(unsigned char *)plaintext_buffer,
		cbcp->self_private_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_decrypted < 0) {
		char error_buffer[256];
		ERR_error_string(ERR_get_error(), (char *)error_buffer);
		CBCP_DEBUG_PRINT("OpenSSL ERROR: %.*s\n", (int)sizeof(error_buffer), error_buffer);
		return CBCP_STATUS_ERROR;
	}

	at = plaintext_buffer;

	// Deserialize //

	uint64_t challenge_2_proof;
	uint64_t challenge_3;

	cbcp_deserialize_byte_array(&at, (char *)&challenge_2_proof, sizeof(challenge_2_proof));

	if (challenge_2_proof != challenge_2) {
		return CBCP_STATUS_ERROR;
	}

	cbcp_deserialize_byte_array(&at, (char *)&challenge_3, sizeof(challenge_3));

	cbcp_deserialize_byte_array(&at, (char *)&host->aes_key, sizeof(host->aes_key));

	//
	// STEP 4.
	// Packet to SEND:
	//   { u64 challenge_3_proof; u16 client_id_at_server }
	//

	at = plaintext_buffer;

	uint64_t challenge_3_proof = challenge_3;

	cbcp_serialize_byte_array(&at, (char *)&challenge_3_proof, sizeof(challenge_3_proof));
	cbcp_serialize_u16(&at, client_id_at_server);

	amount_to_encrypt = (unsigned int)(at - plaintext_buffer);

	assert(amount_to_encrypt == sizeof(challenge_3_proof) + sizeof(client_id_at_server));

	assert(amount_to_encrypt < maximum_allowed_encryption_size);

	amount_encrypted = RSA_public_encrypt(
		amount_to_encrypt,
		(const unsigned char *)plaintext_buffer,
		(unsigned char *)cipher_buffer,
		host->public_key.key,
		CBCP_RSA_PADDING_SCHEME);

	if (amount_encrypted < 0) {
		//ERR_get_error();
		return CBCP_STATUS_ERROR;
	}

	assert((unsigned int)amount_encrypted <= sizeof(cipher_buffer));

	if (net->send(
		net->implementation_state,
		control_connection_state,
		cipher_buffer,
		amount_encrypted) == -1
	) {
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}


CBCP_Status
cbcp_server_accept_connection(
	CBCP_Net_Implementation *net_impl,
	/*IN + OUT*/ CBCP_Connection *connection,
	CBCP_Bool *out_should_try_again)
{
	connection->net_impl = net_impl;

	// NOTE(jakob): We first know which host it is and what sequence number we use when we receive
	connection->connected_host = NULL;
	connection->sequence_number = 0;


	if (net_impl->server_accept_connection(
		net_impl->implementation_state,
		CBCP_FALSE, // Serve commands
		connection->net_connection_memory,
		out_should_try_again) == -1)
	{
		return CBCP_STATUS_ERROR;
	}



	return CBCP_STATUS_SUCCESS;
}

CBCP_Status
cbcp_server_handle_command(
	CBCP_State *cbcp,
	char *receive_buffer,
	unsigned int receive_buffer_length,
	CBCP_Connection *connection,
	CBCP_Command_Result *out_command_result)
{
	CBCP_Net_Implementation *net_impl = connection->net_impl;
	CBCP_Command_Rejected_Args command_rejected_args = CBCP_ZERO_INITIALIZER;
	command_rejected_args.user_data = cbcp->command_rejected_callback_user_data;

	int receive_amount;

	if (net_impl->receive(
		net_impl->implementation_state,
		connection->net_connection_memory,
		receive_buffer,
		receive_buffer_length,
		&receive_amount) == -1
	) {
		CBCP_DEBUG_PRINT("Error when serving using network subsystem, '%s'\n", net_impl->name);
		goto clean_up_and_return_error_1;
	}

	assert((unsigned int)receive_amount <= receive_buffer_length);

	char *at;
	at = receive_buffer;

	if ((unsigned int)receive_amount < cbcp_offset_to_command_payload(net_impl)) {
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_PACKET_TOO_SMALL;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_1;
	}
#ifdef CBCP_VERBOSE
	BIO_dump_fp (stdout, (const char *)receive_buffer, 0x72);
#endif

	// Decrypt only the header first.

	//
	// Additinoal authenticated data
	//
	unsigned char *additional_authenticated_data;
	additional_authenticated_data = (unsigned char *) at;

	uint16_t client_id_at_server;
	client_id_at_server = cbcp_deserialize_u16(&at);

	if(client_id_at_server >= cbcp->host_count) {
		CBCP_DEBUG_PRINT("Received host id is out of bounds: %d.\n", client_id_at_server);

		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_INVALID_HOST_ID;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_1;
	}

	unsigned char *iv;
	iv = (unsigned char *)at;
	at += CBCP_AES_INITIAL_VECTOR_SIZE;

	unsigned int additional_authenticated_data_length;
	additional_authenticated_data_length = at - receive_buffer;

	//
	// GCM TAG
	//
	unsigned char *tag;
	tag = (unsigned char*)at;

	at += CBCP_AES_GCM_TAG_SIZE;

#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("TAG:\n");
	BIO_dump_fp (stdout, (const char *)tag, CBCP_AES_GCM_TAG_SIZE);
#endif

	CBCP_Host *host;
	host = cbcp->hosts[client_id_at_server];


	EVP_CIPHER_CTX *context;
	if(!(context = EVP_CIPHER_CTX_new())) {
		CBCP_DEBUG_PRINT("Failed to create new openssl cipher context.\n");

		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_OPENSSL_ERROR;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}

	unsigned char *decryption_location;
	decryption_location = (unsigned char *)at;

	if(cbcp_gcm_decrypt_cbcp_packet_header(
		context,
		decryption_location,
		additional_authenticated_data,
		additional_authenticated_data_length,
		host->aes_key,
		iv, CBCP_AES_INITIAL_VECTOR_SIZE,
		CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE) == -1)
	{
		CBCP_DEBUG_PRINT("Error during decryption of packet header.\n");
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_HEADER_DECRYPTION_FAILED;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}

	CBCP_Command_Packet_Header packet_header;
	cbcp_deserialize_command_packet_header(&at, &packet_header);

	unsigned int payload_decryption_amount;
	payload_decryption_amount = packet_header.payload_length;
	payload_decryption_amount = cbcp_round_up_to_nearest_encryption_block_size(
		payload_decryption_amount);

	CBCP_DEBUG_PRINT("decryption_amount: %d\n", payload_decryption_amount);

	unsigned int rest_of_receive_buffer_length;
	rest_of_receive_buffer_length = receive_buffer_length - (at - receive_buffer);

	if (payload_decryption_amount > rest_of_receive_buffer_length) {
		CBCP_DEBUG_PRINT("Packet payload exceeds receive buffer size.\n");
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_PAYLOAD_EXCEEDS_RECEIVE_BUFFER;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}

	if(cbcp_gcm_decrypt_cbcp_packet_payload(
		context,
		(unsigned char*)at, payload_decryption_amount,
		tag) == -1)
	{
		CBCP_DEBUG_PRINT("Error during decryption of payload.\n");
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_PAYLOAD_DECRYPTION_FAILED;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}


	CBCP_DEBUG_PRINT("Bounds checking interface id: %d\n", packet_header.interface_id_at_server);
	if (packet_header.interface_id_at_server >= cbcp->own_interface_count) {
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_INVALID_INTERFACE_ID;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}

	CBCP_Own_Interface *own_interface;
	own_interface = cbcp->own_interfaces[packet_header.interface_id_at_server];

	if (packet_header.capability_id >= own_interface->capability_entry_count) {
		if (cbcp->command_rejected_callback) {
			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_INVALID_CAPABILITY_ID;
			cbcp->command_rejected_callback(command_rejected_args);
		}
		goto clean_up_and_return_error_2;
	}

	CBCP_Capability capability;
	capability = own_interface->capability_table[packet_header.capability_id].capability;

	CBCP_DEBUG_PRINT("Validating.\n");

	CBCP_Command_Result command_result;
	memset(&command_result, 0, sizeof(command_result));

	if (cbcp_capability_validate_secret(
		packet_header.command_id,
		&packet_header.secret,
		&own_interface->master_secret,
		&packet_header.reduction_field,
		packet_header.capability_id,
		capability)
	) {
		CBCP_DEBUG_PRINT("Receiving side command address: (i:%d, c:%d)\n",
				packet_header.interface_id_at_server, packet_header.command_id);

		uint16_t payload_length = packet_header.payload_length;
		CBCP_DEBUG_PRINT("  Payload length: %d\n", payload_length);

		if (packet_header.command_id >= own_interface->command_count) {
			CBCP_DEBUG_PRINT("Command ID Invalid.\n");

			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_INVALID_COMMAND_ID;
			cbcp->command_rejected_callback(command_rejected_args);
			goto clean_up_and_return_error_2;
		}

		CBCP_Own_Command *command = &own_interface->commands[packet_header.command_id];


		if (!command->callback) {
			CBCP_DEBUG_PRINT("Command not implemented.\n");

			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_COMMAND_NOT_IMPLEMENTED;
			cbcp->command_rejected_callback(command_rejected_args);
			goto clean_up_and_return_error_2;
		}

		unsigned int offset_to_response_payload = cbcp_offset_to_response_payload(net_impl);

		if (offset_to_response_payload > command->response_buffer_length) {
			CBCP_DEBUG_PRINT("Command response buffer not big enough.\n");

			command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_RESPONSE_BUFFER_TOO_SMALL;
			cbcp->command_rejected_callback(command_rejected_args);
			goto clean_up_and_return_error_2;
		}

		CBCP_Command_Args args;
		args.payload = at;
		args.payload_length = payload_length;
		args.response_payload = ((char *)command->response_buffer) + offset_to_response_payload;
		args.response_payload_length = 0;
		args.response_payload_max_length = command->response_buffer_length - offset_to_response_payload;
		args.host_user_data = host->user_data;
		args.user_data = command->user_data;
		args.cbcp = cbcp;

		command->callback(&args);
		command_result.response_buffer = command->response_buffer;
		command_result.response_payload_length = args.response_payload_length;
	}
	else if (cbcp->command_rejected_callback) {
		// NOTE(jakob): Capability license invalid, call back user program
		command_rejected_args.reason = CBCP_COMMAND_REJECTED_REASON_INVALID_CAPABILITY;
		cbcp->command_rejected_callback(command_rejected_args);
		return CBCP_STATUS_ERROR;
	}

	// NOTE(jakob): Fill out remaining fields of connection struct
	connection->connected_host = host;
	connection->sequence_number = packet_header.sequence_number;

	EVP_CIPHER_CTX_free(context);
	*out_command_result = command_result;
	return CBCP_STATUS_SUCCESS;

clean_up_and_return_error_2:
	EVP_CIPHER_CTX_free(context);

clean_up_and_return_error_1:
	net_impl->close_connection(net_impl->implementation_state, connection->net_connection_memory);

	return CBCP_STATUS_ERROR;
}

CBCP_Status
cbcp_server_send_command_response(
	CBCP_Connection *connection,
	CBCP_Command_Result command_result)
{
	CBCP_Net_Implementation *net_impl = connection->net_impl;

	char *at = (char *)command_result.response_buffer;

	//
	// Additional authenticated data (AAD)
	//
	unsigned char *additional_authenticated_data = (unsigned char *)at;

	unsigned char *initial_vector = (unsigned char *)at;
	RAND_bytes(initial_vector, CBCP_AES_INITIAL_VECTOR_SIZE);
	at += CBCP_AES_INITIAL_VECTOR_SIZE;

	unsigned int additional_authenticated_data_length;
	additional_authenticated_data_length = at - (char *)command_result.response_buffer;

	//
	// GCM Tag
	//
	unsigned char *tag = (unsigned char *)at;
	cbcp_serialize_zero_bytes(&at, CBCP_AES_GCM_TAG_SIZE);

	//
	// Response packet header
	//
	CBCP_Response_Packet_Header packet_header = CBCP_ZERO_INITIALIZER;
	packet_header.sequence_number = connection->sequence_number;
	packet_header.response_payload_length = command_result.response_payload_length;


	unsigned char *packet_header_location = (unsigned char *)at;

	cbcp_serialize_response_packet_header(&at, &packet_header);


	unsigned int packet_length;
	unsigned int amount_to_encrypt;
	{
		unsigned int unpadded_amount_to_encrypt = (
			CBCP_ENCRYPTED_RESPONSE_PACKET_HEADER_SIZE +
			net_impl->size_of_additional_packet_header +
			command_result.response_payload_length);


		amount_to_encrypt = cbcp_round_up_to_nearest_encryption_block_size(unpadded_amount_to_encrypt);
		unsigned int padding = amount_to_encrypt - unpadded_amount_to_encrypt;
		memset(packet_header_location + unpadded_amount_to_encrypt, 0, padding);

		packet_length = amount_to_encrypt + CBCP_UNENCRYPTED_RESPONSE_PACKET_HEADER_SIZE;
	}

	// CBCP_DEBUG_PRINT("amount_to_encrypt: %d\n", amount_to_encrypt);

	unsigned int encrypted_length = 0;


#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("Response pre-encryption packet:\n");
	BIO_dump_fp (stdout, (const char *)command_result.response_buffer, packet_length);
#endif


	if(cbcp_gcm_encrypt_in_place(
		packet_header_location,
		amount_to_encrypt,
		additional_authenticated_data,
		additional_authenticated_data_length,
		connection->connected_host->aes_key,
		initial_vector, CBCP_AES_INITIAL_VECTOR_SIZE,
		tag,
		&encrypted_length) == -1)
	{
		CBCP_DEBUG_PRINT("Failed to encrypt the packet.\n");
		return CBCP_STATUS_ERROR;
	}
#ifdef CBCP_VERBOSE
	CBCP_DEBUG_PRINT("Response post-encryption packet:\n");
	BIO_dump_fp (stdout, (const char *)command_result.response_buffer, packet_length);
	CBCP_DEBUG_PRINT("TAG:\n");
	BIO_dump_fp (stdout, (const char *)tag, CBCP_AES_GCM_TAG_SIZE);
#endif

	if(net_impl->send(
		net_impl->implementation_state,
		connection->net_connection_memory,
		(char *)command_result.response_buffer,
		packet_length) == -1)
	{
		return CBCP_STATUS_ERROR;
	}

	return CBCP_STATUS_SUCCESS;
}

unsigned int
cbcp_offset_to_command_payload(CBCP_Net_Implementation *net_impl)
{
	unsigned int result = (
		CBCP_UNENCRYPTED_COMMAND_PACKET_HEADER_SIZE +
		CBCP_ENCRYPTED_COMMAND_PACKET_HEADER_SIZE +
		net_impl->size_of_additional_packet_header);

	return result;
}

unsigned int
cbcp_offset_to_response_payload(CBCP_Net_Implementation *net_impl)
{
	unsigned int result = (
		CBCP_UNENCRYPTED_RESPONSE_PACKET_HEADER_SIZE +
		CBCP_ENCRYPTED_RESPONSE_PACKET_HEADER_SIZE +
		net_impl->size_of_additional_packet_header);

	return result;
}

unsigned int
cbcp_size_of_command_packet(unsigned int payload_size, CBCP_Net_Implementation *net_impl)
{
	unsigned int result;

	result = cbcp_offset_to_command_payload(net_impl);
	result += payload_size;
	result = cbcp_round_up_to_nearest_encryption_block_size(result);

	return result;
}


unsigned int
cbcp_size_of_response_packet(unsigned int payload_size, CBCP_Net_Implementation *net_impl)
{
	unsigned int result;

	result = cbcp_offset_to_response_payload(net_impl);
	result += payload_size;
	result = cbcp_round_up_to_nearest_encryption_block_size(result);

	return result;
}

#undef CBCP_ADDITIONAL_AUTHENTICATED_DATA_SIZE
#undef CBCP_AES_GCM_TAG_SIZE
