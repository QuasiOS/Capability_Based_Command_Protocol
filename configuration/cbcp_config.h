#ifndef CBCP_CONFIG_H
#define CBCP_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#	define CBCP_ZERO_INITIALIZER {}
#	define CBCP_C_LITERAL(TYPE)
#else
#	define CBCP_ZERO_INITIALIZER {0}
#	define CBCP_C_LITERAL(TYPE) (TYPE)
#endif

#define CBCP_ZERO_LITERAL(TYPE) CBCP_C_LITERAL(TYPE)CBCP_ZERO_INITIALIZER

#define CBCP_CONFIG_DEFINE_STATUS_TYPE(name, ...) enum name##_E {__VA_ARGS__}; typedef struct { enum name##_E error; } name

#ifdef __cplusplus
#define CBCP_CONFIG_STATUS(type, value) {type ## __ ## value}
#else
#define CBCP_CONFIG_STATUS(type, value) ((type){type ## __ ## value})
#endif

#define CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE 64
#define CBCP_CONFIG_CAPABILITY_NAME_LENGTH_LIMIT 256

#define CBCP_CONFIG_FIELD_SEPERATOR ';'
#define CBCP_CONFIG_SUBFIELD_SEPERATOR ','

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Status,
	CBCP_Config_Status__SUCCESS = 0,
	CBCP_Config_Status__ERROR = -1,
);
#define CBCP_CONFIG_STATUS_SUCCESS CBCP_CONFIG_STATUS(CBCP_Config_Status, SUCCESS)
#define CBCP_CONFIG_STATUS_ERROR CBCP_CONFIG_STATUS(CBCP_Config_Status, ERROR)

#define CBCP_CAPABILITY_SECRET_SIZE 16
#define CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT 4
#define CBCP_CAPABILITY_KEY_SIZE 128

typedef struct CBCP_Capability {
	uint64_t capability_mask;
} CBCP_Capability;

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


#define CBCP_REFLIST_TYPE_LIST\
	CBCP_L(CBCP_Config_Group, struct CBCP_Config_Group, cbcp_config_group)\
	CBCP_L(CBCP_Config_Group_Bucket, struct CBCP_Config_Group_Bucket, cbcp_config_group_bucket)\
	CBCP_L(CBCP_Config_Hash_Entry_Bucket, struct CBCP_Config_Hash_Entry_Bucket, cbcp_config_hash_entry_bucket)\
	CBCP_L(CBCP_Config_Host, struct CBCP_Config_Host, cbcp_config_host)\
	CBCP_L(CBCP_Config_Host_Bucket, struct CBCP_Config_Host_Bucket, cbcp_config_host_bucket)\
	CBCP_L(CBCP_Config_Interface_Bucket, struct CBCP_Config_Interface_Bucket, cbcp_config_interface_bucket)\
	CBCP_L(CBCP_Config_Interface_Instance, struct CBCP_Config_Interface_Instance, cbcp_config_interface_instance)\
	CBCP_L(CBCP_Config_Interface_Instance_Bucket, struct CBCP_Config_Interface_Instance_Bucket, cbcp_config_interface_instance_bucket)\
	CBCP_L(CBCP_Config_Interface_Subset, struct CBCP_Config_Interface_Subset, cbcp_config_interface_subset)\
	CBCP_L(CBCP_Config_License, struct CBCP_Config_License, cbcp_config_license)\
	CBCP_L(CBCP_Config_License_Bucket, struct CBCP_Config_License_Bucket, cbcp_config_license_bucket)\
	CBCP_L(CBCP_Config_Neighbor_Info, struct CBCP_Config_Neighbor_Info, cbcp_config_neighbor_info)\
	CBCP_L(CBCP_Config_Net_Address, struct CBCP_Config_Net_Address, cbcp_config_net_address)\
	CBCP_L(CBCP_Config_Net_Address_Bucket, struct CBCP_Config_Net_Address_Bucket, cbcp_config_net_address_bucket)\
	CBCP_L(CBCP_Config_String, struct CBCP_Config_String, cbcp_config_string)\
	CBCP_L(CBCP_Config_String_Bucket, struct CBCP_Config_String_Bucket, cbcp_config_string_bucket)\
	CBCP_L(CBCP_Config_Capability, struct CBCP_Capability, cbcp_config_capability)\
	CBCP_L(CBCP_Config_Capability_Bucket, struct CBCP_Config_Capability_Bucket, cbcp_config_capability_bucket)\
/* End CBCP_REFLIST_TYPE_LIST */

#define CBCP_BUCKET_ARRAY_TYPE_LIST\
	CBCP_L(CBCP_Config_Group, CBCP_Config_Group, 7, cbcp_config_group)\
	CBCP_L(CBCP_Config_Hash_Entry, CBCP_Config_Hash_Entry, 9, cbcp_config_hash_entry)\
	CBCP_L(CBCP_Config_Host, CBCP_Config_Host, 7, cbcp_config_host)\
	CBCP_L(CBCP_Config_Interface, CBCP_Config_Interface, 7, cbcp_config_interface)\
	CBCP_L(CBCP_Config_Interface_Instance, CBCP_Config_Interface_Instance, 7, cbcp_config_interface_instance)\
	CBCP_L(CBCP_Config_License, CBCP_Config_License, 7, cbcp_config_license)\
	CBCP_L(CBCP_Config_Net_Address, CBCP_Config_Net_Address, 9, cbcp_config_net_address)\
	CBCP_L(CBCP_Config_String, CBCP_Config_String, 9, cbcp_config_string)\
	CBCP_L(CBCP_Config_Capability, CBCP_Capability, 9, cbcp_config_capability)\
/* End CBCP_BUCKET_ARRAY_TYPE_LIST */



typedef struct CBCP_Config_Reflist {
	unsigned int count;
	unsigned int capacity;
	void **pointers;
} CBCP_Config_Reflist;


// NOTE(jakob): CAUTION!!! The pointer `pointers` can change do to realloc.
// This implies that pointers to any particular element can become invalid
// and cause a segmentation fault.
#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, FUNCTION_NAME_PREFIX)\
typedef struct ARRAY_TYPE##_Reflist {\
	unsigned int count;\
	ELEMENT_TYPE **pointers;\
} ARRAY_TYPE##_Reflist;

CBCP_REFLIST_TYPE_LIST

typedef struct CBCP_Config_String {
	char *chars;
	unsigned int length;
} CBCP_Config_String;

typedef struct CBCP_Config_String_Intern {
	CBCP_Config_String *string;
} CBCP_Config_String_Intern;

typedef struct CBCP_Config_Net_Address {
	CBCP_Config_String_Intern protocol;
	CBCP_Config_String_Intern address;
} CBCP_Config_Net_Address;

typedef struct CBCP_Config_Host {
	CBCP_Config_String_Intern name;
	CBCP_Config_Group_Reflist groups;
	CBCP_Config_Net_Address_Reflist net_addresses;
	CBCP_Config_Neighbor_Info_Reflist neighbor_infos;
	CBCP_Config_Interface_Instance_Reflist local_interfaces;
	CBCP_Config_Interface_Subset_Reflist remote_interfaces;

	RSA *rsa_key;
} CBCP_Config_Host;

typedef struct CBCP_Config_Group {
	CBCP_Config_String_Intern name;
	CBCP_Config_Host_Reflist hosts;
} CBCP_Config_Group;

typedef struct CBCP_Config_Host_Or_Group {
	int is_group;
	union {
		CBCP_Config_Host *host;
		CBCP_Config_Group *group;
	} u;
} CBCP_Config_Host_Or_Group;

typedef struct CBCP_Config_Neighbor_Info {
	CBCP_Config_Host *neighbor;
	CBCP_Config_License_Reflist licenses;
} CBCP_Config_Neighbor_Info;

typedef struct CBCP_Config_Interface {
	CBCP_Config_String_Intern name;
	unsigned int command_count;
	CBCP_Config_String_Intern commands[CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE];
} CBCP_Config_Interface;

// TODO(jakob): rename CBCP_Config_Interface_Subset to something like CBCP_Config_Subinterface
typedef struct CBCP_Config_Interface_Subset {
	CBCP_Config_Interface *interface;
	CBCP_Capability capability;
} CBCP_Config_Interface_Subset;

typedef struct CBCP_Config_Interface_Instance {
	CBCP_Config_Interface *interface;
	CBCP_Capability_Secret master_secret; // Capability_Password
	CBCP_Config_Capability_Reflist capabilities;
} CBCP_Config_Interface_Instance;

typedef struct CBCP_Config_License {
	CBCP_Config_Interface *interface;
	CBCP_Config_Group *client_group;
	CBCP_Capability_Reduction_Field reduction_field;
	CBCP_Capability_Secret secret;
	uint32_t capability_id;
} CBCP_Config_License;

typedef struct CBCP_Config_Host_Iterator {
	CBCP_Config_Host_Or_Group host_or_group;
	unsigned int index;
} CBCP_Config_Host_Iterator;



#define CBCP_CONFIG_HASH_ENTRY_NONE ((CBCP_Config_Hash_Entry *)NULL)
#define CBCP_CONFIG_HASH_ENTRY_DELETED ((CBCP_Config_Hash_Entry *)1)
#define CBCP_CONFIG_INITIAL_HASH_TABLE_SIZE (1 << 2)

typedef struct CBCP_Config_Hash_Entry {
	void *key;
	void *data;
} CBCP_Config_Hash_Entry;

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
typedef struct ARRAY_TYPE##_Bucket {\
	ELEMENT_TYPE elements[1UL << ELEMENT_INDEX_BITS];\
} ARRAY_TYPE##_Bucket;

CBCP_BUCKET_ARRAY_TYPE_LIST

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
typedef struct ARRAY_TYPE##_Bucket_Array {\
	unsigned int count;\
	ARRAY_TYPE##_Bucket_Reflist buckets; \
} ARRAY_TYPE##_Bucket_Array;

CBCP_BUCKET_ARRAY_TYPE_LIST

typedef struct CBCP_Config_Bucket_Array {
	unsigned int count;
	CBCP_Config_Reflist buckets;
} CBCP_Config_Bucket_Array;

typedef struct CBCP_Config_Hash_Table {
	// NOTE(jakob): This is a dynamic hash table offering pointer to pointer
	// mapping. It uses open addressing with double hashing for probing. The
	// table size is always a power of 2 and the second hash function always
	// returns an odd value. Thus, the table size and the probing stride are
	// relatively prime ensuring that the probe sequence is a permutation of
	// all the table indices  0,1,...,`capacity` - 1.

	uint32_t count_limit;
	uint32_t capacity;

	// NOTE(jakob): The `entries` array owns the memory for the entries, the
	// `table` just points to it.
	CBCP_Config_Hash_Entry_Bucket_Array entries;

	CBCP_Config_Hash_Entry **table; // NOTE(jakob): Warning! Gets realloced
} CBCP_Config_Hash_Table;

typedef struct CBCP_Config_String_Hash_Set {
	// NOTE(jakob): This is a dynamic string hash set. It uses open addressing
	// with double hashing for probing. The table size is always a power of 2
	// and the second hash function always returns an odd value. Thus, the
	// table size and the probing stride are relatively prime ensuring that the
	// probe sequence is a permutation of all the table indices
	// 0,1,...,`capacity` - 1.

	uint32_t count_limit;
	uint32_t capacity;

	// NOTE(jakob): The `entries` array owns the memory for the entries, the
	// `table` just points to it.
	CBCP_Config_String_Bucket_Array entries;

	CBCP_Config_String **table; // NOTE(jakob): Warning! Gets realloced
} CBCP_Config_String_Hash_Set;

typedef struct CBCP_Config {
	CBCP_Config_Host_Bucket_Array hosts;
	CBCP_Config_Group_Bucket_Array groups;
	CBCP_Config_Interface_Bucket_Array interfaces;
	CBCP_Config_License_Bucket_Array licenses;
	CBCP_Config_Interface_Instance_Bucket_Array interface_instances;
	CBCP_Config_Net_Address_Bucket_Array net_addresses;
	CBCP_Config_Capability_Bucket_Array access_entries;

	CBCP_Config_Hash_Table hosts_and_groups_by_name;
	CBCP_Config_Hash_Table interfaces_by_name;
	CBCP_Config_String_Hash_Set string_interns;

} CBCP_Config;

typedef struct CBCP_Config_Parse_State {
	char *base;
	char *at;
	char *end;
} CBCP_Config_Parse_State;


#if defined(CBCP_CONFIG_NO_LOGGING)
#define cbcp_config_log(...) ((void)0)
#define cbcp_config_parse_log(...) ((void)0)
#define cbcp_config_log_set_prefix(...) ((void)0)
#else
static const char *global_config_file_path;
static const char *global_log_prefix = "";
void cbcp_config_log(const char *format, ...);
void cbcp_config_parse_log(char *base, char *log_at, const char *format, ...);
void cbcp_config_log_set_prefix(const char *prefix);
#endif


static CBCP_Config_Status
cbcp_config_parse_eat_whitespace(CBCP_Config_Parse_State *parse);

static CBCP_Config_Status
cbcp_config_parse_eat_seperator_inline(CBCP_Config_Parse_State *parse, char seperator_char);

static CBCP_Config_Status
cbcp_config_parse_eat_seperator(CBCP_Config_Parse_State *parse, char seperator_char);

static char
cbcp_config_case_convert_char_lower(char c);

static CBCP_Config_Status
cbcp_config_parse_eat_substring_case_insensitive(
	CBCP_Config_Parse_State *parse,
	const char *needle);

static CBCP_Config_Status
cbcp_config_parse_get_positive_decimal_integer(CBCP_Config_Parse_State *parse, int *result_out);

static CBCP_Config_Status
cbcp_config_parse_get_version(
	CBCP_Config_Parse_State *parse,
	int *major_version,
	int *minor_version);

static CBCP_Config_Status
cbcp_config_parse_eat_name(CBCP_Config_Parse_State *parse);

static CBCP_Config_Status
cbcp_config_parse_eat_address_string(CBCP_Config_Parse_State *parse);

static uint32_t
cbcp_config_hash_pointer(
	void *pointer);

static uint32_t
cbcp_config_hash_u32_to_odd(
	uint32_t index);

// Hash table

static void
cbcp_config_hash_table_init(
	CBCP_Config_Hash_Table *hash_table,
	uint32_t initial_minimum_capacity);

static CBCP_Config_Status
cbcp_config_hash_table_get_slot(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	CBCP_Config_Hash_Entry ***out_slot);

static CBCP_Config_Status
cbcp_config_hash_table_grow(
	CBCP_Config_Hash_Table *hash_table);

static CBCP_Config_Status
cbcp_config_hash_table_insert(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	void *data);

static bool
cbcp_config_hash_table_search(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	void **out_data);

// / Hash table

// String hash set

static void
cbcp_config_string_hash_set_init(
	CBCP_Config_String_Hash_Set *hash_set,
	uint32_t initial_minimum_capacity);

static CBCP_Config_Status
cbcp_config_string_hash_set_get_slot(
	CBCP_Config_String_Hash_Set *hash_table,
	CBCP_Config_String key,
	CBCP_Config_String ***out_slot);

static CBCP_Config_Status
cbcp_config_string_hash_set_grow(
	CBCP_Config_String_Hash_Set *hash_set);

static CBCP_Config_Status
cbcp_config_string_hash_set_insert(
	CBCP_Config_String_Hash_Set *hash_set,
	CBCP_Config_String key,
	CBCP_Config_String **out_key_in_set);

static bool
cbcp_config_string_hash_set_contains(
	CBCP_Config_String_Hash_Set *hash_set,
	CBCP_Config_String key);

// / String hash set

static char *
cbcp_config_copy_string(char *source, unsigned int length);

static CBCP_Config_String_Intern
cbcp_config_intern_from_string(CBCP_Config_String_Hash_Set *interns, char *string, unsigned int string_length);

static CBCP_Config_String
cbcp_config_string_from_intern(CBCP_Config_String_Intern intern);

static bool
cbcp_config_string_interns_are_equal(CBCP_Config_String_Intern a, CBCP_Config_String_Intern b);

static bool
cbcp_config_parse_has_next_statement(CBCP_Config_Parse_State *parse);

static CBCP_Config_Status
cbcp_config_parse_get_name(CBCP_Config_Parse_State *parse, unsigned int *out_name_length, int *out_name_is_group);

#if 0
// TODO(jakob): Hash table
static CBCP_Config_Status
cbcp_config_entity_id_from_name(
	CBCP_Config_Host_Bucket_Array *entities,
	CBCP_Config_String_Intern name,
	CBCP_Config_Entity_Id *out_entity_id);
#endif

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Get_Capability_Name_Status,
	CBCP_Config_Parse_Get_Capability_Name_Status__OK_DONE = 0,
	CBCP_Config_Parse_Get_Capability_Name_Status__OK_NEXT = 1,
	CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NO_NAME = 2,
	CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_GROUP_NAME = 3,
	CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NAME_TOO_LONG = 4,
);

static CBCP_Config_Parse_Get_Capability_Name_Status
cbcp_config_parse_get_capability_name(
	CBCP_Config_Parse_State *parse,
	CBCP_Config_String_Hash_Set *interns,
	CBCP_Config_String_Intern *out_capability_name_intern);

static CBCP_Config_Status
cbcp_config_reflist_add(
	CBCP_Config_Reflist *array,
	void *element,
	bool no_duplicates);

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, FUNCTION_NAME_PREFIX)\
static CBCP_Config_Status FUNCTION_NAME_PREFIX##_reflist_add(ARRAY_TYPE##_Reflist *array, ELEMENT_TYPE *element, bool no_duplicates);

CBCP_REFLIST_TYPE_LIST

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
static ELEMENT_TYPE *FUNCTION_NAME_PREFIX##_bucket_array_new(ARRAY_TYPE##_Bucket_Array *array);

CBCP_BUCKET_ARRAY_TYPE_LIST

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
static ELEMENT_TYPE *\
FUNCTION_NAME_PREFIX##_bucket_array_get(ARRAY_TYPE##_Bucket_Array *array, unsigned int index);

CBCP_BUCKET_ARRAY_TYPE_LIST

static CBCP_Config_Host_Iterator
cbcp_config_host_iterator(CBCP_Config_Host_Or_Group host_or_group);

static bool
cbcp_config_host_iterator_next(
	CBCP_Config_Host_Iterator *iterator,
	CBCP_Config_Host **out_next_host);

static CBCP_Config_Status
cbcp_config_add_licence_edges(
	CBCP_Config_Host_Or_Group server,
	CBCP_Config_Host_Or_Group client,
	CBCP_Config_Interface_Subset interface_subset,
	CBCP_Config_License_Bucket_Array *licenses);

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Host_Definitions_Status,
	CBCP_Config_Parse_Host_Definitions_Status__SUCCESS = 0,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_INVALID_HOST_NAME = 2,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_INVALID_HOST_ADDRESS = 3,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_HOST_REDEFINITION = 4,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_INVALID_PROTOCOL_NAME = 5,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_MISSING_SEPERATOR = 6,
	CBCP_Config_Parse_Host_Definitions_Status__ERROR_RSA_GENERATION = 7,
);

static CBCP_Config_Parse_Host_Definitions_Status
cbcp_config_parse_host_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config);


CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Group_Definitions_Status,
	CBCP_Config_Parse_Group_Definitions_Status__SUCCESS = 0,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_INVALID_GROUP_NAME = 2,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_GROUP_REDEFINITION = 3,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_INVALID_HOST_NAME = 4,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_REPEATED_HOST = 5,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_UNDEFINED_HOST = 6,
	CBCP_Config_Parse_Group_Definitions_Status__ERROR_MISSING_SEPERATOR = 7,
);

static CBCP_Config_Parse_Group_Definitions_Status
cbcp_config_parse_group_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config);


CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Interface_Definitions_Status,
	CBCP_Config_Parse_Interface_Definitions_Status__SUCCESS = 0,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_MISSING_SEPERATOR = 2,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_INVALID_INTERFACE_NAME = 3,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_INTERFACE_REDEFINITION = 4,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_INVALID_CAPABILITY_NAME = 5,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_EXCEEDED_CAPABILITY_MAX = 6,
	CBCP_Config_Parse_Interface_Definitions_Status__ERROR_CAPABILITY_REDEFINITION = 7,
);

static CBCP_Config_Parse_Interface_Definitions_Status
cbcp_config_parse_interface_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config);

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Implements_Status,
	CBCP_Config_Parse_Implements_Status__SUCCESS = 0,
	CBCP_Config_Parse_Implements_Status__ERROR_MISSING_SEPERATOR = 2,
	CBCP_Config_Parse_Implements_Status__ERROR_INVALID_SERVER_NAME = 3,
	CBCP_Config_Parse_Implements_Status__ERROR_INVALID_INTERFACE_NAME = 4,
	CBCP_Config_Parse_Implements_Status__ERROR_UNDEFINED_SERVER = 5,
	CBCP_Config_Parse_Implements_Status__ERROR_UNDEFINED_INTERFACE = 6,
	CBCP_Config_Parse_Implements_Status__ERROR_REPEATED_SERVER = 7,
	CBCP_Config_Parse_Implements_Status__ERROR_REPEATED_INTERFACE = 8,
);

static CBCP_Config_Parse_Implements_Status
cbcp_config_parse_implements(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config);

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_License_Definitions_Status,
	CBCP_Config_Parse_License_Definitions_Status__SUCCESS = 0,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_INVALID_CLIENT_NAME = 2,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_UNDEFINED_CLIENT = 3,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_MISSING_SEPERATOR = 4,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_INVALID_SERVER_NAME = 5,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_UNDEFINED_SERVER = 6,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_INVALID_INTERFACE_NAME = 7,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_UNDEFINED_INTERFACE = 8,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_INVALID_CAPABILITY_NAME = 9,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_UNDEFINED_CAPABILITY = 10,
	CBCP_Config_Parse_License_Definitions_Status__ERROR_ADDING_EDGES = 11,
);

static CBCP_Config_Parse_License_Definitions_Status
cbcp_config_parse_license_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config);

CBCP_CONFIG_DEFINE_STATUS_TYPE(CBCP_Config_Parse_Status,
	CBCP_Config_Parse_Status__SUCCESS = 0,
	CBCP_Config_Parse_Status__ERROR_MISSING_HEADER = 1,
	CBCP_Config_Parse_Status__ERROR_VERSION_INVALID = 2,
	CBCP_Config_Parse_Status__ERROR_MISSING_SEPERATOR = 3,
	CBCP_Config_Parse_Status__ERROR_MISSING_HOSTS_SECTION = 4,
	CBCP_Config_Parse_Status__ERROR_INVALID_HOSTS_SECTION = 5,
	CBCP_Config_Parse_Status__ERROR_INVALID_GROUPS_SECTION = 6,
	CBCP_Config_Parse_Status__ERROR_MISSING_INTERFACES_SECTION = 7,
	CBCP_Config_Parse_Status__ERROR_INVALID_INTERFACES_SECTION = 8,
	CBCP_Config_Parse_Status__ERROR_MISSING_IMPLEMENTS_SECTION = 9,
	CBCP_Config_Parse_Status__ERROR_INVALID_IMPLEMENTS_SECTION = 10,
	CBCP_Config_Parse_Status__ERROR_MISSING_LICENSES_SECTION = 11,
	CBCP_Config_Parse_Status__ERROR_INVALID_LICENSES_SECTION = 12,
);

static CBCP_Config_Parse_Status
cbcp_config_parse(char *config_file_contents, unsigned int config_file_length, CBCP_Config *config);

#include <stdio.h>
#include <malloc.h>

static int read_file(const char *file_path, char **file_contents_out, unsigned int *file_length_out);

static void
cbcp_config_string_from_capability_vector(uint64_t capability_vector, char buffer[CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE]);

CBCP_Config_Status
cbcp_config(const char *config_file_path, const char *output_directory_path);

#ifdef __cplusplus
}
#endif

#endif
