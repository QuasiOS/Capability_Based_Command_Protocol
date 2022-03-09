#include "cbcp_config.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#if !defined(CBCP_ALLOCATE) || !defined(CBCP_REALLOCATE)
#include <malloc.h>
#if !defined(CBCP_ALLOCATE)
#define CBCP_ALLOCATE(size) malloc(size)
#endif
#if !defined(CBCP_REALLOCATE)
#define CBCP_REALLOCATE(pointer, new_size) realloc((pointer), (new_size))
#endif
#endif

#ifdef __cplusplus
extern "C" {
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

//
// END CBCP_CAPABILITIES
//


#if defined(CBCP_CONFIG_NO_LOGGING)
#define cbcp_config_log(...) ((void)0)
#define cbcp_config_parse_log(...) ((void)0)
#define cbcp_config_log_set_prefix(...) ((void)0)
#else

#include <stdarg.h>

static CBCP_Config_Status
cbcp_db_generate_RSA_key(CBCP_Config_Host *host, int key_size_bits) // char *hostname, RSA *out_rsa_key, int key_size_bits)
{
	int            return_value = 0;
	BIGNUM        *big_number   = NULL;
	unsigned long  e = RSA_F4;

	big_number = BN_new();
	return_value = BN_set_word(big_number, e);
	if(return_value == 1)
	{
		host->rsa_key = RSA_new();
		return_value = RSA_generate_key_ex(host->rsa_key, key_size_bits, big_number, NULL);
	}

	BN_free(big_number);

	if (return_value == 1)
	{
		return CBCP_CONFIG_STATUS_SUCCESS;
	}
	else
	{
		return CBCP_CONFIG_STATUS_ERROR;
	}

}

static CBCP_Config_Status
cbcp_config_reflist_add(
	CBCP_Config_Reflist *array,
	void *element,
	bool no_duplicates)
{
	if (no_duplicates) {
		// Early out if element was already added
		for (unsigned int i = 0; i < array->count; ++i) {
			if (array->pointers[i] == element) {
				return CBCP_CONFIG_STATUS_SUCCESS;
			}
		}
	}

	if (array->count + 1 > array->capacity) {

		// Capacity sequence: 0,8,16,32,56,88,136,208,320,488,736,1112,...
		unsigned int new_capacity = (array->capacity + (array->capacity >> 1) + 8) & ~7;

		void *new_pointer = CBCP_REALLOCATE(
			array->pointers,
			new_capacity * sizeof(*array->pointers));

		if (new_pointer) {
			array->pointers = (void **)new_pointer;

			// Zero added memory
			unsigned int added_element_count =
				new_capacity - array->capacity;
			unsigned int added_memory_size =
				added_element_count * sizeof(*array->pointers);
			memset(&array->pointers[array->capacity], 0, added_memory_size);

			array->capacity = new_capacity;
		}
		else {
			cbcp_config_log("Could not allocate enough memory.\n");
			return CBCP_CONFIG_STATUS_ERROR;
		}
	}

	array->pointers[array->count++] = element;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, FUNCTION_NAME_PREFIX)\
static CBCP_Config_Status FUNCTION_NAME_PREFIX##_reflist_add(ARRAY_TYPE##_Reflist *array, ELEMENT_TYPE *element, bool no_duplicates) {\
	return cbcp_config_reflist_add((CBCP_Config_Reflist *)array, (void *)element, no_duplicates); \
}

CBCP_REFLIST_TYPE_LIST

void cbcp_config_log(const char *format, ...) {
	fflush(stderr);
	fprintf(stderr, "%s", global_log_prefix);
	va_list argument_list;
	va_start(argument_list, format);
	vfprintf(stderr, format, argument_list);
	va_end(argument_list);
	fflush(stderr);
}

void cbcp_config_parse_log(char *base, char *log_at, const char *format, ...) {

	unsigned int row = 1;
	unsigned int column = 0;

	while (log_at >= base && (*log_at != '\n')) {
		++column;
		--log_at;
	}

	while (log_at >= base) {
		if (*log_at == '\n') {
			++row;
		}
		--log_at;
	}

	fflush(stderr);
	fprintf(stderr, "%s:%d:%d: %s", global_config_file_path, row, column, global_log_prefix);
	va_list argument_list;
	va_start(argument_list, format);
	vfprintf(stderr, format, argument_list);
	va_end(argument_list);
	fflush(stderr);
}

void cbcp_config_log_set_prefix(const char *prefix) {
	global_log_prefix = prefix;
}

#endif


static CBCP_Config_Status
cbcp_config_parse_eat_whitespace(CBCP_Config_Parse_State *parse) {

	char *at = parse->at;

	while (*at <= ' ' && at < parse->end) ++at;

	if (at == parse->at) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_parse_eat_seperator_inline(CBCP_Config_Parse_State *parse, char seperator_char) {

	char *at = parse->at;

	// Eat leading whitespace
	while (at < parse->end && *at <= ' ' && *at != '\n' && *at != seperator_char) ++at;

	if (at < parse->end && *at == seperator_char) {

		// Eat seperator_char
		++at;

		// Eat trailing whitespace
		while (at < parse->end && *at <= ' ' && *at != '\n') ++at;
	}
	else {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_parse_eat_seperator(CBCP_Config_Parse_State *parse, char seperator_char) {

	char *at = parse->at;

	// Eat leading whitespace
	while (at < parse->end && *at <= ' ' && *at != seperator_char) ++at;

	if (at < parse->end && *at == seperator_char) {

		// Eat seperator_char
		++at;

		// Eat trailing whitespace
		while (at < parse->end && *at <= ' ') ++at;
	}
	else {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static char
cbcp_config_case_convert_char_lower(char c) {
	if (c >= 'A' && c <= 'Z') {
		c += ('a' - 'A');
	}

	return c;
}

static CBCP_Config_Status
cbcp_config_parse_eat_substring_case_insensitive(
	CBCP_Config_Parse_State *parse,
	const char *needle)
{

	char *at = parse->at;
	char *needle_at = (char *)needle;


	while (at < parse->end) {
		char at_char = *at;
		char needle_at_char = *needle_at;

		if (needle_at_char == '\0') {
			parse->at = at;
			return CBCP_CONFIG_STATUS_SUCCESS;
		}

		at_char = cbcp_config_case_convert_char_lower(at_char);
		needle_at_char = cbcp_config_case_convert_char_lower(needle_at_char);

		if (needle_at_char != at_char) {
			return CBCP_CONFIG_STATUS_ERROR;
		}

		++at;
		++needle_at;
	}

	return CBCP_CONFIG_STATUS_ERROR;
}

static CBCP_Config_Status
cbcp_config_parse_get_positive_decimal_integer(CBCP_Config_Parse_State *parse, int *result_out) {

	int result = 0;

	char *at = parse->at;

	char digit = *at - '0';

	if (digit >= 0 && digit <= 9) {
		result = digit;
		++at;
	}
	else {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	while (at < parse->end) {
		digit = *at - '0';
		if (digit >= 0 && digit <= 9) {
			result *= 10;
			result += digit;
			++at;
		}
		else {
			break;
		}
	}

	parse->at = at;

	*result_out = result;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_parse_get_version(
	CBCP_Config_Parse_State *parse,
	int *major_version,
	int *minor_version)
{
	CBCP_Config_Parse_State parse_copy = *parse;

	if (cbcp_config_parse_get_positive_decimal_integer(&parse_copy, major_version).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	if (*parse_copy.at != '.' || parse_copy.at >= parse_copy.end) {
		return CBCP_CONFIG_STATUS_ERROR;
	}
	++parse_copy.at;

	if (cbcp_config_parse_get_positive_decimal_integer(&parse_copy, minor_version).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_parse_eat_name(CBCP_Config_Parse_State *parse) {

	char *at = parse->at;

	int trailing_space_count = 0;

	for (; at < parse->end; ++at) {

		char c = *at;

		if (
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			(c == '-' || c == '_' || c == '+' || c == '.' || c == '/')
		) {
			trailing_space_count = 0;
			continue;
		}
		else if (c == ' ') {
			++trailing_space_count;
			continue;
		}
		else {
			break;
		}
	}

	at -= trailing_space_count;

	if (parse->at == at) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_parse_eat_address_string(CBCP_Config_Parse_State *parse) {
	char *at = parse->at;

	while (*at != CBCP_CONFIG_FIELD_SEPERATOR && *at != '\n' && at < parse->end) ++at;

	if (parse->at == at) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	parse->at = at;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static char *
cbcp_config_copy_string(char *source, unsigned int length) {

	char *copy = (char *)CBCP_ALLOCATE(length+1);

	memcpy(copy, source, length);

	copy[length] = '\0';

	return copy;
}

static CBCP_Config_String_Intern
cbcp_config_intern_from_string(CBCP_Config_String_Hash_Set *interns, char *chars, unsigned int length) {

	assert(chars);

	CBCP_Config_String_Intern result;
	result.string = NULL;

	CBCP_Config_String string;
	string.chars = chars;
	string.length = length;

	CBCP_Config_String *interned_string;

	if (cbcp_config_string_hash_set_insert(interns, string, &interned_string).error) {
		assert(!"Should not fail");
	}

	assert(interned_string);

	result.string = interned_string;

	return result;
}

static CBCP_Config_String
cbcp_config_string_from_intern(CBCP_Config_String_Intern intern) {
	return *intern.string;
}

static bool
cbcp_config_string_interns_are_equal(CBCP_Config_String_Intern a, CBCP_Config_String_Intern b) {
	return a.string == b.string;
}

static bool
cbcp_config_parse_has_next_statement(CBCP_Config_Parse_State *parse) {

	cbcp_config_parse_eat_whitespace(parse);

	if (parse->at >= parse->end || *parse->at == '!') {
		return false;
	}

	return true;
}

static CBCP_Config_Status
cbcp_config_parse_get_name(CBCP_Config_Parse_State *parse, unsigned int *out_name_length, int *out_name_is_group) {

	CBCP_Config_Parse_State parse_copy = *parse;

	char *name_start = parse_copy.at;

	int is_group = 0;

	if (*parse_copy.at == '@') {
		is_group = 1;
		++parse_copy.at;
	}

	if (cbcp_config_parse_eat_name(&parse_copy).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	unsigned int name_length = parse_copy.at - name_start;

	parse->at = parse_copy.at;

	*out_name_length = name_length;
	*out_name_is_group = is_group;
	return CBCP_CONFIG_STATUS_SUCCESS;
}


static void *
cbcp_config_bucket_array_get(
	CBCP_Config_Bucket_Array *array,
	unsigned int index,
	unsigned int element_size,
	unsigned int bucket_index_bit_offset)
{
	assert(index < array->count);

	unsigned int bucket_index = index >> bucket_index_bit_offset;
	unsigned int element_index = index & ((1UL << bucket_index_bit_offset)-1);

	void *void_bucket = array->buckets.pointers[bucket_index];
	void *result = (void *)(((char *)void_bucket) + element_index*element_size);

	return result;
}

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
static ELEMENT_TYPE *\
FUNCTION_NAME_PREFIX##_bucket_array_get(ARRAY_TYPE##_Bucket_Array *array, unsigned int index) {\
	ELEMENT_TYPE *result = (ELEMENT_TYPE *)cbcp_config_bucket_array_get((CBCP_Config_Bucket_Array *)array, index, sizeof(*result), ELEMENT_INDEX_BITS);\
	return result;\
}

CBCP_BUCKET_ARRAY_TYPE_LIST

static CBCP_Config_Status
cbcp_config_host_or_group_from_name(
	CBCP_Config_Hash_Table *hosts_and_groups_by_name,
	CBCP_Config_String_Intern name,
	CBCP_Config_Host_Or_Group *host_or_group)
{
	void *host_or_group_pointer;

	if (!cbcp_config_hash_table_search(hosts_and_groups_by_name, (void *)name.string, &host_or_group_pointer)) {
		// Not found
		return CBCP_CONFIG_STATUS_ERROR;
	}

	if (host_or_group->is_group) {
		host_or_group->u.group = (CBCP_Config_Group *)host_or_group_pointer;
	}
	else {
		host_or_group->u.host = (CBCP_Config_Host *)host_or_group_pointer;
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}

#if 0
static CBCP_Config_Status
cbcp_config_entity_id_from_name(
	CBCP_Config_Host_Bucket_Array *hosts,
	CBCP_Config_String_Intern name,
	CBCP_Config_Entity_Id *out_entity_id)
{
	CBCP_Config_Host *host;

	if (cbcp_config_host_from_name(hosts, name, &host).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	*out_entity_id = host->id;
	return CBCP_CONFIG_STATUS_SUCCESS;
}
#endif

static CBCP_Config_Parse_Get_Capability_Name_Status
cbcp_config_parse_get_capability_name(
	CBCP_Config_Parse_State *parse,
	CBCP_Config_String_Hash_Set *interns,
	CBCP_Config_String_Intern *out_capability_name_intern)
{

	CBCP_Config_Parse_State parse_copy = *parse;

	if (parse_copy.at >= parse_copy.end || *parse_copy.at == '\n') {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, OK_DONE);
	}

	char *capability_name = parse_copy.at;
	unsigned int capability_name_length;
	int is_group;

	if (cbcp_config_parse_get_name(&parse_copy, &capability_name_length, &is_group).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, ERROR_NO_NAME);
	}

	if (is_group) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, ERROR_GROUP_NAME);
	}

	if (capability_name_length > CBCP_CONFIG_CAPABILITY_NAME_LENGTH_LIMIT) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, ERROR_NAME_TOO_LONG);
	}


	*out_capability_name_intern =
		cbcp_config_intern_from_string(
			interns,
			capability_name,
			capability_name_length);

	parse->at = parse_copy.at;

	if (cbcp_config_parse_eat_seperator_inline(parse, CBCP_CONFIG_SUBFIELD_SEPERATOR).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, OK_DONE);
	}

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Get_Capability_Name_Status, OK_NEXT);
}

static void *
cbcp_config_bucket_array_new(
	CBCP_Config_Bucket_Array *array,
	unsigned int element_size,
	unsigned int bucket_index_bit_offset)
{
	unsigned int index = array->count;
	unsigned int bucket_element_count = 1UL << bucket_index_bit_offset;
	unsigned int bucket_index = index >> bucket_index_bit_offset;
	unsigned int element_index = index & (bucket_element_count-1);

	void *void_bucket;

	if (bucket_index >= array->buckets.count) {
		void_bucket = CBCP_ALLOCATE(bucket_element_count*element_size);
		assert(void_bucket);
		cbcp_config_reflist_add(&array->buckets, void_bucket, false);
	}
	else {
		void_bucket = array->buckets.pointers[bucket_index];
	}

	void *result = (void *)(((char *)void_bucket) + element_index*element_size);

	++array->count;

	return result;
}

#undef CBCP_L
#define CBCP_L(ARRAY_TYPE, ELEMENT_TYPE, ELEMENT_INDEX_BITS, FUNCTION_NAME_PREFIX)\
static ELEMENT_TYPE *FUNCTION_NAME_PREFIX##_bucket_array_new(ARRAY_TYPE##_Bucket_Array *array) {\
	ELEMENT_TYPE *result = (ELEMENT_TYPE *)cbcp_config_bucket_array_new((CBCP_Config_Bucket_Array *)array, sizeof(*result), ELEMENT_INDEX_BITS);\
	*result = CBCP_ZERO_LITERAL(ELEMENT_TYPE);\
	return result;\
}

CBCP_BUCKET_ARRAY_TYPE_LIST

static uint32_t cbcp_config_u32_next_power_of_2(uint32_t x) {
	// TODO(jakob): Compiler intrinsics for "count leading zeros" instruction
	--x;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	++x;
	return x;
}

static void
cbcp_config_hash_table_init(
	CBCP_Config_Hash_Table *hash_table,
	uint32_t initial_minimum_capacity)
{
	assert(hash_table->table == NULL);

	uint32_t initial_capacity = 2;

	if (initial_minimum_capacity > 2) {
		initial_capacity = cbcp_config_u32_next_power_of_2(initial_minimum_capacity);
	}

	*hash_table = CBCP_ZERO_LITERAL(CBCP_Config_Hash_Table);

	hash_table->capacity = initial_capacity;
	hash_table->count_limit = hash_table->capacity >> 1;

	size_t memory_size = hash_table->capacity*sizeof(*hash_table->table);

	hash_table->table = (
		(CBCP_Config_Hash_Entry **)
		CBCP_ALLOCATE(memory_size));

	memset(hash_table->table, 0, memory_size);
}


static uint32_t cbcp_config_hash_pointer(void *pointer) {

	uint64_t v = (uint64_t)(uintptr_t)pointer;
	// TODO(jakob): Conduct tests of hash distribution
	v = (~v) + (v << 18); // v = (v << 18) - v - 1;
	v ^= (v >> 31);
	v *= 21; // v = (v + (v << 2)) + (v << 4);
	v ^= (v >> 11);
	v += (v << 6);
	v ^= (v >> 22);
	return (uint32_t) v;
}

static uint32_t cbcp_config_hash_string(CBCP_Config_String key_string)
{
	// NOTE(jakob): This is an implementation of the Murmur3 hash function,
	// derived from an implementation found on the wikipedia page for murmur hash

	size_t length = key_string.length;
	char *key_bytes = key_string.chars;

	// TODO(jakob): randomized seed to prevent Hash denial of service?
	uint32_t hash = 0x369d9bb5;

	if (length > 3)
	{
		uint32_t* key_4_byte_chunk = (uint32_t*) key_bytes;
		size_t num_whole_chunks = length >> 2;

		do
		{
			uint32_t k = *key_4_byte_chunk++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			hash ^= k;
			hash = (hash << 13) | (hash >> 19);
			hash = (hash * 5) + 0xe6546b64;
		} while (--num_whole_chunks);

		key_bytes = (char*) key_4_byte_chunk;
	}

	size_t residual_length = length & 3;

	if (residual_length != 0)
	{
		// Length was not divisible by 4
		uint32_t k = 0;
		key_bytes = &key_bytes[residual_length - 1];
		do
		{
			k <<= 8;
			k |= *key_bytes--;
		} while (--residual_length);

		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		hash ^= k;
	}

	hash ^= length;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash;
}


static uint32_t cbcp_config_hash_u32_to_odd(uint32_t x) {
	// NOTE(jakob): from https://github.com/skeeto/hash-prospector
	x ^= x >> 16;
	x *= 0x7feb352d;
	x ^= x >> 15;
	x *= 0x846ca68b;
	x ^= x >> 16;

	x |= 1; // Make hash value always odd

	return x;
}

static CBCP_Config_Status
cbcp_config_hash_table_get_slot(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	CBCP_Config_Hash_Entry ***out_slot)
{
	uint32_t hash = cbcp_config_hash_pointer(key);
	uint32_t index = hash & (hash_table->capacity - 1); // capacity must be a power of 2
	uint32_t initial_index = index;

	uint32_t stride = cbcp_config_hash_u32_to_odd(index);

	CBCP_Config_Hash_Entry **slot = &hash_table->table[index];


	while (*slot > CBCP_CONFIG_HASH_ENTRY_DELETED && (*slot)->key != key) {
		index += stride;
		index &= (hash_table->capacity - 1); // capacity must be a power of 2

		if (index == initial_index) {
			return CBCP_CONFIG_STATUS_ERROR;
		}

		slot = &hash_table->table[index];
	}

	*out_slot = slot;

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_hash_table_grow(
	CBCP_Config_Hash_Table *hash_table)
{
	assert(hash_table->entries.count == hash_table->count_limit);

	// Double table size
	unsigned int new_capacity = hash_table->capacity << 1;

	if (new_capacity == 0) {
		new_capacity = 16;
	}

	unsigned int new_count_limit = new_capacity >> 1;
	assert(new_count_limit != 0);

	size_t memory_size = new_capacity * sizeof(*hash_table->table);

	CBCP_Config_Hash_Entry **new_table =
		(CBCP_Config_Hash_Entry **)CBCP_REALLOCATE(hash_table->table, memory_size);

	if (new_table == NULL) {
		return CBCP_CONFIG_STATUS_ERROR;
	}


	hash_table->count_limit = new_count_limit;
	hash_table->capacity = new_capacity;
	hash_table->table = new_table;

	memset(hash_table->table, 0, memory_size);


	for (unsigned int i = 0; i < hash_table->entries.count; ++i) {
		CBCP_Config_Hash_Entry *entry =
			cbcp_config_hash_entry_bucket_array_get(&hash_table->entries, i);

		CBCP_Config_Hash_Entry **slot = NULL;

		if (cbcp_config_hash_table_get_slot(hash_table, entry->key, &slot).error) {
			return CBCP_CONFIG_STATUS_ERROR;
		}

		assert(slot != NULL);

		*slot = entry;
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_hash_table_insert(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	void *data)
{
	assert(hash_table->entries.count <= hash_table->count_limit);

	if (hash_table->entries.count == hash_table->count_limit) {
		if (cbcp_config_hash_table_grow(hash_table).error) {
			return CBCP_CONFIG_STATUS_ERROR;
		}
	}

	assert(hash_table->entries.count < hash_table->count_limit);

	CBCP_Config_Hash_Entry **slot = NULL;

	if (cbcp_config_hash_table_get_slot(hash_table, key, &slot).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	assert(slot != NULL);

	CBCP_Config_Hash_Entry *entry = cbcp_config_hash_entry_bucket_array_new(&hash_table->entries);

	entry->key = key;
	entry->data = data;

	*slot = entry;

	return CBCP_CONFIG_STATUS_SUCCESS;
}


static bool
cbcp_config_hash_table_search(
	CBCP_Config_Hash_Table *hash_table,
	void *key,
	void **out_data)
{
	CBCP_Config_Hash_Entry **slot = NULL;

	if (cbcp_config_hash_table_get_slot(hash_table, key, &slot).error) {
		assert(!"Since hash table is dynamic, it should not be possible to be out of slots.");
	}

	assert(slot != NULL);

	if (*slot == NULL) {
		// Not found
		return false;
	}
	else {
		*out_data = (**slot).data;
		// Found
		return true;
	}
}

// / Hash table

// String hash set

static void
cbcp_config_string_hash_set_init(
	CBCP_Config_String_Hash_Set *hash_set,
	uint32_t initial_minimum_capacity)
{
	assert(hash_set->table == NULL);

	uint32_t initial_capacity = 2;

	if (initial_minimum_capacity > 2) {
		initial_capacity = cbcp_config_u32_next_power_of_2(initial_minimum_capacity);
	}

	*hash_set = CBCP_ZERO_LITERAL(CBCP_Config_String_Hash_Set);

	hash_set->capacity = initial_capacity;
	hash_set->count_limit = hash_set->capacity >> 1;

	size_t memory_size = hash_set->capacity*sizeof(*hash_set->table);

	hash_set->table = (
		(CBCP_Config_String **)
		CBCP_ALLOCATE(memory_size));

	memset(hash_set->table, 0, memory_size);
}

static CBCP_Config_Status
cbcp_config_string_hash_set_get_slot(
	CBCP_Config_String_Hash_Set *hash_set,
	CBCP_Config_String key,
	CBCP_Config_String ***out_slot)
{
	uint32_t hash = cbcp_config_hash_string(key);
	uint32_t stride = cbcp_config_hash_u32_to_odd(hash);
	uint32_t initial_index = hash & (hash_set->capacity - 1); // capacity must be a power of 2
	uint32_t index = initial_index;

	CBCP_Config_String **slot;

	for (;;) {
		slot = &hash_set->table[index];

		if (*slot <= ((CBCP_Config_String *)1)) {
			break;
		}

		CBCP_Config_String in_table_key = **slot;

		if (in_table_key.length == key.length) {
			if (strncmp(in_table_key.chars, key.chars, key.length) == 0) {
				break;
			}
		}

		index += stride;
		index &= (hash_set->capacity - 1); // capacity must be a power of 2

		if (index == initial_index) {
			return CBCP_CONFIG_STATUS_ERROR;
		}
	}
	*out_slot = slot;
	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_string_hash_set_grow(
	CBCP_Config_String_Hash_Set *hash_set)
{
	assert(hash_set->entries.count == hash_set->count_limit);

	// Double table size
	unsigned int new_capacity = hash_set->capacity << 1;

	if (new_capacity == 0) {
		new_capacity = 16;
	}

	unsigned int new_count_limit = new_capacity >> 1;
	assert(new_count_limit != 0);

	size_t memory_size = new_capacity * sizeof(*hash_set->table);

	CBCP_Config_String **new_table =
		(CBCP_Config_String **)CBCP_REALLOCATE(hash_set->table, memory_size);

	if (new_table == NULL) {
		return CBCP_CONFIG_STATUS_ERROR;
	}


	hash_set->count_limit = new_count_limit;
	hash_set->capacity = new_capacity;
	hash_set->table = new_table;

	memset(hash_set->table, 0, memory_size);


	for (unsigned int i = 0; i < hash_set->entries.count; ++i) {
		CBCP_Config_String *entry =
			cbcp_config_string_bucket_array_get(&hash_set->entries, i);

		CBCP_Config_String **slot = NULL;

		if (cbcp_config_string_hash_set_get_slot(hash_set, *entry, &slot).error) {
			return CBCP_CONFIG_STATUS_ERROR;
		}

		assert(slot != NULL);

		*slot = entry;
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}

static CBCP_Config_Status
cbcp_config_string_hash_set_insert(
	CBCP_Config_String_Hash_Set *hash_set,
	CBCP_Config_String key,
	CBCP_Config_String **out_key_in_set)
{
	assert(hash_set->entries.count <= hash_set->count_limit);

	if (hash_set->entries.count == hash_set->count_limit) {
		if (cbcp_config_string_hash_set_grow(hash_set).error) {
			return CBCP_CONFIG_STATUS_ERROR;
		}
	}

	assert(hash_set->entries.count < hash_set->count_limit);

	CBCP_Config_String **slot = NULL;

	if (cbcp_config_string_hash_set_get_slot(hash_set, key, &slot).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	assert(slot != NULL);

	if (*slot <= (CBCP_Config_String *)1) {
		CBCP_Config_String *entry = cbcp_config_string_bucket_array_new(&hash_set->entries);

		key.chars = cbcp_config_copy_string(key.chars, key.length);

		*entry = key;

		*slot = entry;
	}

	*out_key_in_set = *slot;
	return CBCP_CONFIG_STATUS_SUCCESS;
}

static bool
cbcp_config_string_hash_set_contains(
	CBCP_Config_String_Hash_Set *hash_set,
	CBCP_Config_String key)
{
	CBCP_Config_String **slot = NULL;

	if (cbcp_config_string_hash_set_get_slot(hash_set, key, &slot).error) {
		return false;
	}

	assert(slot != NULL);

	return *slot > (CBCP_Config_String *)1;
}

// / String hash set


static CBCP_Config_Parse_Host_Definitions_Status
cbcp_config_parse_host_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config)
{
	CBCP_Config_Host_Bucket_Array *hosts = &config->hosts;
	CBCP_Config_String_Hash_Set *interns = &config->string_interns;
	CBCP_Config_Net_Address_Bucket_Array *net_addresses = &config->net_addresses;

	CBCP_Config_Hash_Table *hosts_and_groups_by_name = &config->hosts_and_groups_by_name;

	CBCP_Config_Parse_State parse_copy = *parse;

	while (cbcp_config_parse_has_next_statement(&parse_copy)) {

		char *host_name_start = parse_copy.at;
		unsigned int host_name_length;
		int is_group_name;

		if (cbcp_config_parse_get_name(&parse_copy, &host_name_length, &is_group_name).error) {
			cbcp_config_parse_log(
				parse_copy.base, host_name_start,
				"\tExpected host name.\n");
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Host_Definitions_Status,
				ERROR_INVALID_HOST_NAME);
		}

		if (is_group_name) {
			cbcp_config_parse_log(
				parse_copy.base, host_name_start,
				"\tHost names cannot start with @-sign.\n"
				"\tNames starting with @-sign are reserved for groups.\n");
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Host_Definitions_Status,
				ERROR_INVALID_HOST_NAME);
		}


		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between host name and network addresses.\n",
				CBCP_CONFIG_FIELD_SEPERATOR);
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Host_Definitions_Status,
				ERROR_MISSING_SEPERATOR);
		}


		CBCP_Config_String_Intern host_name_intern =
			cbcp_config_intern_from_string(interns, host_name_start, host_name_length);

		CBCP_Config_Host *existing_host = NULL;

		if (cbcp_config_hash_table_search(
			hosts_and_groups_by_name,
			(void *)host_name_intern.string,
			(void **)&existing_host)
		) {
			cbcp_config_parse_log(
				parse_copy.base, host_name_start,
				"\tRedefinition of host '%.*s'\n",
				host_name_length, host_name_start);
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Host_Definitions_Status,
				ERROR_HOST_REDEFINITION);
		}

		CBCP_Config_Host *host = cbcp_config_host_bucket_array_new(hosts);
		host->name = host_name_intern;

		do {

			char *protocol_string_start = parse_copy.at;

			if (cbcp_config_parse_eat_name(&parse_copy).error) {
				cbcp_config_parse_log(
					parse_copy.base, protocol_string_start,
					"Could not parse network protocol name.\n");
				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Host_Definitions_Status,
					ERROR_INVALID_PROTOCOL_NAME);
			}

			unsigned int protocol_string_length = parse_copy.at - protocol_string_start;

			if (cbcp_config_parse_eat_seperator_inline(
				&parse_copy,
				CBCP_CONFIG_SUBFIELD_SEPERATOR).error
			) {
				cbcp_config_parse_log(
					parse_copy.base, parse_copy.at,
					"Expected '%c' between.\n",
					CBCP_CONFIG_SUBFIELD_SEPERATOR);
				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Host_Definitions_Status,
					ERROR_MISSING_SEPERATOR);
			}

			char *address_string_start = parse_copy.at;

			if (cbcp_config_parse_eat_address_string(&parse_copy).error) {
				cbcp_config_parse_log(
					parse_copy.base, address_string_start,
					"\tCould not parse the network address.\n");
				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Host_Definitions_Status,
					ERROR_INVALID_HOST_ADDRESS);
			}

			unsigned int address_string_length = parse_copy.at - address_string_start;

			CBCP_Config_String_Intern protocol_name_intern = cbcp_config_intern_from_string(
				interns,
				protocol_string_start,
				protocol_string_length);

			CBCP_Config_String_Intern address_string_intern = cbcp_config_intern_from_string(
				interns,
				address_string_start,
				address_string_length);

			CBCP_Config_Net_Address *net_address =
				cbcp_config_net_address_bucket_array_new(net_addresses);

			net_address->protocol = protocol_name_intern;
			net_address->address = address_string_intern;

			cbcp_config_net_address_reflist_add(&host->net_addresses, net_address, false);

		} while (!cbcp_config_parse_eat_seperator_inline(
			&parse_copy,
			CBCP_CONFIG_FIELD_SEPERATOR).error
		);

		cbcp_config_hash_table_insert(
			hosts_and_groups_by_name,
			(void *)host_name_intern.string,
			(void *)host);

		if (cbcp_db_generate_RSA_key(host, 2048).error)
		{
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Host_Definitions_Status,
				ERROR_RSA_GENERATION);
		}
	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Host_Definitions_Status, SUCCESS);
}


static CBCP_Config_Parse_Group_Definitions_Status
cbcp_config_parse_group_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config)
{
	CBCP_Config_Group_Bucket_Array *groups = &config->groups;
	CBCP_Config_String_Hash_Set *interns = &config->string_interns;

	CBCP_Config_Hash_Table *hosts_and_groups_by_name = &config->hosts_and_groups_by_name;

	CBCP_Config_Parse_State parse_copy = *parse;

	while (cbcp_config_parse_has_next_statement(&parse_copy)) {

		char *group_name_start = parse_copy.at;
		unsigned int group_name_length;
		int is_group;

		if (cbcp_config_parse_get_name(&parse_copy, &group_name_length, &is_group).error) {
			cbcp_config_parse_log(
				parse_copy.base, group_name_start,
				"\tExpected group name.\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_INVALID_GROUP_NAME);
		}

		if (!is_group) {
			cbcp_config_parse_log(
				parse_copy.base, group_name_start,
				"\tGroup names must start with @-sign.\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_INVALID_GROUP_NAME);
		}

		CBCP_Config_String_Intern group_name_intern =
			cbcp_config_intern_from_string(interns, group_name_start, group_name_length);

		CBCP_Config_Group *already_existing_group;

		if (cbcp_config_hash_table_search(
			hosts_and_groups_by_name,
			group_name_intern.string,
			(void **)&already_existing_group)
		) {
			cbcp_config_parse_log(
				parse_copy.base, group_name_start,
				"\tRedefinition of group '%.*s'\n",
				group_name_length, group_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_GROUP_REDEFINITION);
		}

		CBCP_Config_Group *group = cbcp_config_group_bucket_array_new(groups);
		group->name = group_name_intern;

		cbcp_config_hash_table_insert(
			hosts_and_groups_by_name,
			(void *)group_name_intern.string,
			(void *)group);

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between group name and host list.\n"
				"\tIn definition of group '%.*s'.\n",
				CBCP_CONFIG_FIELD_SEPERATOR,
				group_name_length,
				group_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_MISSING_SEPERATOR);
		}

		do {

			if (parse_copy.at >= parse_copy.end || *parse_copy.at == '\n') {
				break;
			}

			char *host_name = parse_copy.at;
			unsigned int host_name_length;
			int is_group;

			if (cbcp_config_parse_get_name(&parse_copy, &host_name_length, &is_group).error) {
				cbcp_config_parse_log(
					parse_copy.base, host_name,
					"\tA host name contains illegal characters.\n"
					"\tIn definition of group '%.*s'.\n",
					group_name_length,
					group_name_start);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_INVALID_HOST_NAME);
			}

			if (is_group) {
				cbcp_config_parse_log(
					parse_copy.base, host_name,
					"\tA host name is not allowed to start with @-sign.\n"
					"\tIn definition of group '%.*s'.\n",
					group_name_length,
					group_name_start);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_INVALID_HOST_NAME);
			}


			CBCP_Config_String_Intern host_name_intern =
				cbcp_config_intern_from_string(interns, host_name, host_name_length);

			CBCP_Config_Host *host;

			if (! cbcp_config_hash_table_search(
				hosts_and_groups_by_name,
				(void *)host_name_intern.string,
				(void **)&host)
			) {
				cbcp_config_parse_log(
					parse_copy.base, host_name,
					"\tReference to undefined host '%.*s'\n"
					"\tIn definition of group '%.*s'.\n",
					host_name_length,
					host_name,
					group_name_length,
					group_name_start);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_UNDEFINED_HOST);
			}

			// Test for repeats
			for (unsigned int i = 0; i < group->hosts.count; ++i) {
				CBCP_Config_Host *other = group->hosts.pointers[i];

				if (other == host) {
					cbcp_config_parse_log(
						parse_copy.base, host_name,
						"\tRepeated reference to host '%.*s'\n"
						"\tIn definition of group '%.*s'.\n",
						host_name_length,
						host_name,
						group_name_length,
						group_name_start);
					return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, ERROR_REPEATED_HOST);
				}
			}

			cbcp_config_host_reflist_add(&group->hosts, host, false);
			cbcp_config_group_reflist_add(&host->groups, group, false);

		} while (!cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_SUBFIELD_SEPERATOR).error);

	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Group_Definitions_Status, SUCCESS);
}

static CBCP_Config_Parse_Interface_Definitions_Status
cbcp_config_parse_interface_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config)
{
	CBCP_Config_Interface_Bucket_Array *interfaces = &config->interfaces;
	CBCP_Config_String_Hash_Set *interns = &config->string_interns;
	CBCP_Config_Hash_Table *interfaces_by_name = &config->interfaces_by_name;

	CBCP_Config_Parse_State parse_copy = *parse;

	while (cbcp_config_parse_has_next_statement(&parse_copy)) {

		char *interface_name = parse_copy.at;
		unsigned int interface_name_length;
		{
			int is_group;

			if (cbcp_config_parse_get_name(&parse_copy, &interface_name_length, &is_group).error) {
				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tName of interface expected.\n");

				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Interface_Definitions_Status,
					ERROR_INVALID_INTERFACE_NAME);
			}
			else if (is_group) {
				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tInterface names cannot start with @-sign.\n"
					"\tNames starting with @-sign are reserved for groups.\n");

				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Interface_Definitions_Status,
					ERROR_INVALID_INTERFACE_NAME);
			}
		}

		CBCP_Config_String_Intern interface_name_intern =
			cbcp_config_intern_from_string(interns, interface_name, interface_name_length);

		// Make sure that we are not redefining the interface
		for (unsigned int i = 0; i < interfaces->count; ++i) {
			CBCP_Config_Interface *interface = cbcp_config_interface_bucket_array_get(interfaces, i);

			if (cbcp_config_string_interns_are_equal(interface->name, interface_name_intern)) {

				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tRedefinition of interface '%.*s'.\n",
					interface_name_length, interface_name);

				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Interface_Definitions_Status,
					ERROR_INTERFACE_REDEFINITION);
			}

		}

		// assert(interfaces->count < interfaces->capacity);
		CBCP_Config_Interface *interface =
			cbcp_config_interface_bucket_array_new(interfaces);

		interface->name = interface_name_intern;

		cbcp_config_hash_table_insert(
			interfaces_by_name,
			(void *)interface_name_intern.string,
			(void *)interface);

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between interface name and capability list.\n",
				CBCP_CONFIG_FIELD_SEPERATOR);

			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Interface_Definitions_Status,
				ERROR_MISSING_SEPERATOR);
		}



		CBCP_Config_Parse_Get_Capability_Name_Status get_capability_name_status;

		do {

			char *capability_name_start = parse_copy.at;

			CBCP_Config_String_Intern capability_name_intern;

			get_capability_name_status = cbcp_config_parse_get_capability_name(
				&parse_copy,
				interns,
				&capability_name_intern);

			switch (get_capability_name_status.error) {
				case CBCP_Config_Parse_Get_Capability_Name_Status__OK_DONE:
				case CBCP_Config_Parse_Get_Capability_Name_Status__OK_NEXT: {
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NO_NAME: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tExpected capability name.\n"
						"\tIn capability list of interface '%.*s'.\n",
						interface_name_length, interface_name);

					return CBCP_CONFIG_STATUS(
						CBCP_Config_Parse_Interface_Definitions_Status,
						ERROR_INVALID_CAPABILITY_NAME);
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_GROUP_NAME: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tCapability names cannot start with @-sign.\n"
						"\tNames starting with @-sign are reserved for groups.\n"
						"\tIn capability list of interface '%.*s'.\n",
						interface_name_length, interface_name);

					return CBCP_CONFIG_STATUS(
						CBCP_Config_Parse_Interface_Definitions_Status,
						ERROR_INVALID_CAPABILITY_NAME);
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NAME_TOO_LONG: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tCapability name is too long.\n"
						"\tThe maximum allowed length for a capability name is %d.\n"
						"\tIn capability list of interface '%.*s'.\n",
						CBCP_CONFIG_CAPABILITY_NAME_LENGTH_LIMIT,
						interface_name_length, interface_name);

					return CBCP_CONFIG_STATUS(
						CBCP_Config_Parse_Interface_Definitions_Status,
						ERROR_INVALID_CAPABILITY_NAME);
				} break;
			}

            if (interface->command_count >= CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE) {
				cbcp_config_parse_log(
					parse_copy.base, capability_name_start,
					"\tToo many capabilities for a single interface.\n"
					"\tThe maximum number of capabilities for a single interface is %d.\n"
					"\tIn capability list of interface '%.*s'.\n",
					CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE,
					interface_name_length, interface_name);

				return CBCP_CONFIG_STATUS(
					CBCP_Config_Parse_Interface_Definitions_Status,
					ERROR_EXCEEDED_CAPABILITY_MAX);
			}

			// Make sure capability does not already exist for this interface

            for (unsigned int i = 0; i < interface->command_count; ++i) {
				if (cbcp_config_string_interns_are_equal(
                    interface->commands[i],
					capability_name_intern)
				) {
					CBCP_Config_String capability_name =
						cbcp_config_string_from_intern(capability_name_intern);

					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tRepeated capability '%.*s'.\n"
						"\tIn capability list of interface '%.*s'.\n",
						capability_name.length, capability_name.chars,
						interface_name_length, interface_name);

					return CBCP_CONFIG_STATUS(
						CBCP_Config_Parse_Interface_Definitions_Status,
						ERROR_CAPABILITY_REDEFINITION);
				}
			}

            interface->commands[interface->command_count++] = capability_name_intern;

		} while (get_capability_name_status.error != CBCP_Config_Parse_Get_Capability_Name_Status__OK_DONE);
	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Interface_Definitions_Status, SUCCESS);
}


static CBCP_Config_Parse_Implements_Status
cbcp_config_parse_implements(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config)
{
	CBCP_Config_Hash_Table *interfaces_by_name = &config->interfaces_by_name;
	CBCP_Config_String_Hash_Set *interns = &config->string_interns;

	CBCP_Config_Hash_Table *hosts_and_groups_by_name = &config->hosts_and_groups_by_name;

	CBCP_Config_Parse_State parse_copy = *parse;

	while (cbcp_config_parse_has_next_statement(&parse_copy)) {

		char *server_name = parse_copy.at;
		unsigned int server_name_length;

		CBCP_Config_Host_Or_Group server;

		if (cbcp_config_parse_get_name(&parse_copy, &server_name_length, &server.is_group).error) {
			cbcp_config_parse_log(
				parse_copy.base, server_name,
				"\tName of interface server expected (This is either a defined host or group).\n");

			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_Implements_Status,
				ERROR_INVALID_SERVER_NAME);
		}

		CBCP_Config_String_Intern server_name_intern =
			cbcp_config_intern_from_string(interns, server_name, server_name_length);

		if (cbcp_config_host_or_group_from_name(hosts_and_groups_by_name, server_name_intern, &server).error) {
			cbcp_config_parse_log(
				parse_copy.base, server_name,
				"\tThe given server name '%.*s' does not match any definied hosts or groups.\n",
				server_name_length, server_name);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, ERROR_UNDEFINED_SERVER);
		}

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between interface server name and interface name.\n",
				CBCP_CONFIG_FIELD_SEPERATOR);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, ERROR_MISSING_SEPERATOR);
		}

		// Parse list of interfaces
		do {

			if (parse_copy.at >= parse_copy.end || *parse_copy.at == '\n') {
				break;
			}

			char *interface_name = parse_copy.at;
			unsigned int interface_name_length;
			int interface_name_is_group;

			if (cbcp_config_parse_get_name(
				&parse_copy,
				&interface_name_length,
				&interface_name_is_group).error
			) {
				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tInterface name contains illegal characters.\n"
					"\tIn implemts section for '%.*s'.\n",
					interface_name_length,
					interface_name);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, ERROR_INVALID_INTERFACE_NAME);
			}

			if (interface_name_is_group) {
				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tInterface names are not allowed to start with an @-sign.\n"
					"\tIn implemts section for '%.*s'.\n",
					interface_name_length,
					interface_name);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, ERROR_INVALID_INTERFACE_NAME);
			}

			CBCP_Config_String_Intern interface_name_intern =
				cbcp_config_intern_from_string(interns, interface_name, interface_name_length);

			CBCP_Config_Interface *interface;

			bool interface_found = cbcp_config_hash_table_search(
				interfaces_by_name,
				(void *)interface_name_intern.string,
				(void **)&interface);

			if (!interface_found)
			{
				cbcp_config_parse_log(
					parse_copy.base, interface_name,
					"\tThe interface '%.*s' is not defined.\n",
					interface_name_length, interface_name);
				return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, ERROR_UNDEFINED_INTERFACE);
			}

			CBCP_Config_Host_Iterator server_host_iterator = cbcp_config_host_iterator(server);
			CBCP_Config_Host *server_host = NULL;

			while (cbcp_config_host_iterator_next(&server_host_iterator, &server_host)) {

				CBCP_Config_Interface_Instance *interface_instance;

				for (unsigned int i = 0; i < server_host->local_interfaces.count; ++i) {
					interface_instance = server_host->local_interfaces.pointers[i];
					if (interface_instance->interface == interface) {
						goto continue_outer;
					}
				}

				interface_instance = cbcp_config_interface_instance_bucket_array_new(
					&config->interface_instances);

				*interface_instance = CBCP_ZERO_LITERAL(CBCP_Config_Interface_Instance);

				interface_instance->interface = interface;

				interface_instance->master_secret = cbcp_capability_generate_master_secret();

				cbcp_config_interface_instance_reflist_add(
					&server_host->local_interfaces,
					interface_instance,
					false);


				continue_outer: continue;
			}

		} while (!cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_SUBFIELD_SEPERATOR).error);
	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Implements_Status, SUCCESS);
}

static CBCP_Config_Host_Iterator
cbcp_config_host_iterator(CBCP_Config_Host_Or_Group host_or_group)
{
	CBCP_Config_Host_Iterator host_iterator;
	host_iterator.host_or_group = host_or_group;
	host_iterator.index = 0;
	return host_iterator;
}

static bool
cbcp_config_host_iterator_next(
	CBCP_Config_Host_Iterator *iterator,
	CBCP_Config_Host **out_next_host)
{

	CBCP_Config_Host_Or_Group host_or_group = iterator->host_or_group;

	if (host_or_group.is_group) {

		CBCP_Config_Group *group = host_or_group.u.group;
		if (iterator->index >= group->hosts.count) {
			return false;
		}

		*out_next_host = group->hosts.pointers[iterator->index];
	}
	else {
		if (iterator->index > 0) {
			return false;
		}

		*out_next_host = host_or_group.u.host;
	}

	++iterator->index;
	return true;
}

static CBCP_Config_Status
cbcp_config_add_licence_edges(
	CBCP_Config_Host_Or_Group server_collection,
	CBCP_Config_Host_Or_Group client_collection,
	CBCP_Config_Interface_Subset interface_subset,
	CBCP_Config_License_Bucket_Array *licenses)
{
	CBCP_Config_Host_Iterator client_host_iterator;
	CBCP_Config_Host_Iterator server_host_iterator;
	CBCP_Config_Host *client_host;
	CBCP_Config_Host *server_host;

	//
	// Union remote subinterface for clients
	//

	client_host_iterator = cbcp_config_host_iterator(client_collection);
	client_host = NULL;

	while (cbcp_config_host_iterator_next(&client_host_iterator, &client_host)) {

		CBCP_Config_Interface_Subset_Reflist *remote_interfaces = &client_host->remote_interfaces;

		CBCP_Config_Interface_Subset *remote_interface_subset = NULL;

		for (unsigned int remote_interface_index = 0;
			remote_interface_index < remote_interfaces->count;
			++remote_interface_index
		) {
			CBCP_Config_Interface_Subset *it =
				(CBCP_Config_Interface_Subset *)(
					remote_interfaces->pointers[remote_interface_index]);

			if (interface_subset.interface == it->interface) {
				remote_interface_subset = it;
			}
		}

		// Union remote interface
		if (remote_interface_subset) {
			remote_interface_subset->capability.capability_mask |= interface_subset.capability.capability_mask;
		}
		else {
			remote_interface_subset =
				(CBCP_Config_Interface_Subset *)CBCP_ALLOCATE(sizeof(*remote_interface_subset));
			*remote_interface_subset = interface_subset;

			if (cbcp_config_interface_subset_reflist_add(
				&client_host->remote_interfaces,
				remote_interface_subset,
				false).error
			) {
				return CBCP_CONFIG_STATUS_ERROR;
			}
		}
	}


	//
    // Init license and assign it to server and client
	//
	server_host_iterator = cbcp_config_host_iterator(server_collection);
	server_host = NULL;

	while (cbcp_config_host_iterator_next(&server_host_iterator, &server_host)) {

		// Find interface instance for server corresponding to current interface
		CBCP_Config_Interface_Instance *server_interface_instance = NULL;
		for (unsigned int i = 0; i < server_host->local_interfaces.count; ++i) {
			CBCP_Config_Interface_Instance *it =
				server_host->local_interfaces.pointers[i];

			if (it->interface == interface_subset.interface) {
				// Found
				server_interface_instance = it;
				break;
			}
		}

		assert(server_interface_instance != NULL);

		CBCP_Config_License *license =
			cbcp_config_license_bucket_array_new(licenses);


		*license = CBCP_ZERO_LITERAL(CBCP_Config_License);

		// TODO(jakob & Jørn): Init license
		license->interface = interface_subset.interface;

		license->reduction_field.subfields[0] = interface_subset.capability;
		license->reduction_field.subfields[1].capability_mask = ~(uint64_t)0;
		license->reduction_field.subfields[2].capability_mask = ~(uint64_t)0;
		license->reduction_field.subfields[3].capability_mask = ~(uint64_t)0;

		cbcp_config_capability_reflist_add(
			&server_interface_instance->capabilities,
			&license->reduction_field.subfields[0],
			false);

		license->capability_id = server_interface_instance->capabilities.count-1;

		license->secret = cbcp_capability_compute_secret(
			&server_interface_instance->master_secret,
			&license->reduction_field,
			license->capability_id);


		license->client_group = client_collection.is_group
			? client_collection.u.group
			: NULL;

		client_host_iterator = cbcp_config_host_iterator(client_collection);
		client_host = NULL;

		while (cbcp_config_host_iterator_next(&client_host_iterator, &client_host)) {

			// Skip if client and server are the same host
			if (client_host == server_host) {
				continue;
			}

			CBCP_Config_Neighbor_Info_Reflist *client_neighbors =
				&client_host->neighbor_infos;

			// Find entry matching
			CBCP_Config_Neighbor_Info *server_info_at_client = NULL;

			for (unsigned int i = 0; i < client_neighbors->count; ++i) {
				if (client_neighbors->pointers[i]->neighbor == server_host) {
					server_info_at_client = client_neighbors->pointers[i];
					break;
				}
			}

			if (server_info_at_client == NULL) {
				// Not found, add new entry
				server_info_at_client =
					(CBCP_Config_Neighbor_Info*)CBCP_ALLOCATE(sizeof(*server_info_at_client));
				*server_info_at_client = CBCP_ZERO_LITERAL(CBCP_Config_Neighbor_Info);
				server_info_at_client->neighbor = server_host;
				cbcp_config_neighbor_info_reflist_add(
					client_neighbors,
					server_info_at_client,
					false);
			}

			if (cbcp_config_license_reflist_add(
				&server_info_at_client->licenses,
				license,
				false).error
			) {
				return CBCP_CONFIG_STATUS_ERROR;
			}
			else {

			}

			CBCP_Config_Neighbor_Info_Reflist *server_neighbors =
				&server_host->neighbor_infos;

			bool client_already_added_to_server_neighbors = false;

			for (unsigned int i = 0; i < server_neighbors->count; ++i) {
				CBCP_Config_Neighbor_Info *server_neighbor_info =
					server_neighbors->pointers[i];

				if (server_neighbor_info->neighbor == client_host) {
					client_already_added_to_server_neighbors = true;
					break;
				}
			}

			if (!client_already_added_to_server_neighbors) {

				CBCP_Config_Neighbor_Info *server_neighbor_info =
					(CBCP_Config_Neighbor_Info*)CBCP_ALLOCATE(sizeof(*server_neighbor_info));

				*server_neighbor_info = CBCP_ZERO_LITERAL(CBCP_Config_Neighbor_Info);

				server_neighbor_info->neighbor = client_host;

				if (cbcp_config_neighbor_info_reflist_add(
					server_neighbors,
					server_neighbor_info,
					false).error
				) {
					return CBCP_CONFIG_STATUS_ERROR;
				}
			}
		}
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}


static CBCP_Config_Parse_License_Definitions_Status
cbcp_config_parse_license_definitions(
	CBCP_Config_Parse_State *parse,
	CBCP_Config *config)
{
	CBCP_Config_Hash_Table *interfaces_by_name = &config->interfaces_by_name;
	CBCP_Config_License_Bucket_Array *licenses = &config->licenses;
	CBCP_Config_String_Hash_Set *interns = &config->string_interns;

	CBCP_Config_Hash_Table *hosts_and_groups_by_name = &config->hosts_and_groups_by_name;

	CBCP_Config_Parse_State parse_copy = *parse;

	CBCP_Config_Host_Or_Group client;
	CBCP_Config_Host_Or_Group server;

	while (cbcp_config_parse_has_next_statement(&parse_copy)) {

		char *client_name_start = parse_copy.at;
		unsigned int client_name_length;

		if (cbcp_config_parse_get_name(&parse_copy, &client_name_length, &client.is_group).error) {
			cbcp_config_parse_log(
				parse_copy.base, client_name_start,
				"\tName of client expected (This is either a defined host or group).\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_CLIENT_NAME);
		}

		CBCP_Config_String_Intern client_name_intern =
			cbcp_config_intern_from_string(interns, client_name_start, client_name_length);

		if (cbcp_config_host_or_group_from_name(hosts_and_groups_by_name, client_name_intern, &client).error) {
			cbcp_config_parse_log(
				parse_copy.base, client_name_start,
				"\tThe given client name '%.*s' does not match any definied hosts or groups.\n",
				client_name_length, client_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_UNDEFINED_CLIENT);
		}

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between client name and provider name\n",
				CBCP_CONFIG_FIELD_SEPERATOR);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_MISSING_SEPERATOR);
		}

		char *server_name_start = parse_copy.at;
		unsigned int server_name_length;

		if (cbcp_config_parse_get_name(&parse_copy, &server_name_length, &server.is_group).error) {
			cbcp_config_parse_log(
				parse_copy.base, server_name_start,
				"\tName of server expected (This is either a defined host or group).\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_SERVER_NAME);
		}

		CBCP_Config_String_Intern server_name_intern =
			cbcp_config_intern_from_string(interns, server_name_start, server_name_length);

		if (cbcp_config_host_or_group_from_name(hosts_and_groups_by_name, server_name_intern, &server).error) {
			cbcp_config_parse_log(
				parse_copy.base, server_name_start,
				"\tThe given server name '%.*s' does not match any definied hosts or groups.\n",
				server_name_length, server_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_UNDEFINED_SERVER);
		}

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between server name and interface name.\n",
				CBCP_CONFIG_FIELD_SEPERATOR);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_MISSING_SEPERATOR);
		}

		char *interface_name_start = parse_copy.at;
		unsigned int interface_name_length;
		int is_interface_name_group;

		if (cbcp_config_parse_get_name(&parse_copy, &interface_name_length, &is_interface_name_group).error) {
			cbcp_config_parse_log(
				parse_copy.base, interface_name_start,
				"\tName of interface expected.\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_INTERFACE_NAME);
		}

		if (is_interface_name_group) {
			cbcp_config_parse_log(
				parse_copy.base, interface_name_start,
				"\tInterface names cannot start with @-sign.\n"
				"\tNames starting with @-sign are reserved for groups.\n");
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_INTERFACE_NAME);
		}


		CBCP_Config_String_Intern interface_name_intern =
			cbcp_config_intern_from_string(interns, interface_name_start, interface_name_length);

		CBCP_Config_Interface *interface;

		// TODO(jakob): Replace by hash table lookup for interface *
		bool interface_found = cbcp_config_hash_table_search(
			interfaces_by_name,
			(void *)interface_name_intern.string,
			(void **)&interface);

		if (!interface_found)
		{
			cbcp_config_parse_log(
				parse_copy.base, interface_name_start,
				"\tThe interface '%.*s' is not defined for server '%.*s'.\n",
				interface_name_length, interface_name_start,
				server_name_length, server_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_UNDEFINED_INTERFACE);
		}

		if (cbcp_config_parse_eat_seperator_inline(&parse_copy, CBCP_CONFIG_FIELD_SEPERATOR).error) {
			cbcp_config_parse_log(
				parse_copy.base, parse_copy.at,
				"\tExpected '%c' between interface name and capability list.\n",
				"\tIn the license definition for client '%.*s', server '%.*s', and interface '%.*s'.\n",
				CBCP_CONFIG_FIELD_SEPERATOR,
				client_name_length, client_name_start,
				server_name_length, server_name_start,
				interface_name_length, interface_name_start);
			return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_MISSING_SEPERATOR);
		}


		CBCP_Config_Interface_Subset interface_subset = CBCP_ZERO_INITIALIZER;

		interface_subset.interface = interface;
		interface_subset.capability.capability_mask = 0;

		CBCP_Config_Parse_Get_Capability_Name_Status get_capability_name_status;

		do {

			char *capability_name_start = parse_copy.at;

			CBCP_Config_String_Intern capability_name_intern;

			get_capability_name_status = cbcp_config_parse_get_capability_name(
				&parse_copy,
				interns,
				&capability_name_intern);

			switch (get_capability_name_status.error) {
				case CBCP_Config_Parse_Get_Capability_Name_Status__OK_DONE:
				case CBCP_Config_Parse_Get_Capability_Name_Status__OK_NEXT: {
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NO_NAME: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tExpected capability name.\n"
						"\tIn the license definition of client '%.*s', server '%.*s', and interface '%.*s'",
						client_name_length, client_name_start,
						server_name_length, server_name_start,
						interface_name_length, interface_name_start);
					return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_CAPABILITY_NAME);
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_GROUP_NAME: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tCapability names cannot start with @-sign.\n"
						"\tNames starting with @-sign are reserved for groups.\n"
						"\tIn the license definition of client '%.*s', server '%.*s', and interface '%.*s'",
						client_name_length, client_name_start,
						server_name_length, server_name_start,
						interface_name_length, interface_name_start);
					return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_CAPABILITY_NAME);
				} break;

				case CBCP_Config_Parse_Get_Capability_Name_Status__ERROR_NAME_TOO_LONG: {
					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tCapability name is too long.\n"
						"\tThe maximum allowed length for a capability name is %d.\n"
						"\tIn the license definition of client '%.*s', server '%.*s', and interface '%.*s'",
						CBCP_CONFIG_CAPABILITY_NAME_LENGTH_LIMIT,
						client_name_length, client_name_start,
						server_name_length, server_name_start,
						interface_name_length, interface_name_start);
					return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_INVALID_CAPABILITY_NAME);
				} break;
			}

			// Make sure capability exists for this interface
			{
				unsigned int i = 0;

                for (; i < interface->command_count; ++i) {
					if (cbcp_config_string_interns_are_equal(
                        interface->commands[i],
						capability_name_intern)
					) {
						break;
					}
				}

                if (i == interface->command_count) {

					CBCP_Config_String capability_name_string =
						cbcp_config_string_from_intern(capability_name_intern);

					cbcp_config_parse_log(
						parse_copy.base, capability_name_start,
						"\tThe capability '%.*s' is not defined for interface '%.*s' of server '%.*s' required by client '%.*s'.\n",
						capability_name_string.length, capability_name_string.chars,
						interface_name_length, interface_name_start,
						server_name_length, server_name_start,
						client_name_length, client_name_start);
					return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, ERROR_UNDEFINED_CAPABILITY);
				}
				else {
					interface_subset.capability.capability_mask |= (1UL << i);
				}
			}

		} while (
			get_capability_name_status.error !=
			CBCP_Config_Parse_Get_Capability_Name_Status__OK_DONE
		);

		if (cbcp_config_add_licence_edges(server, client, interface_subset, licenses).error) {
			cbcp_config_log("Could not add license edges.\n");
			return CBCP_CONFIG_STATUS(
				CBCP_Config_Parse_License_Definitions_Status,
				ERROR_ADDING_EDGES);
		}

	}

	parse->at = parse_copy.at;

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_License_Definitions_Status, SUCCESS);
}


static CBCP_Config_Parse_Status
cbcp_config_parse(char *config_file_contents, unsigned int config_file_length, CBCP_Config *config) {

	CBCP_Config_Parse_State parse;
	parse.base = config_file_contents;
	parse.at = parse.base;
	parse.end = parse.base + config_file_length;

	cbcp_config_parse_eat_whitespace(&parse);

	// Version Section

	cbcp_config_log_set_prefix("Error parsing CBCP config header.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!CBCP ").error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"\tExpected !CBCP document header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_HEADER);
	}

	int major_version;
	int minor_version;
	if (cbcp_config_parse_get_version(&parse, &major_version, &minor_version).error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"\tVersion number expected in header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_VERSION_INVALID);
	}

	if (major_version > 1) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"\tThis cbcp-config file is for a newer version of CBCP.\n"
			"\tConsider looking for an updated version of the CBCP configuration utility.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_VERSION_INVALID);
	}

	if (cbcp_config_parse_eat_seperator(&parse, '\n').error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"\tExpected section seperator (at least one line feed).\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_SEPERATOR);
	}

	// Hosts Section

	cbcp_config_log_set_prefix("Error parsing host definition section.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!HOSTS").error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"\tExpected a !HOSTS section header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_HOSTS_SECTION);
	}
	else if (cbcp_config_parse_host_definitions(&parse, config).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_INVALID_HOSTS_SECTION);
	}


	// Groups Section (Optional)

	cbcp_config_log_set_prefix("Error parsing group definition section.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!GROUPS").error) {
		// NOTE(jakob): No groups section is ok since it is optional
	}
	else if (cbcp_config_parse_group_definitions(&parse, config).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_INVALID_GROUPS_SECTION);
	}

	// Interfaces Section

	cbcp_config_log_set_prefix("Error parsing interface definition section.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!INTERFACES").error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"CBCP config file is missing an !INTERFACES section header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_INTERFACES_SECTION);
	}
	else if (cbcp_config_parse_interface_definitions(&parse, config).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_INVALID_INTERFACES_SECTION);
	}


	// Implements Section

	cbcp_config_log_set_prefix("Error parsing interface implementers section.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!IMPLEMENTS").error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"CBCP config file is missing an !IMPLEMENTS section header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_IMPLEMENTS_SECTION);
	}
	else if (cbcp_config_parse_implements(&parse, config).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_INVALID_IMPLEMENTS_SECTION);
	}

	// Licenses Section

	cbcp_config_log_set_prefix("Error parsing license definition section.\n");

	if (cbcp_config_parse_eat_substring_case_insensitive(&parse, "!CAPABILITIES").error) {
		cbcp_config_parse_log(
			parse.base, parse.at,
			"CBCP config file is missing a !CAPABILITIES section header.\n");
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_MISSING_LICENSES_SECTION);
	}
	else if (cbcp_config_parse_license_definitions(&parse, config).error) {
		return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, ERROR_INVALID_LICENSES_SECTION);
	}

	return CBCP_CONFIG_STATUS(CBCP_Config_Parse_Status, SUCCESS);
}

#include <stdio.h>
#include <malloc.h>

static int read_file(const char *file_path, char **file_contents_out, unsigned int *file_length_out) {
	FILE *file = fopen(file_path, "r");

	if (!file) {
		return -1;
	}

	fseek(file, 0, SEEK_END);
	size_t file_length = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *file_contents = (char *)malloc(file_length+1);

	if (fread(file_contents, file_length, 1, file) != 1) {
		return -1;
	}

	file_contents[file_length] = '\0';

	fclose(file);

	*file_contents_out = file_contents;
	*file_length_out = file_length;
	return 0;
}

static void
cbcp_config_string_from_capability_mask(uint64_t capability_mask, char buffer[CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE]) {
	static const char *bit_strings[] = {
		"0000", "0001", "0010", "0011",
		"0100", "0101", "0110", "0111",
		"1000", "1001", "1010", "1011",
		"1100", "1101", "1110", "1111",
	};

	unsigned int buffer_size = CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE + 1;

	for (int chunk_index = buffer_size/4-1; chunk_index >= 0; --chunk_index) {
		const char *bit_chunk = bit_strings[(capability_mask >> (4*chunk_index)) & 0xf];
		snprintf(buffer, buffer_size, "%.4s", bit_chunk);
		buffer_size -= 4;
		buffer += 4;
	}
}

static CBCP_Config_Status
cbcp_config_output_database(CBCP_Config *config, const char *output_directory_path)
{
	int openssl_return_value;
	char *checksum_position;
	char *header_offset_cursor;


	CBCP_Config_Host_Bucket_Array *hosts = &config->hosts;
	unsigned int buffer_size = 1<<20;
	char *buffer_start = (char *) CBCP_ALLOCATE(buffer_size); // Allocate 1 MB to the database output

	cbcp_config_log_set_prefix("");

	for (unsigned int host_index = 0; host_index < config->hosts.count; ++host_index) {

		fprintf(stderr, "\nCBCP DATA HEADER\n");

		char *cursor = buffer_start;

		cbcp_serialize_byte_array(&cursor, (char *) "cbcpdata", 8);

		uint16_t major_version = 0;
		uint16_t minor_version = 7;
		cbcp_serialize_u16(&cursor, major_version);
        cbcp_serialize_u16(&cursor, minor_version);

		checksum_position = cursor;
		cbcp_serialize_u32(&cursor, 0); // Checksum set to zero before the checksum is calcualted
		header_offset_cursor = cursor;
		// advance cursor:
		cursor += sizeof(uint32_t) * 3;

		//
		// Output Self section
		//

		fprintf(stderr, "\nSELF SECTION\n");

		cbcp_serialize_u32(&header_offset_cursor, (uint32_t) (cursor - buffer_start));
		CBCP_Config_Host *self = cbcp_config_host_bucket_array_get(hosts, host_index);
		CBCP_Config_String self_name = cbcp_config_string_from_intern(self->name);
		cbcp_serialize_length_byte_array_8(&cursor, self_name.chars, self_name.length);

		cbcp_serialize_u8(&cursor, self->net_addresses.count);
		cbcp_serialize_u16(&cursor, self->groups.count);
		cbcp_serialize_u16(&cursor, self->local_interfaces.count);


		// Public Key
		unsigned char *public_DER_key = NULL;
		openssl_return_value = i2d_RSAPublicKey(self->rsa_key, &public_DER_key);
		if (openssl_return_value < 0)
		{
			return CBCP_CONFIG_STATUS_ERROR;
		}
		uint16_t public_key_length = (uint16_t) openssl_return_value;
		cbcp_serialize_length_byte_array_16(&cursor, (char *) public_DER_key, public_key_length);

		// Private Key
		unsigned char *private_DER_key = NULL;
		openssl_return_value = i2d_RSAPrivateKey(self->rsa_key, &private_DER_key);
		if (openssl_return_value < 0)
		{
			return CBCP_CONFIG_STATUS_ERROR;
		}
		uint16_t private_key_length = (uint16_t) openssl_return_value;
		cbcp_serialize_length_byte_array_16(&cursor, (char *) private_DER_key, private_key_length);


		for(uint8_t i = 0; i < self->net_addresses.count; ++i)
		{
			// Transport protocol
			CBCP_Config_String protocol = cbcp_config_string_from_intern(self->net_addresses.pointers[i]->protocol);
			cbcp_serialize_length_byte_array_8(&cursor, protocol.chars, protocol.length);
			// Transport address
			CBCP_Config_String address = cbcp_config_string_from_intern(self->net_addresses.pointers[i]->address);
			cbcp_serialize_length_byte_array_16(&cursor, address.chars, address.length);

		}

		for(uint8_t i = 0; i < self->groups.count; ++i)
		{
			// Group name
			CBCP_Config_String group_name = cbcp_config_string_from_intern(self->groups.pointers[i]->name);
			cbcp_serialize_length_byte_array_8(&cursor, group_name.chars, group_name.length);
		}

		// fprintf(stderr,
		// 	"==========================\n"
		// 	"%.*s\n"
		// 	"==========================\n",
		// 	self_name.length, self_name.chars);

		// Output own interfaces
		// Total self interface count

		fprintf(stderr, "\nSelf Interfaces\n");

		for (unsigned int interface_index = 0;
			interface_index < self->local_interfaces.count;
			++interface_index
		) {

			CBCP_Config_Interface_Instance *interface_instance =
				self->local_interfaces.pointers[interface_index];

			CBCP_Config_Interface *interface = interface_instance->interface;

			CBCP_Config_String interface_name =
				cbcp_config_string_from_intern(interface->name);

			// OUTPUT: interface_name

			fprintf(stderr, "Interface '%.*s': ",
				interface_name.length, interface_name.chars);

			cbcp_serialize_length_byte_array_8(&cursor, interface_name.chars, interface_name.length);

			// Capability stuff:
			cbcp_serialize_byte_array(&cursor, (char *) &interface_instance->master_secret.secret_8, CBCP_CAPABILITY_SECRET_SIZE);

            // Number of capability entries
            cbcp_serialize_u16(&cursor, interface_instance->capabilities.count);
            cbcp_serialize_u8(&cursor, (uint8_t) interface->command_count);

			for (unsigned int capability_index = 0;
				capability_index < interface_instance->capabilities.count;
				++capability_index)
			{
				CBCP_Capability *capability = interface_instance->capabilities.pointers[capability_index];
				cbcp_serialize_u64(&cursor, capability->capability_mask);
			}

			for (
				unsigned int capability_index = 0;
                capability_index < interface->command_count;
				++capability_index
			) {
                CBCP_Config_String command_name =
                    cbcp_config_string_from_intern(interface->commands[capability_index]);

				// OUTPUT: capability_name
				fprintf(stderr, "'%.*s' ",
                    command_name.length, command_name.chars);

				// command Name
                cbcp_serialize_length_byte_array_8(&cursor, command_name.chars, command_name.length);
			}

			fprintf(stderr, "\n");

		}

		//
		// Output remote interfaces
		// (Partly?) As in: only the commands `self` has access to

		fprintf(stderr, "\nREMOTE INTERFACE SECTION\n");

		CBCP_Config_Interface_Subset_Reflist *remote_interfaces = &self->remote_interfaces;

		// Set remote interfaces offset in header
		cbcp_serialize_u32(&header_offset_cursor, (uint32_t) (cursor - buffer_start));

		cbcp_serialize_u32(&cursor, remote_interfaces->count);

		for (unsigned int remote_interface_index = 0;
			remote_interface_index < remote_interfaces->count;
			++remote_interface_index
		) {
			CBCP_Config_Interface_Subset *remote_interface_subset =
				remote_interfaces->pointers[remote_interface_index];

			uint64_t capability_mask = remote_interface_subset->capability.capability_mask;

			CBCP_Config_Interface *interface = remote_interface_subset->interface;

			CBCP_Config_String interface_name =
					cbcp_config_string_from_intern(interface->name);

			// fprintf(stderr, "Remote Interface (%.*s):", interface_name.length, interface_name.chars);

			cbcp_serialize_length_byte_array_8(&cursor, interface_name.chars, interface_name.length);
			uint8_t licensed_capability_count = 0;
			char *licensed_capability_count_cusor = cursor;

			// Advance cursor
			cursor += sizeof (licensed_capability_count);
			for (
				uint8_t command_id = 0;
                command_id < interface->command_count;
				++command_id
			) {
				if (capability_mask & (1UL << command_id)) {
					CBCP_Config_String capability_name =
                        cbcp_config_string_from_intern(interface->commands[command_id]);

                    // command id
					cbcp_serialize_u8(&cursor, (uint8_t)command_id);

					// command Name
					licensed_capability_count++;
					cbcp_serialize_length_byte_array_8(&cursor, capability_name.chars, capability_name.length);

					// fprintf(stderr, " <%.*s>", capability_name.length, capability_name.chars);
				}
			}

			cbcp_serialize_u8(&licensed_capability_count_cusor, licensed_capability_count);

			fprintf(stderr, "\n");

		}


		//
		// Output Neighbor section
		//
		// Set offset to Neighbor section
		fprintf(stderr, "\nNEIGHBOR SECTION\n");

		fprintf(stderr, "in header<");
		cbcp_serialize_u32(&header_offset_cursor, (uint32_t) (cursor - buffer_start));
		fprintf(stderr, ">");

		cbcp_serialize_u32(&cursor, self->neighbor_infos.count);

		for (
			unsigned int neighbor_index = 0;
			neighbor_index < self->neighbor_infos.count;
			++neighbor_index
		) {
			CBCP_Config_Neighbor_Info *neighbor_info = (
				(CBCP_Config_Neighbor_Info *)
				self->neighbor_infos.pointers[neighbor_index]);

			CBCP_Config_Host *neighbor = neighbor_info->neighbor;

			CBCP_Config_String neighbor_name =
				cbcp_config_string_from_intern(neighbor->name);

			// OUTPUT: neighbor name
			// fprintf(stderr, "Neighbor '%.*s': \n", neighbor_name.length, neighbor_name.chars);

            cbcp_serialize_length_byte_array_8(&cursor, neighbor_name.chars, neighbor_name.length);

            CBCP_Config_Net_Address *neighbor_address = NULL;

			for (uint8_t self_address_index = 0;
				self_address_index < self->net_addresses.count;
				++self_address_index)
			{
				CBCP_Config_Net_Address *self_address =
					self->net_addresses.pointers[self_address_index];

				for (uint8_t neighbor_address_index = 0;
					neighbor_address_index < neighbor->net_addresses.count;
					++neighbor_address_index)
				{
					neighbor_address =
						neighbor->net_addresses.pointers[neighbor_address_index];

					if (cbcp_config_string_interns_are_equal(
						self_address->protocol,
						neighbor_address->protocol))
					{
						goto found_matching_neighbor_network_address;
					}
				}
			}

			// We did not find a mathing neighbor network address

			cbcp_config_log("Could not find compatible network address for neighbor '%.*s' of host '%.*s'",
				neighbor_name.length, neighbor_name.chars,
				self_name.length, self_name.chars);

			return CBCP_CONFIG_STATUS_ERROR;

found_matching_neighbor_network_address:
			// Transport protocol
			{
				CBCP_Config_String protocol;
				CBCP_Config_String address;
				protocol = cbcp_config_string_from_intern(neighbor_address->protocol);
				address = cbcp_config_string_from_intern(neighbor_address->address);

				cbcp_serialize_length_byte_array_8(&cursor, protocol.chars, protocol.length);
				cbcp_serialize_length_byte_array_16(&cursor, address.chars, address.length);
			}

			uint16_t license_count = (uint16_t) neighbor_info->licenses.count;
			cbcp_serialize_u16(&cursor, license_count);

			// Public Key
			unsigned char *public_DER_key = NULL;
			openssl_return_value = i2d_RSAPublicKey(neighbor->rsa_key, &public_DER_key);
			if (openssl_return_value < 0)
			{
				return CBCP_CONFIG_STATUS_ERROR;
			}
			uint16_t public_key_length = (uint16_t) openssl_return_value;
			cbcp_serialize_length_byte_array_16(&cursor, (char *) public_DER_key, public_key_length);


			for (
				unsigned int license_index = 0;
				license_index < neighbor_info->licenses.count;
				++license_index
			) {
				CBCP_Config_License *license = (
					(CBCP_Config_License *)
					neighbor_info->licenses.pointers[license_index]);


				CBCP_Config_Interface_Instance_Reflist server_interfaces =
					neighbor->local_interfaces;

				uint32_t interface_id_at_server;

				for (interface_id_at_server = 0;
					interface_id_at_server < server_interfaces.count;
					++interface_id_at_server
				) {
					CBCP_Config_Interface_Instance *neighbor_interface_instance =
						server_interfaces.pointers[interface_id_at_server];

					CBCP_Config_Interface *neighbor_interface =
						neighbor_interface_instance->interface;

					if (neighbor_interface == license->interface) {
						break;
					}
				}

				assert(interface_id_at_server < server_interfaces.count);

				CBCP_Config_Interface_Subset_Reflist self_remote_interfaces =
					self->remote_interfaces;

				uint32_t interface_id_at_client;

				for (interface_id_at_client = 0;
					interface_id_at_client < self_remote_interfaces.count;
					++interface_id_at_client
				) {
					CBCP_Config_Interface_Subset *remote_interface_subset =
						self_remote_interfaces.pointers[interface_id_at_client];

					CBCP_Config_Interface *remote_interface =
						remote_interface_subset->interface;

					if (remote_interface == license->interface) {
						break;
					}
				}
				assert(interface_id_at_client < self_remote_interfaces.count);

                assert(interface_id_at_client < self_remote_interfaces.count);

				uint16_t client_group_id;

				if (license->client_group == NULL) {
					// NOTE(jakob & jørn): Client group for this license is self
					// which we denote by an all one-bits client_group_id.
					client_group_id = ~0;
				}
				else {

					for (client_group_id = 0;
						client_group_id < (uint16_t)self->groups.count;
						++client_group_id
					) {
						if (self->groups.pointers[client_group_id] == license->client_group) {
							break;
						}
					}

					assert(client_group_id < self->groups.count);
				}

                cbcp_serialize_u16(&cursor, interface_id_at_client);
                cbcp_serialize_u16(&cursor, interface_id_at_server);
				cbcp_serialize_u16(&cursor, client_group_id);
				for(int i = 0; i < CBCP_CAPABILITY_REDUCTION_SUBFIELD_COUNT; ++i)
				{
					cbcp_serialize_u64(&cursor, license->reduction_field.subfields[i].capability_mask);
				}
				cbcp_serialize_byte_array(&cursor, (char *) &license->secret.secret_8, CBCP_CAPABILITY_SECRET_SIZE);
				cbcp_serialize_u64(&cursor, license->capability_id);
			}

		}

		fprintf(stderr, "\n\n");

		{
			cbcp_serialize_u32(&checksum_position, 42); // TODO(Jørn and Jakob) Calcualted real checksum
			char database_filename[1024];

			snprintf(
				database_filename,
				sizeof(database_filename),
				"%s/%.*s.cbcpdb",
				output_directory_path,
				self_name.length,
				self_name.chars);

			FILE *f = fopen(database_filename, "w+");
			unsigned int used_buffer_size = cursor - buffer_start;
			fwrite(buffer_start, used_buffer_size, 1, f);
			fclose(f);
		}
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}


CBCP_Config_Status
cbcp_config(const char *config_file_path, const char *output_directory_path) {

	char *config_file_contents;
	unsigned int config_file_length;

	if (read_file(config_file_path, &config_file_contents, &config_file_length)) {
		cbcp_config_log("Could not read config file, '%s'.\n", config_file_path);
		return CBCP_CONFIG_STATUS_ERROR;
	}

#if !defined(CBCP_CONFIG_NO_LOGGING)
	global_config_file_path = config_file_path;
#endif

	CBCP_Config config = CBCP_C_LITERAL(CBCP_Config)CBCP_ZERO_INITIALIZER;

	cbcp_config_hash_table_init(&config.hosts_and_groups_by_name, 64);
	cbcp_config_hash_table_init(&config.interfaces_by_name, 64);
	cbcp_config_string_hash_set_init(&config.string_interns, 128);

	// NOTE(jakob): Reserve the first string intern for an uninitialized string
	cbcp_config_intern_from_string(
		&config.string_interns,
		(char *)"UNINITIALIZED",
		sizeof("UNINITIALIZED")-1);

	if (cbcp_config_parse(config_file_contents, config_file_length, &config).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	if (cbcp_config_output_database(&config, output_directory_path).error) {
		return CBCP_CONFIG_STATUS_ERROR;
	}

	return CBCP_CONFIG_STATUS_SUCCESS;
}

int main(int argument_count, char *arguments[])
{
	const char *config_file_path = "network.cbcp-config";
	const char *output_directory_path = ".";

	// if (argument_count > 2) {
	// 	cbcp_config_log(
	// 		"Usage:\n%s [<config file>]\n"
	// 		"\t<config file> specifies the path to the .cbcp-config file defining the CBCP network.\n"
	// 		"\t\tDefaults to 'network.cbcp-config'.\n", arguments[0]);
	// 	return -1;
	// }

	if (argument_count > 1) {
		config_file_path = arguments[1];

		if (argument_count > 2) {
			output_directory_path = arguments[2];
		}
	}


	if (cbcp_config(config_file_path, output_directory_path).error) {
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif
