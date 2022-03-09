#ifndef CBCP_WRITE_DATABASE_H
#define CBCP_WRITE_DATABASE_H

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "cbcp_config.h"

#define CBCP_DB_MAX_COMMANDS_PER_INTERFACE 64
#define CBCP_DB_SECRET_BYTE_SIZE 16 // 128 bits, used in AES-128
#define CBCP_DB_REDUCTION_SUBFIELD_COUNT 4

typedef struct CBCP_DB_Reduction_Field
{
    uint64_t subfields[CBCP_DB_REDUCTION_SUBFIELD_COUNT];
} CBCP_DB_Reduction_Field;

typedef struct CBCP_DB_Secret
{
    uint8_t secret[CBCP_DB_SECRET_BYTE_SIZE];
} CBCP_DB_Secret;

typedef struct CBCP_DB_Access_Entry
{
    uint64_t license_id; // used as search key
    uint64_t capability_mask;
} CBCP_DB_Access_Entry;

typedef struct CBCP_DB_Interface_Header
{
    char     *name;
    uint8_t  length;
    CBCP_DB_Secret       master_secret; // Capability_Password
    uint16_t             access_entry_count;
    CBCP_DB_Access_Entry *access_entry_table;
    uint8_t              command_count;
    // After the header follows the command name on the format
    // uint8_t length:char[] name
} CBCP_DB_Interface_Header;

typedef struct CBCP_DB_License
{
    uint32_t interface_id_at_client;
    uint32_t interface_id_at_server;
    CBCP_DB_Reduction_Field reduction_field;
    CBCP_Secret          secret;
    uint64_t             licence_id; // NOTE(Jørn) 64-bit is used to make it hard to guess another class
} CBCP_DB_License;

int database_generate_RSA_key(CBCP_Config_Host *host, int key_size_bits);

int cbcp_db_init_interface(CBCP_DB_Interface_Header *interface);
int cbcp_db_init_license(
        CBCP_DB_License *license,
        CBCP_DB_Interface_Header *object,
        uint64_t capability_mask,
        uint64_t licence_id);

void cbcp_db_marshal_host(
        bool write_private_key,
        CBCP_Config_String selected_host_name_string,
        CBCP_Config_String host_address,
        CBCP_Config_Host *selected_host_entity,
        CBCP_DB_File_Header *database_buffer,
        int  *current_offset);


void database_file_write_host_to_buffer(
        bool write_private_key,
        CBCP_Config_String selected_host_name_string,
        CBCP_Config_String host_address,
        CBCP_Config_Host *selected_host_entity,
        CBCP_DB_File_Header *database_buffer,
        int  *current_offset);
void database_file_write_interfaces_to_buffer(
        CBCP_DB_File_Header *database_buffer,
        int  *current_offset,
        CBCP_Config_Interface_Instance *interface_instance);
//void database_file_write_license(
//        CBCP_DB_File_Header *database_buffer,
//        int  *current_offset,
//        int64_t local_remote,
//        int64_t remote_local,
//        Capability *capability);
void database_file_write_remote_interface(
        CBCP_DB_File_Header *database_buffer,
        int  *current_offset,
        CBCP_Config_Interface *interface);
#endif
