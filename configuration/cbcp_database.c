#include "cbcp_database.h"

#include "string.h"

int database_generate_RSA_key(CBCP_Config_Host *host, int key_size_bits) // char *hostname, RSA *out_rsa_key, int key_size_bits)
{
	int            return_value = 0;
	BIGNUM        *big_number   = NULL;
	unsigned long  e = RSA_F4;

	big_number = BN_new();
	return_value = BN_set_word(big_number, e);
	if(return_value == 1)
	{
		host->rsa_key = RSA_new();
		#ifdef CBCP_DEBUG_NO_KEYS
		return_value = 1;
		#else
		return_value = RSA_generate_key_ex(host->rsa_key, key_size_bits, big_number, NULL);
		#endif
	}

	BN_free(big_number);

	return (return_value == 1);
}

void database_file_write_host_to_buffer(
		bool is_self,
		CBCP_Config_String selected_host_name_string,
		CBCP_Config_String host_address,
		CBCP_Config_Host *host_entity,
		CBCP_Database_File_Format *database_buffer,
		int  *current_offset)
{

	// Name
	memcpy(database_buffer->data + *current_offset, selected_host_name_string.chars, selected_host_name_string.length);
	*current_offset = *current_offset + selected_host_name_string.length;
	database_buffer->data[(*current_offset)] = 0;
	(*current_offset)++;

	// Address
	memcpy(database_buffer->data + *current_offset, host_address.chars, host_address.length);
	*current_offset = *current_offset + host_address.length;
	database_buffer->data[(*current_offset)] = 0;
	(*current_offset)++;

	// Public PEM
	unsigned char *public_DER_key = NULL;

	uint32_t public_key_length = i2d_RSAPublicKey(host_entity->rsa_key, &public_DER_key);

	memcpy(database_buffer->data + *current_offset, &public_key_length, sizeof (public_key_length));
	*current_offset = *current_offset + sizeof (public_key_length);
	memcpy(database_buffer->data + *current_offset, public_DER_key, public_key_length);
	*current_offset = *current_offset + public_key_length;
	// Private PEM
	if (is_self)
	{
		unsigned char *private_DER_key = NULL;
		uint32_t private_key_length = i2d_RSAPrivateKey(host_entity->rsa_key, &private_DER_key);
		memcpy(database_buffer->data + *current_offset, &private_key_length, sizeof (private_key_length));
		*current_offset = *current_offset + sizeof (private_key_length);
		memcpy(database_buffer->data + *current_offset, private_DER_key, private_key_length);
		*current_offset = *current_offset + private_key_length;
	}
	else
	{
		// No private key for this host:
		uint32_t private_key_length = 0;
		memcpy(database_buffer->data + *current_offset, &private_key_length, sizeof (private_key_length));
		*current_offset = *current_offset + sizeof (private_key_length);
	}
}

void database_file_write_remote_interface(
		CBCP_Database_File_Format *database_buffer,
		int  *current_offset,
		CBCP_Config_Interface *interface)
{
	CBCP_Config_String string = cbcp_config_string_from_intern(interface->name);
	memcpy(database_buffer->data + *current_offset, string.chars, string.length);
	*current_offset += string.length;
	database_buffer->data[(*current_offset)] = 0;
	(*current_offset)++;

	uint8_t capability_count = (uint8_t)interface->capability_count;
	memcpy(database_buffer->data + *current_offset, &capability_count, sizeof (capability_count));
	*current_offset = *current_offset + sizeof (capability_count);

	for (unsigned char i = 0; i < interface->capability_count; i++)
	{
		CBCP_Config_String string = cbcp_config_string_from_intern(interface->capabilities[i]);
		if (string.length == 0)
		{
			break;
		}
		memcpy(database_buffer->data + *current_offset, &i, sizeof (i));
		*current_offset = *current_offset + sizeof (i);
		memcpy(database_buffer->data + *current_offset, string.chars, string.length);
		*current_offset = *current_offset + string.length;
		database_buffer->data[(*current_offset)] = 0;
		(*current_offset)++;
	}

}

//void database_file_write_license(
//		CBCP_Database_File_Format *database_buffer,
//		int  *current_offset,
//		int64_t local_remote,
//		int64_t remote_local,
//		Capability *capability)
//{
//	// Interface ID is 3 bytes per specification.
//	// We wrap the ID's in int64_t but are only saving the three first bytes
//	memcpy(database_buffer->data + *current_offset, &local_remote, 3);
//	*current_offset = *current_offset + 3;

//	memcpy(database_buffer->data + *current_offset, &remote_local, 3);
//	*current_offset = *current_offset + 3;

//	memcpy(database_buffer->data + *current_offset, capability, sizeof (Capability));
//	*current_offset = *current_offset + sizeof (Capability);
//}

void database_file_write_interfaces_to_buffer(
	CBCP_Database_File_Format *database_buffer,
	int  *current_offset,
	CBCP_Config_Interface_Instance *interface_instance)
{
	CBCP_Config_Interface *interface = interface_instance->interface;

	database_buffer->header.number_self_interfaces++;
	// TODO(Jørn) I have removed static for cbcp_config_string_from_intern in cbcp_config.h
	CBCP_Config_String temp_string = cbcp_config_string_from_intern(interface->name);
	// Interface Name
	memcpy(database_buffer->data + *current_offset, temp_string.chars, temp_string.length);
	*current_offset = *current_offset + temp_string.length;
	database_buffer->data[(*current_offset)] = 0;
	(*current_offset)++;

//	memcpy(database_buffer->data + *current_offset, &interface_instance->capability_object, sizeof (Capability_Object));
//	*current_offset = *current_offset + sizeof (Capability_Object);

//	memcpy(database_buffer->data + *current_offset, &interface_instance->owner_capability, sizeof (Capability));
//	*current_offset = *current_offset + sizeof (Capability);

	// Save Number capabilities
	int8_t number_cast = interface->capability_count;
	memcpy(database_buffer->data + *current_offset, &number_cast, sizeof (number_cast));
	*current_offset = *current_offset + sizeof (number_cast);
	// Save all capabilities
	for(unsigned int i = 0; i < interface->capability_count; i++)
	{
		CBCP_Config_String temp_string = cbcp_config_string_from_intern(interface->capabilities[i]);
		// Interface Name
		memcpy(database_buffer->data + *current_offset, temp_string.chars, temp_string.length);
		*current_offset = *current_offset + temp_string.length;
		database_buffer->data[(*current_offset)] = 0;
		(*current_offset)++;
	}
}

//void database_file_write_licenses_to_buffer(
//        CBCP_Database_File_Format *database_buffer,
//        int  *current_offset,
//        CBCP_Config_String_Array *interns,
//        CBCP_Config *config,
//        CBCP_Config_License *license)
//{

//    // Add one to count of capabilites
//    database_buffer->header.number_capabilities++;

//    char capability_vector_string[CBCP_CONFIG_MAX_CAPABILITIES_PER_INTERFACE + 1];

//    cbcp_config_string_from_capability_vector(
//        license->capability_vector,
//        capability_vector_string);

//    CBCP_Config_Interface interface =
//        *cbcp_config_interface_from_index(&config->interfaces, license->interface_id.index);

//    CBCP_Config_Entity server_entity =
//        *cbcp_config_entity_from_index(&config->entities, interface.server_id.index);

//    CBCP_Config_String client_name = cbcp_config_string_from_intern(
//        &config->string_interns,
//        cbcp_config_entity_from_index(
//            &config->entities,
//            license->client_id.index)
//        ->name);
//    CBCP_Config_String server_name = cbcp_config_string_from_intern(&config->string_interns, server_entity.name);
//    CBCP_Config_String interface_name = cbcp_config_string_from_intern(&config->string_interns, interface.name);

//    // Write which reciveing host the capability is valid for
//    memcpy(database_buffer->data + *current_offset, server_name.chars, server_name.length + 1);
//    *current_offset = *current_offset + server_name.length + 1;

//    // Write the interface name
//    memcpy(database_buffer->data + *current_offset, interface_name.chars, interface_name.length + 1);
//    *current_offset = *current_offset + interface_name.length + 1;

//    // Write the interface index on the reciveing host

//    // TODO(Jørn) is license->interface_id.index the acutal interface index at server host?
//    memcpy(database_buffer->data + *current_offset, &license->interface_id.index, 3);
//    *current_offset = *current_offset + 3;

//    // List all the capabilites this licens gives in the format "id:name" where ":" is a zero byte

//    for (
//        unsigned int class_host_relation_index = server_entity.type_specific.first_class_host_relation_id.index;
//        class_host_relation_index < config->class_host_relations.count;
//        ++class_host_relation_index
//    ) {
//        CBCP_Config_Class_Host_Relation relation = *cbcp_config_class_host_relation_from_index(&config->class_host_relations, class_host_relation_index);

//        if (cbcp_config_compare_entity_ids(relation.class_id, server_entity.id) != 0) {
//            // Break since we are no longer looking at hosts for this particular class
//            break;
//        }

//        assert(relation.host_id.index < config->entities.count);

//        CBCP_Config_Entity host_server_entity = *cbcp_config_entity_from_index(&config->entities, relation.host_id.index);
//        server_name = cbcp_config_string_from_intern(&config->string_interns, host_server_entity.name);

//        fprintf(stderr,
//            "'%.*s' <- '%.*s'/'%.*s',\n\tcapability vector: <%s>\n",
//            client_name.length, client_name.chars,
//            server_name.length, server_name.chars,
//            interface_name.length, interface_name.chars,
//            capability_vector_string);

//        // Write capability id
//        memcpy(database_buffer->data + *current_offset, &A.CBCP_robot_arm_capability[HOST_C].capability, sizeof (Capability));
//        *current_offset = *current_offset + sizeof (Capability);

//        // Write capability name
//        memcpy(database_buffer->data + *current_offset, &A.CBCP_robot_arm_capability[HOST_C].capability, sizeof (Capability));
//        *current_offset = *current_offset + sizeof (Capability);
//    }
//}

/*
void database_load_rsa_keys()
{
	const unsigned char *b = p;
	RSA *r = d2i_RSAPrivateKey(NULL, &b, ret);
}
*/
