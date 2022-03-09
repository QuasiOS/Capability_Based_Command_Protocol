/*
** Manager
*/

#include <cbcp.h>
#define CBCP_NET_TCP_IMPLEMENTATION
#include <cbcp_net_tcp.h>

#include <errno.h> /* For errno */
#include <string.h> /* For strerror */
#include <stdio.h> /* For printf, fprintf */
#include <stdlib.h> /* For exit */

static void cmd_log_callback(CBCP_Command_Args *args);

static void command_rejected_callback(CBCP_Command_Rejected_Args args);

int main(int argc, char const *argv[]) {
	const char *cbcp_database_filepath;
	CBCP_State *cbcp;
	FILE *log_file;

	if (argc < 2) {
		fprintf(stderr, "Usage:\n\t%s <cbcp_database_filepath>\n", argv[0]);
		exit(-1);
	}

	cbcp_database_filepath = argv[1];

	/*
	** Initialize CBCP by loading the database file for this host
	*/

	cbcp_net_tcp_init(0);
	cbcp = cbcp_init(cbcp_database_filepath);

	if (cbcp == NULL) {
		fprintf(stderr, "Could not initialize CBCP.\n");
		exit(-1);
	}

	/*
	** Open log file in append mode
	*/

	log_file = fopen("log_file.txt", "a");

	if (log_file == NULL) {
		fprintf(stderr, "Could not open log file: %s\n", strerror(errno));
		exit(-1);
	}

	/*
	** Bind command callbacks
	*/

	if (!cbcp_server_init_command(
		cbcp,
		"Logging",
		"Log",
		cmd_log_callback,
		(void *)log_file,
		0)
	) {
		fprintf(stderr, "Could not init served command.\n");
		exit(-1);
	}

	/* Set command rejected callback */
	cbcp_server_set_command_rejected_callback(cbcp, command_rejected_callback, (void *)log_file);

	cbcp_server_start(cbcp);

	fclose(log_file);

	return 0;
}

static void
cmd_log_callback(CBCP_Command_Args *args) {
	FILE *log_file;
	char *message;
	unsigned int message_length;

	/* Get arguments */
	log_file = (FILE *)args->user_data;
	message = (char *)args->payload;
	message_length = args->payload_length;

	if (strncmp("calzone", message, sizeof("calzone")-1) == 0) {
		/* Revoke capability */
		CBCP_Own_Interface *logging_interface;
		CBCP_Own_Command *log_command;

		logging_interface =	cbcp_get_own_interface(args->cbcp, (char *)"Logging", sizeof("Logging")-1);
		log_command = cbcp_get_own_command(logging_interface, (char *)"Log", sizeof("Log")-1);
		cbcp_server_disable_command_for_all(log_command);
		fprintf(stdout, "Disabled log command.\n");
	}

	/* Append message to log file */
	fprintf(log_file, "%.*s\n", message_length, message);
	fflush(log_file);
	fprintf(stdout, "Logged: \"%.*s\"\n", (int)message_length, message);
}

static void command_rejected_callback(CBCP_Command_Rejected_Args args) {
	FILE *log_file;
	log_file = (FILE *)args.user_data;

	fprintf(log_file, "Command rejected! Reason: %x\n", args.reason);
	fflush(log_file);
	fprintf(stdout, "Command rejected! Reason: %x\n", args.reason);
}