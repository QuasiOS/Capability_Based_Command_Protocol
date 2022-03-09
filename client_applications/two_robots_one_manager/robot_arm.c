/*
** Robot Arm
*/

#include <cbcp.h>
#define CBCP_NET_TCP_IMPLEMENTATION
#include <cbcp_net_tcp.h>

#include <stdio.h> /* For printf, fprintf */
#include <stdlib.h> /* For malloc */
#include <sys/select.h> /* For select */
#include <string.h> /* For strncpy */

#define MESSAGE_BUFFER_SIZE 128

struct Load_Bricks_User_Data {
	CBCP_Command *cmd_notify_done_loading;
	CBCP_Command *cmd_manager_log;
};

static void cmd_load_bricks_callback(CBCP_Command_Args *args);

int main(int argc, char const *argv[]) {
	const char *cbcp_database_filepath;
	CBCP_State *cbcp;
	struct Load_Bricks_User_Data user_data;

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
	** Get references to needed commands in the mobile robot and manager
	*/

	user_data.cmd_notify_done_loading =
		cbcp_client_init_command(cbcp, "Mobile Robot", "Info", "Done Loading");

	user_data.cmd_manager_log =
		cbcp_client_init_command(cbcp, "Manager", "Logging", "Log");

	/*
	** Bind command callbacks
	*/

	cbcp_server_init_command(
		cbcp,
		"Arm",
		"Load Bricks",
		cmd_load_bricks_callback,
		&user_data,
		MESSAGE_BUFFER_SIZE);

	cbcp_server_start(cbcp);

	return 0;
}

static void load_bricks(void) {
	int i;

	/* Simulate loading bricks */

	printf("Loading Bricks: 0%%\n");

	for (i = 1; i <= 5; ++i) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 200000;
		select(0, NULL, NULL, NULL, &tv);
		printf("Loading Bricks: %d%%\n", i*100/5);
	}
	printf("\n");
}

static void cmd_load_bricks_callback(CBCP_Command_Args *args) {
	char *response_payload;
	struct Load_Bricks_User_Data *user_data;
	CBCP_Command *cmd_manager_log;

	load_bricks();

	/* Notify that we are done loading bricks */

	response_payload = (char *)args->response_payload;
	strncpy(response_payload, "We are done loading bricks.", MESSAGE_BUFFER_SIZE);
	args->response_payload_length = 42;

	user_data = (struct Load_Bricks_User_Data *)args->user_data;
	cmd_manager_log = user_data->cmd_manager_log;


	/* Pass NULL for response callback since we don't care about the response */
	cbcp_client_send_command_async(cmd_manager_log, (char *)"We are done loading bricks.", sizeof("We are done loading bricks.")-1, NULL, 0, NULL, NULL);
}