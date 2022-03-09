/*
** Mobile Robot
*/

#include <cbcp.h>
#define CBCP_NET_TCP_IMPLEMENTATION
#include <cbcp_net_tcp.h>

#include <stdio.h> /* For printf, fprintf */
#include <stdlib.h> /* For malloc, exit */
#include <string.h> /* For strncpy */
#include <sys/select.h> /* For select */

static void drive(const char *description);

int main(int argc, char const *argv[]) {
	const char *cbcp_database_filepath;
	CBCP_Command *cmd_load_bricks;
	CBCP_Command *cmd_manager_log;
	CBCP_State *cbcp;
	const char *job_done_message = "Job done";
	CBCP_Response response;
	char response_buffer[4096];
	unsigned int iteration;

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
	** Init commands
	*/

	cmd_load_bricks = cbcp_client_init_command(cbcp, "Robot Arm", "Arm", "Load Bricks");
	cmd_manager_log = cbcp_client_init_command(cbcp, "Manager", "Logging", "Log");

	if (!cmd_load_bricks || !cmd_manager_log) {
		fprintf(stderr, "Could not initialize needed commands.\n");
		exit(-1);
	}

	/*
	** Client code here
	*/


	for (iteration = 0; ; ++iteration) {
		drive("to robot arm");
		response = cbcp_client_send_command(cmd_load_bricks, NULL, 0, response_buffer, sizeof(response_buffer));
		if (!response.payload) {
			fprintf(stderr, "Could not send command.\n");
			exit(-1);
		}
		drive("to goal destination");
		if (iteration == 3) {
			response = cbcp_client_send_command(cmd_manager_log, (char *)"calzone", sizeof("calzone")-1, response_buffer, sizeof(response_buffer));
		}
		else {
			response = cbcp_client_send_command(cmd_manager_log, (void *)job_done_message, strlen(job_done_message), response_buffer, sizeof(response_buffer));
		}
		if (!response.payload) {
			fprintf(stderr, "Could not send command.\n");
			exit(-1);
		}
		printf("%s.\n", job_done_message);
	}
	return 0;
}

static void drive(const char *description) {
	int i;

	/* Simulate driving */

	printf("Driving (%s): 0%%\n", description);

	for (i = 1; i <= 5; ++i) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 200000;
		select(0, NULL, NULL, NULL, &tv);
		printf("Driving (%s): %d%%\n", description, i*100/5);
	}
	printf("\n");
}