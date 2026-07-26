#include "enip/session.h"
#include "enip/cip_identity.h"
#include "enip/cip_tcpip_interface.h"
#include "enip/cip_assembly.h"
#include "enip/cip_connection_manager.h"
#include "enip/cip_safety.h"
#include "enip/server_tcp.h"
#include "enip/server_udp.h"

#include <sys/select.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

static volatile sig_atomic_t g_running = 1;
static void on_sigint(int sig)
{
    (void)sig;
    g_running = 0;
}

int main(void)
{
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN); /* a client closing mid-send() must not kill the server */

    session_table_init();
    cip_identity_register();
    cip_tcpip_interface_register();
    cip_assembly_register();
    cip_connection_manager_register();
    cip_safety_register();
    cip_safety_self_test(); /* prove the safety checking logic works before accepting connections */

    server_tcp_init();
    server_udp_init();

    printf("Assembly instances: output(O->T)=%d input(T->O)=%d config=%d\n",
           ASM_INSTANCE_OUTPUT, ASM_INSTANCE_INPUT, ASM_INSTANCE_CONFIG);
    printf("Safety I/O instances: output(O->T)=%d input(T->O)=%d "
           "(open via Connection Manager instance 2)\n",
           SAFETY_INSTANCE_OUTPUT, SAFETY_INSTANCE_INPUT);

    uint32_t counter = 0;
    while (g_running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        int max_fd = -1;
        server_tcp_collect_fds(&readfds, &max_fd);
        server_udp_collect_fds(&readfds, &max_fd);

        struct timeval tv = {.tv_sec = 0, .tv_usec = 10000}; /* 10ms poll for I/O timing */
        int n = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }
        if (n > 0)
        {
            server_tcp_handle_fds(&readfds);
            server_udp_handle_fds(&readfds);
        }

        /* Demo application logic: make the Input (T->O) assembly a free-
         * running counter so a connected scanner sees changing data. */
        counter++;
        uint8_t demo_input[ASM_INPUT_SIZE] = {
            (uint8_t)(counter & 0xFF), (uint8_t)((counter >> 8) & 0xFF),
            (uint8_t)((counter >> 16) & 0xFF), (uint8_t)((counter >> 24) & 0xFF)};
        cip_assembly_set_input(demo_input, sizeof demo_input);

        /* Periodic self-test ("proof test"): every ~500 loop iterations at
         * a 10ms poll interval, roughly every 5 seconds - mirrors a real
         * safety device re-checking that its own diagnostics still work,
         * not just checking incoming data. */
        if (counter % 500 == 0)
        {
            cip_safety_self_test();
        }

        server_udp_tick();
    }

    printf("Shutting down.\n");
    return 0;
}
