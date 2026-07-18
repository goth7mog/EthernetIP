#include "enip/session.h"
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

typedef struct
{
    bool in_use;
    uint32_t handle;
    int fd;
} session_entry_t;

static session_entry_t g_sessions[ENIP_MAX_SESSIONS];
static bool g_seeded = false;

void session_table_init(void)
{
    for (size_t i = 0; i < ENIP_MAX_SESSIONS; i++)
    {
        g_sessions[i].in_use = false;
        g_sessions[i].handle = 0;
        g_sessions[i].fd = -1;
    }
    if (!g_seeded)
    {
        srand((unsigned)time(NULL));
        g_seeded = true;
    }
}

uint32_t session_register(int fd)
{
    for (size_t i = 0; i < ENIP_MAX_SESSIONS; i++)
    {
        if (!g_sessions[i].in_use)
        {
            /* Handle = random salt in the upper bits + slot index in the low
             * byte, so it is non-trivial to guess/collide but still cheap to
             * look up. Slot 0 is reserved so handle is never 0. */
            uint32_t salt = (uint32_t)rand();
            uint32_t handle = (salt << 8) | (uint32_t)(i + 1);
            if (handle == 0)
                handle = 1;

            g_sessions[i].in_use = true;
            g_sessions[i].handle = handle;
            g_sessions[i].fd = fd;
            return handle;
        }
    }
    return 0;
}

bool session_unregister(uint32_t handle, int fd)
{
    for (size_t i = 0; i < ENIP_MAX_SESSIONS; i++)
    {
        if (g_sessions[i].in_use && g_sessions[i].handle == handle && g_sessions[i].fd == fd)
        {
            g_sessions[i].in_use = false;
            g_sessions[i].handle = 0;
            g_sessions[i].fd = -1;
            return true;
        }
    }
    return false;
}

bool session_is_valid(uint32_t handle, int fd)
{
    if (handle == 0)
        return false;
    for (size_t i = 0; i < ENIP_MAX_SESSIONS; i++)
    {
        if (g_sessions[i].in_use && g_sessions[i].handle == handle && g_sessions[i].fd == fd)
        {
            return true;
        }
    }
    return false;
}

void session_drop_fd(int fd)
{
    for (size_t i = 0; i < ENIP_MAX_SESSIONS; i++)
    {
        if (g_sessions[i].in_use && g_sessions[i].fd == fd)
        {
            g_sessions[i].in_use = false;
            g_sessions[i].handle = 0;
            g_sessions[i].fd = -1;
        }
    }
}
