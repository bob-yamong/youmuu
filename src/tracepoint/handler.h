#ifndef HANDLER_H
#define HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <asm/unistd_64.h>
#include "struct.h"
#include "db.h"
#include "buffer.h"
#include "user_struct.h"
#include "container_pid_id.h"

extern time_t boot_time;
extern EventBuffer event_buffer;

int handle_event(void *ctx, void *data, size_t data_sz);
void init_event_handlers(void);

#endif