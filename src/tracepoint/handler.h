#ifndef HANDLER_H
#define HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <time.h>
#include <iostream>
#include <sys/sysinfo.h>
#include <asm/unistd_64.h>
#include <algorithm> 

#include "struct.h"
#include "user_struct.h"
#include "EventLogger.h"
#include "container_info.h"

extern time_t boot_time;

int handle_event(void *ctx, void *data, size_t data_sz);
void init_event_handlers(void);

#endif