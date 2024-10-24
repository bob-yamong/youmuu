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
#include "structs.h"

int handle_event(void *ctx, void *data, size_t data_sz);

#endif