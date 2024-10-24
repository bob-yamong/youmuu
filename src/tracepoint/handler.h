#ifndef HANDLER_H
#define HANDLER_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/sysinfo.h>
#include "syscall.h"
#include "structs.h"
#include "event.h"

void get_task_info_str(const struct current_task *task, char *buf, size_t buf_size);
int handle_event(void *ctx, void *data, size_t data_sz);

#endif