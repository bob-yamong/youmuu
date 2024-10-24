#ifndef EVENT_H
#define EVENT_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include "syscalls.h"
#include "structs.h"

extern struct EventEntry event_table[];

__u32 hash(const char* str);
void init_event_table(void);
__u32 get_event_id(const char* event_str);

#endif