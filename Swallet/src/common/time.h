#ifndef TIME_H
#define TIME_H

#include <stdio.h>
#include <sys/time.h>

double get_time_ms();

#define TIME_START(name) double name = get_time_ms()
#define TIME_END(name, msg) printf("%s: %.3f ms\n", msg, get_time_ms() - name)

#endif