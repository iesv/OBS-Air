/**
 *  Copyright (C) 2011-2012  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#ifndef COMPAT_H
#define COMPAT_H

#if defined(WIN32)
#ifndef WIN32_LEAN_AND_MEAN
 #define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#include <windows.h>
#if defined(_MSC_VER)
#include <time.h>
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#define strdup _strdup
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
static __inline int clock_gettime(int clock_id, struct timespec *time)
{
    FILETIME filetime;
    ULARGE_INTEGER ticks;
    (void)clock_id;
    GetSystemTimePreciseAsFileTime(&filetime);
    ticks.LowPart = filetime.dwLowDateTime;
    ticks.HighPart = filetime.dwHighDateTime;
    ticks.QuadPart -= 116444736000000000ULL;
    time->tv_sec = (time_t)(ticks.QuadPart / 10000000ULL);
    time->tv_nsec = (long)((ticks.QuadPart % 10000000ULL) * 100);
    return 0;
}
#endif
#endif
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#endif

#include "sockets.h"
#include "threads.h"

#endif
