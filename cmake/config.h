#pragma once
#define PACKAGE_VERSION "2.7.0"
#define PACKAGE_NAME "libplist"
#define PACKAGE_STRING "libplist 2.7.0"
#define HAVE_STRDUP 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#ifdef __APPLE__
#define HAVE_STRNDUP 1
#define HAVE_MEMMEM 1
#define HAVE_LOCALTIME_R 1
#define HAVE_GMTIME_R 1
#define HAVE_TIMEGM 1
#define HAVE_TM_TM_GMTOFF 1
#define HAVE_TM_TM_ZONE 1
#endif
#ifdef _MSC_VER
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#endif
