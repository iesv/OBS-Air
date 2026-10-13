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
 *
 *=================================================================
 * modified by fduncanh 2022, 2026
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "../compat.h"
#include <dns_sd.h>
#include "../dnssd.h"
#include "../dnssdint.h"
#include "../utils.h"

#include <ifaddrs.h>
#include <net/if.h>

typedef struct dnssd_private_s {
    TXTRecordRef raop_record;
    TXTRecordRef airplay_record;
    DNSServiceRef raop_service;
    DNSServiceRef airplay_service;
} dnssd_private_t;

void *dnssd_private_init(dnssd_t *public, int *error)
{
    (void)public;
    dnssd_private_t *private = calloc(1, sizeof(*private));
    if (private) {
        TXTRecordCreate(&private->raop_record, 0, NULL);
        TXTRecordCreate(&private->airplay_record, 0, NULL);
    }
    if (error) *error = private ? DNSSD_ERROR_NOERROR : DNSSD_ERROR_OUTOFMEM;
    return private;
}

void dnssd_private_destroy(void *opaque)
{
    dnssd_private_t *private = opaque;
    if (!private) return;
    if (private->raop_service) DNSServiceRefDeallocate(private->raop_service);
    if (private->airplay_service) DNSServiceRefDeallocate(private->airplay_service);
    TXTRecordDeallocate(&private->raop_record);
    TXTRecordDeallocate(&private->airplay_record);
    free(private);
}

/* This address is for the OBS status display. Bonjour advertises and manages
 * addresses on the system's network interfaces itself. */
uint32_t dnssd_get_ipv4(dnssd_t *public)
{
    (void)public;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in destination = {0}, local = {0};
    socklen_t size = sizeof(local);
    uint32_t address = 0;
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9);
    destination.sin_addr.s_addr = htonl(0x01010101);
    if (fd >= 0) {
        if (!connect(fd, (struct sockaddr *)&destination, sizeof(destination)) &&
            !getsockname(fd, (struct sockaddr *)&local, &size))
            address = local.sin_addr.s_addr;
        close(fd);
    }
    if (!address) {
        struct ifaddrs *interfaces = NULL;
        if (!getifaddrs(&interfaces)) {
            for (struct ifaddrs *item = interfaces; item; item = item->ifa_next) {
                if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET &&
                    (item->ifa_flags & IFF_UP) && !(item->ifa_flags & IFF_LOOPBACK)) {
                    address = ((struct sockaddr_in *)item->ifa_addr)->sin_addr.s_addr;
                    break;
                }
            }
            freeifaddrs(interfaces);
        }
    }
    return address;
}

int
dnssd_register_raop(dnssd_t *dnssd_public, unsigned short port)
{
    char servname[256];

    char features[22] = {0};

    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;
    DNSServiceFlags flags = 0;
    uint32_t interface_index = 0;


    snprintf(features, sizeof(features), "0x%X,0x%X", dnssd_public->features1, dnssd_public->features2);

    TXTRecordCreate(&dnssd->raop_record, 0, NULL);
    TXTRecordSetValue(&dnssd->raop_record, "ch", strlen(RAOP_CH), RAOP_CH);
    TXTRecordSetValue(&dnssd->raop_record, "cn", strlen(RAOP_CN), RAOP_CN);
    TXTRecordSetValue(&dnssd->raop_record, "da", strlen(RAOP_DA), RAOP_DA);
    TXTRecordSetValue(&dnssd->raop_record, "et", strlen(RAOP_ET), RAOP_ET);
    TXTRecordSetValue(&dnssd->raop_record, "vv", strlen(RAOP_VV), RAOP_VV);
    TXTRecordSetValue(&dnssd->raop_record, "ft", strlen(features), features);
    TXTRecordSetValue(&dnssd->raop_record, "am", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    TXTRecordSetValue(&dnssd->raop_record, "md", strlen(RAOP_MD), RAOP_MD);
    TXTRecordSetValue(&dnssd->raop_record, "rhd", strlen(RAOP_RHD), RAOP_RHD);
    switch (dnssd_public->pin_pw) {
    case 1:
        /* sf bit 3 0x08  means "pin required" according to https://openairplay.github.io/airplay-spec/status_flags.html  */
        TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("true"), "true");
        TXTRecordSetValue(&dnssd->raop_record, "sf", strlen("0x8c"), "0x8c");
        break;
    case 2:
    case 3:
        /* sf bit 7 0x80 means "password required" according to https://openairplay.github.io/airplay-spec/status_flags.html  */
        TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("true"), "true");
        TXTRecordSetValue(&dnssd->raop_record, "sf", strlen("0x84"), "0x84");
        break;
    default:
        TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("false"), "false");
        TXTRecordSetValue(&dnssd->raop_record, "sf", strlen(RAOP_SF), RAOP_SF);
        break;
    }
    TXTRecordSetValue(&dnssd->raop_record, "sr", strlen(RAOP_SR), RAOP_SR);
    TXTRecordSetValue(&dnssd->raop_record, "ss", strlen(RAOP_SS), RAOP_SS);
    TXTRecordSetValue(&dnssd->raop_record, "sv", strlen(RAOP_SV), RAOP_SV);
    TXTRecordSetValue(&dnssd->raop_record, "tp", strlen(RAOP_TP), RAOP_TP);
    TXTRecordSetValue(&dnssd->raop_record, "txtvers", strlen(RAOP_TXTVERS), RAOP_TXTVERS);
    TXTRecordSetValue(&dnssd->raop_record, "vs", strlen(RAOP_VS), RAOP_VS);
    TXTRecordSetValue(&dnssd->raop_record, "vn", strlen(RAOP_VN), RAOP_VN);
    TXTRecordSetValue(&dnssd->raop_record, "pk", strlen(dnssd_public->pk), dnssd_public->pk);

    /* Convert hardware address to string */
    if (utils_hwaddr_raop(servname, sizeof(servname), dnssd_public->hw_addr, dnssd_public->hw_addr_len) < 0) {
        return -1;
    }

    /* Check that we have bytes for 'hw@name' format */
    if (sizeof(servname) < strlen(servname) + 1 + dnssd_public->name_len + 1) {
        return -2;
    }

    strncat(servname, "@", sizeof(servname)-strlen(servname)-1);
    strncat(servname, dnssd_public->name, sizeof(servname)-strlen(servname)-1);

    /* Register the service */
    DNSServiceErrorType retval = DNSServiceRegister(&dnssd->raop_service, flags, interface_index,
                                                          servname, "_raop._tcp",
                                                          NULL, NULL,
                                                          htons(port),
                                                          TXTRecordGetLength(&dnssd->raop_record),
                                                          TXTRecordGetBytesPtr(&dnssd->raop_record),
                                                          NULL, NULL);

    return (int) retval;   /* error codes are listed in Apple's dns_sd.h */
}

int
dnssd_register_airplay(dnssd_t *dnssd_public, unsigned short port)
{
    char device_id[3 * MAX_HWADDR_LEN];
    char features[22] = {0};

    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;
    DNSServiceFlags flags = 0;
    uint32_t interface_index = 0;


    snprintf(features, sizeof(features), "0x%X,0x%X", dnssd_public->features1, dnssd_public->features2);

    /* Convert hardware address to string */
    if (utils_hwaddr_airplay(device_id, sizeof(device_id), dnssd_public->hw_addr, dnssd_public->hw_addr_len) < 0) {
        return -1;
    }

    // flags is a string representing a 20-bit flag (up to 3 hex digits)
    TXTRecordCreate(&dnssd->airplay_record, 0, NULL);
    TXTRecordSetValue(&dnssd->airplay_record, "deviceid", strlen(device_id), device_id);
    TXTRecordSetValue(&dnssd->airplay_record, "features", strlen(features), features);
    switch (dnssd_public->pin_pw) {
    case 1:   // display onscreen pin
        TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("true"), "true");
        TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;
    case 2:  // require password
    case 3:
        TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("true"), "true");
        TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;
    default:
        TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("false"), "false");
        TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;
    }
    TXTRecordSetValue(&dnssd->airplay_record, "model", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    TXTRecordSetValue(&dnssd->airplay_record, "pk", strlen(dnssd_public->pk), dnssd_public->pk);
    TXTRecordSetValue(&dnssd->airplay_record, "pi", strlen(AIRPLAY_PI), AIRPLAY_PI);
    TXTRecordSetValue(&dnssd->airplay_record, "srcvers", strlen(AIRPLAY_SRCVERS), AIRPLAY_SRCVERS);
    TXTRecordSetValue(&dnssd->airplay_record, "vv", strlen(AIRPLAY_VV), AIRPLAY_VV);

    /* Register the service */
    DNSServiceErrorType retval = DNSServiceRegister(&dnssd->airplay_service, flags, interface_index,
                                                           dnssd_public->name, "_airplay._tcp",
                                                           NULL, NULL,
                                                           htons(port),
                                                           TXTRecordGetLength(&dnssd->airplay_record),
                                                           TXTRecordGetBytesPtr(&dnssd->airplay_record),
                                                           NULL, NULL);

    return (int) retval;   /* error codes are listed in Apple's dns_sd.h */
}

const char *
dnssd_get_raop_txt(dnssd_t *dnssd_public, int *length)
{
    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;
    assert(length);

    *length = TXTRecordGetLength(&dnssd->raop_record);
    return TXTRecordGetBytesPtr(&dnssd->raop_record);
}

const char *
dnssd_get_airplay_txt(dnssd_t *dnssd_public, int *length)
{
    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;
    assert(length);

    *length = TXTRecordGetLength(&dnssd->airplay_record);
    return TXTRecordGetBytesPtr(&dnssd->airplay_record);
}

void
dnssd_unregister_raop(dnssd_t *dnssd_public)
{
    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;

    if (!dnssd->raop_service) {
        return;
    }

    /* Deallocate TXT record */
    TXTRecordDeallocate(&dnssd->raop_record);
    TXTRecordCreate(&dnssd->raop_record, 0, NULL);

    DNSServiceRefDeallocate(dnssd->raop_service);
    dnssd->raop_service = NULL;
}

void
dnssd_unregister_airplay(dnssd_t *dnssd_public)
{
    assert(dnssd_public);
    assert(dnssd_public->dnssd_private);
    dnssd_private_t *dnssd = (dnssd_private_t *) dnssd_public->dnssd_private;

    if (!dnssd->airplay_service) {
        return;
    }

    /* Deallocate TXT record */
    TXTRecordDeallocate(&dnssd->airplay_record);
    TXTRecordCreate(&dnssd->airplay_record, 0, NULL);

    DNSServiceRefDeallocate(dnssd->airplay_service);
    dnssd->airplay_service = NULL;
}

void dnssd_error_text(int *dnssd_error, const char *appname) {
    printf("*** dnssd_implementation: external, dns_sd.h\n");
    if (*dnssd_error == -65537) {
        printf("    No DNS-SD Server found (DNSServiceRegister call returned kDNSServiceErr_Unknown)\n");
    } else if (*dnssd_error == -65548) {
        printf("    DNSServiceRegister call returned kDNSServiceErr_NameConflict\n");
        printf("    Is another instance of %s running with the same DeviceID (MAC address) or using same network ports?\n",
	        appname);
        printf("    Use options -m ... and -p ... to allow multiple instances of %s to run concurrently\n", appname);
    } else {
        printf("dnssd_register_raop failed with error code %d\n"
               " mDNS Error codes are in range FFFE FF00 (-65792) to FFFE FFFF (-65537) "
	       "(see Apple's dns_sd.h)\n", *dnssd_error);
    }
}
