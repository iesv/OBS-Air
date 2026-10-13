/*
 * Copyright (c) 2019 dsafa22 and 2014 Joakim Plate, modified by Florian Draschbacher,
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 *=================================================================
 * modified by fduncanh 2021-23
 */

// Some of the code in here comes from https://github.com/juhovh/shairplay/pull/25/files

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

#include "raop.h"
#include "threads.h"
#include "compat.h"
#include "netutils.h"
#include "byteutils.h"
#include "utils.h"

#define USEC_IN_NSECS   1000ULL
#define MSEC_IN_NSECS   1000000ULL
#define SECOND_IN_NSECS 1000000000ULL
#define SECOND_IN_USECS 1000000ULL

#define LINESIZE 120

#define RAOP_NTP_DATA_COUNT   8
#define RAOP_NTP_PHI_PPM   15e-6                   // 15 PPM
#define RAOP_NTP_R_RHO     0.001                   // packet precision  1ms
#define RAOP_NTP_S_RHO     0.001                   // system clock precision  1ms
#define RAOP_NTP_MAX_DIST  1.5                     // maximum allowed distance  1.5 secs
#define RAOP_NTP_MAX_DISP  16.0                    // maximum dispersion    16 secs.
#define RAOP_NTP_ALPHA     0.05                    // smoothing parameter  0.05

#define RAOP_NTP_CLOCK_BASE (2208988800ull << 32)

typedef struct raop_ntp_data_s {
    q32_32_t time; // The T4 timestamp  at time of ntp packet arrival
    double dispersion;
    double delay; // The round trip delay
    double offset; // The difference between (adjusted) remote and local wall clock time
    q32_32_t t1_sent;
    q32_32_t t3_recv;
} raop_ntp_data_t;

struct raop_ntp_s {
    logger_t *logger;
    raop_callbacks_t callbacks;
    thread_handle_t thread;
    mutex_handle_t run_mutex;
    mutex_handle_t join_mutex;
    mutex_handle_t wait_mutex;
    cond_handle_t wait_cond;

    raop_ntp_data_t data[RAOP_NTP_DATA_COUNT];
    int data_index;

    bool have_fixed_offset;
    q32_32_t fixed_offset;   // stored in Q32_32 fixed-point format

    // The clock sync params are periodically updated to the AirPlay client's NTP clock
    mutex_handle_t sync_params_mutex;
    int64_t sync_offset;
    bool is_synced;
    double sync_delay;
    uint64_t root_distance;
    bool kernel_timestamp_inconsistency_detected;
    uint64_t last_detection_time;

    kernel_timestamp_session_t *ntp_session;

    // Socket address of the AirPlay client
    struct sockaddr_storage remote_saddr;
    socklen_t remote_saddr_len;

    // The remote port of the NTP server on the AirPlay client
    unsigned short timing_rport;

    // The local port of the NTP client on the AirPlay server
    unsigned short timing_lport;

    timing_protocol_t time_protocol;
    bool client_time_received;

    uint64_t video_arrival_offset;

    /* MUTEX LOCKED VARIABLES START */
    /* These variables only edited mutex locked */
    int running;
    int joined;

    // UDP socket
    int tsock;
};

// Keep the upstream clock filter; use native timestamp reception where available.
static double ntp_diff_to_seconds(q32_32_t end, q32_32_t start) {
    return (double)(int64_t)(end - start) / 4294967296.0;
}

kernel_timestamp_session_t *kernel_timestamp_session_create(raop_ntp_t *ntp, int socket_fd) {
    kernel_timestamp_session_t *session = calloc(1, sizeof(*session));
    if (!session) return NULL;
    session->raop_ntp = ntp;
    session->sock_fd = socket_fd;
#ifndef _WIN32
    int enabled = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_TIMESTAMP, &enabled, sizeof(enabled));
#endif
    return session;
}

ssize_t kernel_timestamp_session_recv(kernel_timestamp_session_t *session, char *buffer, size_t size,
                                      void *address, int *address_len, uint64_t *kernel_time,
                                      uint64_t *clock_time) {
    if (kernel_time) *kernel_time = 0;
#ifndef _WIN32
    if (kernel_time) {
        struct sockaddr_storage remote;
        struct iovec iov = { buffer, size };
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct timeval))]; } control;
        struct msghdr message = {0};
        message.msg_name = &remote;
        message.msg_namelen = sizeof(remote);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        ssize_t count = recvmsg(session->sock_fd, &message, 0);
        if (count < 0) return count;
        if (clock_time) *clock_time = raop_ntp_get_local_time();
        if (!(message.msg_flags & MSG_CTRUNC) &&
            raop_ntp_get_local_time() >= session->suspend_kernel_timestamps_until) {
            for (struct cmsghdr *item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
                if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_TIMESTAMP &&
                    item->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
                    struct timeval stamp;
                    memcpy(&stamp, CMSG_DATA(item), sizeof(stamp));
                    *kernel_time = (uint64_t)stamp.tv_sec * SECOND_IN_NSECS +
                                   (uint64_t)stamp.tv_usec * USEC_IN_NSECS;
                    break;
                }
            }
        }
        if (address && address_len) {
            size_t length = (size_t)*address_len < message.msg_namelen ?
                            (size_t)*address_len : message.msg_namelen;
            memcpy(address, &remote, length);
            *address_len = (int)message.msg_namelen;
        }
        return count;
    }
#endif
    // Windows needs no network-adapter configuration for the clock fallback.
    socklen_t length = address && address_len ? (socklen_t)*address_len : 0;
    ssize_t count = recvfrom(session->sock_fd, buffer, (int)size, 0,
                             address, address ? &length : NULL);
    if (address && address_len) *address_len = (int)length;
    if (clock_time) *clock_time = count >= 0 ? raop_ntp_get_local_time() : 0;
    return count;
}

void kernel_timestamp_session_destroy(kernel_timestamp_session_t *ntp_session) {
    if (ntp_session) {
        CLOSESOCKET(ntp_session->sock_fd);
        free(ntp_session);
    }
}

/* for use in syncing audio before a first rtp_sync */
void raop_ntp_set_video_arrival_offset(raop_ntp_t* raop_ntp, const uint64_t *offset) {
    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    raop_ntp->video_arrival_offset = *offset;
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
}

uint64_t raop_ntp_get_video_arrival_offset(raop_ntp_t* raop_ntp) {
    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    uint64_t offset = raop_ntp->video_arrival_offset;
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
    return offset;
}

/*
 * Used for sorting the data array by delay
 */
static int
raop_ntp_compare(const void* av, const void* bv)
{
    const raop_ntp_data_t* a = (const raop_ntp_data_t*)av;
    const raop_ntp_data_t* b = (const raop_ntp_data_t*)bv;
    if (a->delay < b->delay) {
        return -1;
    } else if(a->delay > b->delay) {
        return 1;
    } else {
        return 0;
    }
}

static void
raop_ntp_close_socket(raop_ntp_t *raop_ntp)
{
    if (!raop_ntp) {
        return;
    }

    if (raop_ntp->ntp_session != NULL) {
        kernel_timestamp_session_destroy(raop_ntp->ntp_session);
        raop_ntp->ntp_session = NULL;
        raop_ntp->tsock = -1;
    } else if (raop_ntp->tsock != -1) {
        CLOSESOCKET(raop_ntp->tsock);
        raop_ntp->tsock = -1;
    }
}

static int
raop_ntp_parse_remote(raop_ntp_t *raop_ntp, const char *remote, int remote_addr_len)
{
    int family = AF_UNSPEC;
    assert(raop_ntp);
    if (remote_addr_len == 4) {
        family = AF_INET;
    } else if (remote_addr_len == 16) {
        family = AF_INET6;
    } else {
        return -1;
    }
    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp parse remote ip = %s", remote);
    int ret = netutils_parse_address(family, remote,
                                 &raop_ntp->remote_saddr,
                                 sizeof(raop_ntp->remote_saddr));
    if (ret < 0) {
        return -1;
    }
    raop_ntp->remote_saddr_len = ret;
    return 0;
}

raop_ntp_t *raop_ntp_init(logger_t *logger, raop_callbacks_t *callbacks, const char *remote,
                          int remote_addr_len, unsigned short timing_rport, timing_protocol_t *time_protocol) {
    assert(logger);
    assert(callbacks);

    raop_ntp_t *raop_ntp = calloc(1, sizeof(raop_ntp_t));
    if (!raop_ntp) {
        return NULL;
    }
    raop_ntp->time_protocol = *time_protocol;
    raop_ntp->logger = logger;
    memcpy(&raop_ntp->callbacks, callbacks, sizeof(raop_callbacks_t));
    raop_ntp->timing_rport = timing_rport;
    raop_ntp->tsock = -1;
    raop_ntp->client_time_received = false;
    raop_ntp->have_fixed_offset = false;
    raop_ntp->fixed_offset = 0ull;
    raop_ntp->kernel_timestamp_inconsistency_detected = false;
    raop_ntp->last_detection_time = 0ull;

    raop_ntp->video_arrival_offset = 0;

    if (raop_ntp_parse_remote(raop_ntp, remote, remote_addr_len) < 0) {
        free(raop_ntp);
        return NULL;
    }

    // Set port on the remote address struct
    ((struct sockaddr_in *) &raop_ntp->remote_saddr)->sin_port = htons(timing_rport);

    raop_ntp->running = 0;
    raop_ntp->joined = 1;

    raop_ntp->data_index = 0;
    for (int i = 0; i < RAOP_NTP_DATA_COUNT; ++i) {
        raop_ntp->data[i].offset     = 0ll;
        raop_ntp->data[i].delay      = RAOP_NTP_MAX_DISP;
        raop_ntp->data[i].dispersion = RAOP_NTP_MAX_DISP;
        raop_ntp->data[i].time      = 0ull;
        raop_ntp->data[i].t1_sent   = 0ull;
        raop_ntp->data[i].t3_recv   = 0ull;
    }


    raop_ntp->is_synced = false;
    raop_ntp->sync_offset = 0;

    MUTEX_CREATE(raop_ntp->run_mutex);
    MUTEX_CREATE(raop_ntp->join_mutex);
    MUTEX_CREATE(raop_ntp->wait_mutex);
    COND_CREATE(raop_ntp->wait_cond);
    MUTEX_CREATE(raop_ntp->sync_params_mutex);
    return raop_ntp;
}

void
raop_ntp_destroy(raop_ntp_t *raop_ntp)
{
    if (raop_ntp) {
        raop_ntp_stop(raop_ntp);
        MUTEX_DESTROY(raop_ntp->run_mutex);
        MUTEX_DESTROY(raop_ntp->join_mutex);
        MUTEX_DESTROY(raop_ntp->wait_mutex);
        COND_DESTROY(raop_ntp->wait_cond);
        MUTEX_DESTROY(raop_ntp->sync_params_mutex);
        free(raop_ntp);
    }
}

unsigned short raop_ntp_get_port(raop_ntp_t *raop_ntp) {
    return raop_ntp->timing_lport;
}

static int
raop_ntp_init_socket(raop_ntp_t *raop_ntp, int use_ipv6)
{
    assert(raop_ntp);
    unsigned short tport = raop_ntp->timing_lport;
    int tsock = netutils_init_socket(&tport, use_ipv6, 1);

    if (tsock == -1) {
        if (raop_ntp->callbacks.port_error)
            raop_ntp->callbacks.port_error(raop_ntp->callbacks.cls, "UDP", tport, SOCKET_GET_ERROR());
        goto sockets_cleanup;
    }

    raop_ntp->ntp_session = kernel_timestamp_session_create(raop_ntp, tsock);
    if (raop_ntp->ntp_session == NULL) {
        logger_log(raop_ntp->logger, LOGGER_ERR, "raop_ntp: Failed to allocate high-precision session context");
        goto sockets_cleanup;
    }

    // We're calling recvfrom without knowing whether there is any data, so we need a timeout
    uint32_t recv_timeout_msec = 300;
#ifdef _WIN32
    DWORD tv  = recv_timeout_msec;
#define CAST (char *)
#else
    struct timeval tv;
    tv.tv_sec = recv_timeout_msec / (uint32_t) 1000;
    tv.tv_usec = ((uint32_t) 1000) * (recv_timeout_msec % (uint32_t) 1000);
#define CAST
#endif
    if (setsockopt(tsock, SOL_SOCKET, SO_RCVTIMEO, CAST &tv, sizeof(tv)) < 0) {
        goto sockets_cleanup;
    }

    /* Set socket descriptors */
    raop_ntp->tsock = tsock;

    /* Set port values */
    raop_ntp->timing_lport = tport;
    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp local timing port socket %d port UDP %d", tsock, tport);
    return 0;

    sockets_cleanup:
    if (raop_ntp->ntp_session != NULL) {
        kernel_timestamp_session_destroy(raop_ntp->ntp_session);
        raop_ntp->ntp_session = NULL;
    } else if (tsock != -1) {
        // Fallback to protect if the handle crashed out before session instantiation
        CLOSESOCKET(tsock);
    }
    raop_ntp->tsock = -1;
    return -1;
}

static void
raop_ntp_flush_socket(int fd)
{
#ifdef _WIN32
    u_long bytes_available = 0;
#else
    int bytes_available = 0;
#endif
    while (IOCTLSOCKET(fd, FIONREAD, &bytes_available) == 0 && bytes_available > 0) {
        // We are guaranteed that we won't block, because bytes are available.
        // Read 1 byte. Extra bytes in the datagram will be discarded.
        char c;
        int result = recvfrom(fd, &c, sizeof(c), 0, NULL, NULL);
        if (result < 0) {
            break;
        }
    }
}

#define NTP_BURST_LIMIT RAOP_NTP_DATA_COUNT
static THREAD_RETVAL
raop_ntp_thread(void *arg) {
    raop_ntp_t *raop_ntp = arg;
    assert(raop_ntp);
    unsigned char response[128] = {0};
    int response_len = 0;
    unsigned char request[32] = {0x80, 0xd2, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    double inverse_two_pow_n[RAOP_NTP_DATA_COUNT] = { 1.0 };
    int den = 1;
    for (int i = 0; i < RAOP_NTP_DATA_COUNT; i++) {
        den *= 2;
        inverse_two_pow_n[i] /= ((double) den);
    }
    bool logger_debug = (logger_get_level(raop_ntp->logger) >= LOGGER_DEBUG);
    uint64_t recv_time = 0;

    bool duplicate_ntp_packet = false;
    bool bogus_ntp_packet = false;

    raop_ntp->data_index = 0;

    int ntpcount = 0;
    bool have_offset = false;

    /* these are NTP timestamps in Q32.32 form */
    q32_32_t t2_raw = 0, t3_raw = 0;
    q32_32_t t1 = 0, t2 = 0, t3 = 0, t4 = 0;

    while (1) {
        MUTEX_LOCK(raop_ntp->run_mutex);
        if (!raop_ntp->running) {
            MUTEX_UNLOCK(raop_ntp->run_mutex);
            break;
        }
        MUTEX_UNLOCK(raop_ntp->run_mutex);

        // Flush the socket in case a super delayed response arrived or something
        raop_ntp_flush_socket(raop_ntp->tsock);

        // Send request
        uint64_t send_time = raop_ntp_get_local_time();
        byteutils_put_ntp_timestamp(request, 24, send_time);
        int send_len = sendto(raop_ntp->tsock, (char *)request, sizeof(request), 0,
                              (struct sockaddr *) &raop_ntp->remote_saddr, raop_ntp->remote_saddr_len);
        if (send_len < 0) {
            int sock_err = SOCKET_GET_ERROR();
            logger_log(raop_ntp->logger, LOGGER_ERR, "raop_ntp error sending request. Error %d:%s",
                     sock_err, SOCKET_ERROR_STRING(sock_err));
        } else {
            ntpcount++;
            int pos = raop_ntp->data_index;
            raop_ntp->data[pos].t1_sent = (q32_32_t) byteutils_get_long_be(request, 24);
            if (logger_debug) {
                char *str = utils_data_to_string(request, sizeof(request), 16);
                logger_log(raop_ntp->logger, LOGGER_DEBUG, "\nraop_ntp request  type_t=%d packetlen = %d, send_time = %8.6f\n%s",
                           request[1] &~0x80, (int) sizeof(request), (double) send_time / SECOND_IN_NSECS, str);
                free(str);
            }

            // Read response
            uint64_t recv_time_kernel;   // kernel recv timestamp in microsecs * USEC_IN_NSECS
            uint64_t recv_time_clock;    // userspace recv timestamp in microsecs * USEC_IN_NSECS
            response_len = kernel_timestamp_session_recv(raop_ntp->ntp_session, (char *) response, sizeof(response),
                                                         NULL, NULL, &recv_time_kernel, &recv_time_clock);
            uint64_t localtime = raop_ntp_get_local_time();

            if (response_len < 32) {
                char time[30];
                ntp_timestamp_to_time(send_time, time, sizeof(time));
                if (response_len < 0) {
                    logger_log(raop_ntp->logger, LOGGER_DEBUG , "raop_ntp received timeout (request sent %s)", time);
                } else {
                    logger_log(raop_ntp->logger, LOGGER_ERR , "raop_ntp received truncated response (request sent %s, response_len %d < 32)", time, response_len);
                }
            } else {
                // The iOS client device sends its time in  seconds relative to an arbitrary Epoch (the last boot).
                // For a little bonus confusion, they add SECONDS_FROM_1900_TO_1970.
                // To avoid huge offsets, we adjust all remote timestamps (in raw Q32.32 fixed point format) by a fixed offset
                // raop_ntp->fixed offset, determined when the NTP thread receives its first client time signal.

                // Local time of the server when the NTP request packet left the server  (should equal t1_sent) */
                t1 = (q32_32_t) byteutils_get_long_be(response, 8);

                // Local timestamp of the client when the NTP request packet arrived at the client
                t2_raw = (q32_32_t) byteutils_get_long_be(response, 16);
                /* now adjust t2 to reset client epoch: don't include SECONDS_1900_TO_1970 */
                t2 = raop_ntp_adjust_remote_timestamp_offset(raop_ntp, t2_raw, false);

                // Local timestamp of the client when the response message left the client  (should not equal t3_prev)
                t3_raw = (q32_32_t) byteutils_get_long_be(response, 24);
                byteutils_put_long_be(request, 8, (uint32_t) t3_raw);   //this is returned to client as client_ref
                /* now adjust t3 to reset client epoch : don't include SECONDS_1900_TO_1970 */
                t3 = raop_ntp_adjust_remote_timestamp_offset(raop_ntp, t3_raw, false);

                // local timestamp of the server when the response message arrived at the server

                /* obtain and validate the recv time: use kernel recv timestamp if possible*/
                bool kernel_time = false;
                if (!recv_time_kernel && !recv_time_clock) {
                    recv_time = localtime;
                } else if (!recv_time_kernel) {
                    recv_time = recv_time_clock;
                } else {
                    /* sanity check on kernel timestamp */
                    bool sanity = ((int64_t) (recv_time_kernel - send_time) > 0  && (int64_t) (recv_time_clock - recv_time_kernel) > 0);
                    if (!sanity) {
                        // signal kernel timestamp inconsistency
                        MUTEX_LOCK(raop_ntp->sync_params_mutex);
                        raop_ntp->kernel_timestamp_inconsistency_detected = true;
                        raop_ntp->last_detection_time = localtime;
                        MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
                        recv_time = recv_time_clock;
                    } else if (!raop_ntp->kernel_timestamp_inconsistency_detected ||
                               ((int64_t) (localtime - raop_ntp->last_detection_time)) > (12ULL * SECOND_IN_NSECS)) {
                        recv_time = recv_time_kernel;
                        kernel_time = true;
                    } else {
                        recv_time = recv_time_clock;
                    }
                }

                byteutils_put_ntp_timestamp(request, 16, recv_time);
                t4 = (q32_32_t) byteutils_get_long_be(request, 16);

                if (logger_debug) {
                    char *str = utils_data_to_string(response, response_len, 16);
                    logger_log(raop_ntp->logger, LOGGER_DEBUG,
                               "raop_ntp response type_t=%d packetlen = %d, recv_time = %8.6f (%s)\n%s",
                               response[1] &~0x80, response_len, (double) recv_time / SECOND_IN_NSECS, kernel_time ? "kernel" : "clock", str);
                    free(str);
                    logger_log(raop_ntp->logger, LOGGER_DEBUG,
                               "t1 = %" PRIu64 "\nt2 = %" PRIu64 " (%" PRIu64 ")\nt3 = %" PRIu64 " (%" PRIu64 ")\nt4 = %" PRIu64 "\n" ,
                               t1, t2, t2_raw, t3, t3_raw, t4);
                }

                /* check for a valid t1 (last RAOP_NTP_DATA_COUNT values are available, if corresponding response is not yet received */
                bogus_ntp_packet = true;
                int pos0 = pos;
                for (int i = 0; i < RAOP_NTP_DATA_COUNT; i++) {
                    if (raop_ntp->data[pos0].t1_sent && raop_ntp->data[pos0].t1_sent == t1) {
                        raop_ntp->data[pos0].t1_sent = 0;  //per RFC 5905
                        bogus_ntp_packet = false;
                        break;
                    }
                    pos0++;
                    pos0 = pos0 % RAOP_NTP_DATA_COUNT;
                }
                if (bogus_ntp_packet) {
                    logger_log(raop_ntp->logger, LOGGER_INFO , "raop_ntp received NTP packet with invalid server ref: %"PRIu64, t1);
                }

                duplicate_ntp_packet = false;
                for (int i = 0; i < RAOP_NTP_DATA_COUNT; i++) {
                    if (raop_ntp->data[i].t3_recv == t3_raw) {
                        duplicate_ntp_packet = true;
                        break;
                    }
                }
                if (duplicate_ntp_packet) {
                    logger_log(raop_ntp->logger, LOGGER_INFO , "raop_ntp received NTP packet with duplicate t3: %"PRIu64, t3_raw);
                } else {
                    raop_ntp->data[pos].t3_recv = t3_raw;
                }

                if (!bogus_ntp_packet && !duplicate_ntp_packet) {
                    /* ntp metrics as seconds (as doubles) */
                    double total_time = ntp_diff_to_seconds(t4,t1);
                    double client_process_time = ntp_diff_to_seconds(t3,t2);
                    double client_to_server = ntp_diff_to_seconds(t2,t1);
                    double server_to_client = ntp_diff_to_seconds(t3,t4);
                    double raw_delay = total_time - client_process_time;
                    if (raw_delay < RAOP_NTP_S_RHO) {
                        raw_delay = RAOP_NTP_S_RHO; //per RFC 5905
                    }

                    raop_ntp->data[pos].time = t4;
                    raop_ntp->data[pos].offset = (client_to_server + server_to_client) /2.0;
                    raop_ntp->data[pos].delay  = raw_delay;
                    raop_ntp->data[pos].dispersion = RAOP_NTP_R_RHO + RAOP_NTP_S_RHO + (RAOP_NTP_PHI_PPM  * ntp_diff_to_seconds(t4, t1));
                    raop_ntp->data_index = (pos + 1) % RAOP_NTP_DATA_COUNT;

                    if (logger_debug) {
                        char table[RAOP_NTP_DATA_COUNT * LINESIZE] = { 0 };
                        char line[LINESIZE] = {0};
                        char *ptr = table;
                        size_t remain = sizeof(table);
                        for (int i = 0; i < RAOP_NTP_DATA_COUNT; i++) {
                            snprintf(line, (size_t) LINESIZE, "%d%c %20"PRIu64 " %9.6f %9.6f %12.9f \n", i, (i == pos ? '*' : ' '),
                                raop_ntp->data[i].time, raop_ntp->data[i].offset, raop_ntp->data[i].delay, raop_ntp->data[i].dispersion);
                                size_t len = strlen(line);
                            strncpy(ptr,line,remain);
                            remain -= len;
                            ptr += len;
                        }
                        logger_log(raop_ntp->logger, LOGGER_DEBUG , "      T4 (NTP Q32:32)      offset     delay   dispersion\n%s", table);
                    }

                    /* compute new estimate of client-server NTP offset */
                    int valid_count = 0;
                    raop_ntp_data_t data_sorted[RAOP_NTP_DATA_COUNT];

                    for(int i = 0; i < RAOP_NTP_DATA_COUNT; ++i) {
                        if (raop_ntp->data[i].delay == RAOP_NTP_MAX_DISP || raop_ntp->data[i].time == 0) {
                            continue;
                        }
                        double elapsed_seconds = ntp_diff_to_seconds(t4, raop_ntp->data[i].time);
                        double aged_dispersion = raop_ntp->data[i].dispersion + elapsed_seconds * RAOP_NTP_PHI_PPM;
                        if (aged_dispersion >= RAOP_NTP_MAX_DISP) {
                            raop_ntp->data[i].dispersion = RAOP_NTP_MAX_DISP;
                            continue;
                        }
                        raop_ntp->data[i].dispersion = aged_dispersion;
                        data_sorted[valid_count] = raop_ntp->data[i];
                        valid_count++;
                    }

                    if (valid_count > 1) {
                        qsort(data_sorted, valid_count, sizeof(data_sorted[0]), raop_ntp_compare);
                    }

                    if (valid_count > 0) {
                        double total_filter_dispersion = 0.0;
                        for (int i = 0; i < valid_count; ++i) {
                            total_filter_dispersion += data_sorted[i].dispersion * inverse_two_pow_n[i];
                        }
                        double root_distance = total_filter_dispersion + (data_sorted[0].delay * 0.5);

                        logger_log(raop_ntp->logger, LOGGER_DEBUG, "best NTP data: offset %10.6f, delay %10.6f",
                                   data_sorted[0].offset, data_sorted[0].delay);

                        int64_t sync_offset = 0;
                        bool is_synced;
                        if (root_distance > RAOP_NTP_MAX_DIST) {
                            is_synced = false;
                            sync_offset = (int64_t) (data_sorted[0].offset * 1e9);
                        } else {
                            double offset;
                            if (have_offset) {
                                offset = (double) (raop_ntp->sync_offset * 1e-9);
                                offset = ((1.0 - RAOP_NTP_ALPHA) * offset) +  (RAOP_NTP_ALPHA * data_sorted[0].offset);
                            } else {
                                offset = data_sorted[0].offset;
                            }
                            sync_offset = (int64_t) (offset * 1e9);
                            is_synced = true;
                        }
                        uint64_t root_distance_nsec = (uint64_t) (root_distance *1e9);
                        MUTEX_LOCK(raop_ntp->sync_params_mutex);
                        raop_ntp->is_synced = is_synced;
                        raop_ntp->sync_offset = sync_offset;
                        raop_ntp->root_distance = root_distance_nsec;
                        raop_ntp->sync_delay = data_sorted[0].delay;
                        MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
                        have_offset = true;
                        logger_log(raop_ntp->logger, LOGGER_DEBUG, "current client NTP offset (secs) = %9.6f, root_distance (secs) = %8.6f, is_synced = %s\n",
                                   (double) sync_offset / SECOND_IN_NSECS, (double) root_distance_nsec / SECOND_IN_NSECS, is_synced ? "TRUE" : "FALSE");
                    }
                }
            }
        }

        struct timespec wait_time;
        MUTEX_LOCK(raop_ntp->wait_mutex);
        clock_gettime(CLOCK_REALTIME, &wait_time);
        if (ntpcount > (int) NTP_BURST_LIMIT) {
            wait_time.tv_sec += 3;               // Sleep for 3 seconds
        } else {
            wait_time.tv_nsec += 250000000;   // Sleep for 0.25 seconds during initial NTP burst
            if (wait_time.tv_nsec >= 1000000000LL) {
                wait_time.tv_sec +=1;
                wait_time.tv_nsec -= 1000000000LL;
            }
        }
        pthread_cond_timedwait(&raop_ntp->wait_cond, &raop_ntp->wait_mutex, &wait_time);
        MUTEX_UNLOCK(raop_ntp->wait_mutex);
        ntpcount = ntpcount > NTP_BURST_LIMIT ? NTP_BURST_LIMIT : ntpcount;
    }

    // Ensure running reflects the actual state
    MUTEX_LOCK(raop_ntp->run_mutex);
    raop_ntp->running = false;
    MUTEX_UNLOCK(raop_ntp->run_mutex);

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp exiting thread");
    return 0;
}

int
raop_ntp_start(raop_ntp_t *raop_ntp, unsigned short *timing_lport)
{
    int use_ipv6 = 0;

    if (!raop_ntp || !timing_lport) {
        return -1;
    }

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp starting time");

    /* Fast path avoids taking the lifecycle lock from a worker callback. */
    MUTEX_LOCK(raop_ntp->run_mutex);
    if (raop_ntp->running || !raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        return 0;
    }
    MUTEX_UNLOCK(raop_ntp->run_mutex);

    MUTEX_LOCK(raop_ntp->join_mutex);
    MUTEX_LOCK(raop_ntp->run_mutex);
    if (raop_ntp->running || !raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        MUTEX_UNLOCK(raop_ntp->join_mutex);
        return 0;
    }

    raop_ntp->timing_lport = *timing_lport;

    /* Initialize ports and sockets */
    if (raop_ntp->remote_saddr.ss_family == AF_INET6) {
        use_ipv6 = 1;
    }
    if (raop_ntp_init_socket(raop_ntp, use_ipv6) < 0) {
        logger_log(raop_ntp->logger, LOGGER_ERR, "raop_ntp initializing timing socket failed");
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        MUTEX_UNLOCK(raop_ntp->join_mutex);
        return -1;
    }

    /* Create the thread and initialize running values */
    raop_ntp->running = 1;
    raop_ntp->joined = 0;

    int thread_error = pthread_create(&raop_ntp->thread, NULL,
                                      raop_ntp_thread, raop_ntp);
    if (thread_error != 0) {
        raop_ntp->running = 0;
        raop_ntp->joined = 1;
        raop_ntp_close_socket(raop_ntp);
        logger_log(raop_ntp->logger, LOGGER_ERR,
                   "raop_ntp failed to create worker thread: %s",
                   strerror(thread_error));
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        MUTEX_UNLOCK(raop_ntp->join_mutex);
        return -1;
    }

    *timing_lport = raop_ntp->timing_lport;
    MUTEX_UNLOCK(raop_ntp->run_mutex);
    MUTEX_UNLOCK(raop_ntp->join_mutex);
    return 0;
}

void
raop_ntp_stop(raop_ntp_t *raop_ntp)
{
    assert(raop_ntp);

    thread_handle_t thread;
    int self_thread;

    /* Set the stop flag before taking the join lock so a worker callback can
     * return even when another owner is already joining this thread. */
    MUTEX_LOCK(raop_ntp->run_mutex);
    if (raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        return;
    }
    raop_ntp->running = 0;
    thread = raop_ntp->thread;
    self_thread = pthread_equal(pthread_self(), thread);
    MUTEX_UNLOCK(raop_ntp->run_mutex);

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp stopping time thread");

    if (self_thread) {
        logger_log(raop_ntp->logger, LOGGER_DEBUG,
                   "raop_ntp stop requested by worker; deferring join to owner");
        return;
    }

    MUTEX_LOCK(raop_ntp->wait_mutex);
    COND_SIGNAL(raop_ntp->wait_cond);
    MUTEX_UNLOCK(raop_ntp->wait_mutex);

    MUTEX_LOCK(raop_ntp->join_mutex);
    MUTEX_LOCK(raop_ntp->run_mutex);
    if (raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        MUTEX_UNLOCK(raop_ntp->join_mutex);
        return;
    }
    raop_ntp->running = 0;
    thread = raop_ntp->thread;
    MUTEX_UNLOCK(raop_ntp->run_mutex);

    int join_error = pthread_join(thread, NULL);
    if (join_error != 0) {
        logger_log(raop_ntp->logger, LOGGER_ERR,
                   "raop_ntp failed to join worker thread: %s",
                   strerror(join_error));
        MUTEX_UNLOCK(raop_ntp->join_mutex);
        return;
    }

    raop_ntp_close_socket(raop_ntp);

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp stopped time thread");

    /* Mark thread as joined */
    MUTEX_LOCK(raop_ntp->run_mutex);
    raop_ntp->joined = 1;
    MUTEX_UNLOCK(raop_ntp->run_mutex);
    MUTEX_UNLOCK(raop_ntp->join_mutex);
}

void raop_ntp_get_sync_params(raop_ntp_t *raop_ntp, int64_t *offset_ns, double *delay_sec) {
    if (!raop_ntp) return;

    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    if (offset_ns) {
        *offset_ns = raop_ntp->sync_offset;
    }
    if (delay_sec) {
        *delay_sec = raop_ntp->sync_delay;
    }
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
}

/**
 * Converts from a little endian ntp timestamp to nano seconds since the Unix epoch.
 * Does the same thing as byteutils_get_ntp_timestamp, except its input is an uint64_t
 * and expected to already be in little endian.
 * Please note this just converts to a different representation, the clock remains the
 * same.
 */

uint64_t raop_ntp_timestamp_to_nano_seconds(raop_ntp_t *raop_ntp, uint64_t timestamp) {
    uint64_t seconds = (timestamp >> 32);
    // The fixed reference uses NTP's epoch even when the client omits timing packets.
    seconds -= SECONDS_FROM_1900_TO_1970;
    uint64_t fraction = (timestamp & 0xffffffff);
    return (seconds * SECOND_IN_NSECS) + ((fraction * SECOND_IN_NSECS) >> 32);
}
/**
 * Returns the current time in nano seconds according to the local wall clock.
 * The system Unix time is used as the local wall clock.
 */
uint64_t raop_ntp_get_local_time() {
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return ((uint64_t) time.tv_nsec) + (uint64_t) time.tv_sec * SECOND_IN_NSECS;
}

/**
 * Returns the current time in nano seconds according to the remote wall clock.
 */
uint64_t raop_ntp_get_remote_time(raop_ntp_t *raop_ntp) {
    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    if (!raop_ntp->client_time_received) {
        MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
        return 0;
    }
    int64_t offset = raop_ntp->sync_offset;
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
    return (uint64_t) (((int64_t) raop_ntp_get_local_time()) + offset);
}

/**
 * Returns the local wall clock time in nano seconds for the given point in remote clock time
 */
uint64_t raop_ntp_convert_remote_time(raop_ntp_t *raop_ntp, uint64_t remote_time) {
    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    if (!raop_ntp->client_time_received) {
        MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
        return 0;
    }
    int64_t offset = raop_ntp->sync_offset;
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
    return (uint64_t) (((int64_t) remote_time) - offset);
}

/**
 * Returns the remote wall clock time in nano seconds for the given point in local clock time
 */
uint64_t raop_ntp_convert_local_time(raop_ntp_t *raop_ntp, uint64_t local_time) {
    MUTEX_LOCK(raop_ntp->sync_params_mutex);
    if (!raop_ntp->client_time_received) {
        MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
        return 0;
    }
    int64_t offset = raop_ntp->sync_offset;
    MUTEX_UNLOCK(raop_ntp->sync_params_mutex);
    return (uint64_t) (((int64_t) local_time) + offset);
}

// adjust a client raw timestamp by the fixed Q32.32 offset
q32_32_t raop_ntp_adjust_remote_timestamp_offset(raop_ntp_t *ntp, q32_32_t timestamp, bool add_epoch) {
    if (add_epoch) timestamp += RAOP_NTP_CLOCK_BASE;
    // Audio and video share one fixed reference; unsigned Q32.32 arithmetic wraps safely.
    MUTEX_LOCK(ntp->sync_params_mutex);
    if (!ntp->have_fixed_offset) {
        unsigned char reference[8];
        byteutils_put_ntp_timestamp(reference, 0, raop_ntp_get_local_time());
        ntp->fixed_offset = byteutils_get_long_be(reference, 0) - timestamp;
        ntp->have_fixed_offset = true;
        ntp->client_time_received = true;
    }
    q32_32_t adjusted = timestamp + ntp->fixed_offset;
    MUTEX_UNLOCK(ntp->sync_params_mutex);
    return adjusted;
}
