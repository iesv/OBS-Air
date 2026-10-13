extern "C" {
#include "compat.h"
}
#ifdef _WIN32
#include <iphlpapi.h>
#else
using SOCKET = int;
#endif
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>
#include "raop.h"
extern "C" {
#include "http_request.h"
#include "raop_buffer.h"
#include "plist/plist.h"
#include "mirror_buffer.h"
#include "pairing.h"
#include "crypto.h"
}
#include <openssl/evp.h>

static void video(void *, raop_ntp_t *, video_decode_struct *) {}
static void audio(void *, raop_ntp_t *, audio_decode_struct *) {}

static void check(bool condition, const char *message)
{
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(1);
    }
}

static SOCKET connect_client(unsigned short port)
{
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check(connect(client, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0,
          "protocol client connection failed");
#ifdef _WIN32
    DWORD timeout = 3000;
#else
    timeval timeout{3, 0};
#endif
    check(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout)) == 0,
          "protocol client timeout setup failed");
    return client;
}

static bool discovery_test(dnssd_t *discovery, unsigned short port)
{
#ifdef _WIN32
    const auto ip = dnssd_get_ipv4(discovery);
    DWORD interface_index = 0;
    if (GetBestInterface(0, &interface_index) != NO_ERROR)
        return false;
    ULONG size = 0;
    if (GetIpAddrTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER)
        return false;
    std::vector<unsigned char> table_bytes(size);
    auto *table = reinterpret_cast<MIB_IPADDRTABLE *>(table_bytes.data());
    if (GetIpAddrTable(table, &size, FALSE) != NO_ERROR)
        return false;
    bool on_default_interface = false;
    for (DWORD i = 0; i < table->dwNumEntries; ++i)
        on_default_interface |= table->table[i].dwIndex == interface_index && table->table[i].dwAddr == ip;
    if (!ip || !on_default_interface) {
        std::fputs("mDNS selected an address outside the default interface\n", stderr);
        return false;
    }

    SOCKET client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = ip;
    DWORD timeout = 2000;
    DWORD ttl = 255;
    if (bind(client, reinterpret_cast<sockaddr *>(&local), sizeof(local)) ||
        setsockopt(client, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char *>(&ip), sizeof(ip)) ||
        setsockopt(client, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl)) ||
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout))) {
        CLOSESOCKET(client);
        return false;
    }
    sockaddr_in multicast{};
    multicast.sin_family = AF_INET;
    multicast.sin_port = htons(5353);
    inet_pton(AF_INET, "224.0.0.251", &multicast.sin_addr);
    // Query this test instance so a running OBS receiver cannot answer first.
    const unsigned char query[] = {0,0,0,0,0,1,0,0,0,0,0,0,
        12,'O','B','S','-','A','i','r','-','t','e','s','t',
        8,'_','a','i','r','p','l','a','y',4,'_','t','c','p',5,'l','o','c','a','l',0,0,33,128,1};
    sendto(client, reinterpret_cast<const char *>(query), sizeof(query), 0,
           reinterpret_cast<sockaddr *>(&multicast), sizeof(multicast));
    unsigned char packet[1500]{};
    const int count = recv(client, reinterpret_cast<char *>(packet), sizeof(packet), 0);
    CLOSESOCKET(client);
    if (count < 12 || packet[2] != 0x84)
        return false;
    auto u16 = [&](size_t offset) { return (packet[offset] << 8) | packet[offset + 1]; };
    size_t offset = 12;
    bool address_found = false, service_found = false, text_found = false;
    for (int i = 0; i < u16(6); ++i) {
        while (offset < static_cast<size_t>(count) && packet[offset]) {
            if ((packet[offset] & 0xc0) == 0xc0) {
                ++offset;
                break;
            }
            offset += packet[offset] + 1;
        }
        ++offset;
        if (offset + 10 > static_cast<size_t>(count))
            return false;
        const int type = u16(offset);
        const int length = u16(offset + 8);
        offset += 10;
        if (offset + length > static_cast<size_t>(count))
            return false;
        if (type == 1 && length == 4)
            address_found |= memcmp(packet + offset, &ip, 4) == 0;
        if (type == 33 && length >= 6)
            service_found |= u16(offset + 4) == port;
        if (type == 16 && length > 0)
            text_found = true;
        offset += length;
    }
    in_addr address{};
    address.s_addr = ip;
    char printable[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &address, printable, sizeof(printable));
    std::printf("LAN multicast query: A=%s, SRV=%hu, TXT=%s\n", printable, port, text_found ? "present" : "missing");
    return address_found && service_found && text_found;
#else
    (void)port;
    int length = 0;
    const char *text = dnssd_get_airplay_txt(discovery, &length);
    for (int offset = 0; offset < length;) {
        const unsigned int size = static_cast<unsigned char>(text[offset++]);
        if (offset + size > static_cast<unsigned int>(length))
            return false;
        if (size > 9 && !memcmp(text + offset, "deviceid=", 9))
            return true;
        offset += size;
    }
    return false;
#endif
}

static std::string plist_request(const char *path, plist_t body)
{
    char *data = nullptr;
    uint32_t size = 0;
    plist_to_bin(body, &data, &size);
    std::string message = std::string("POST ") + path + " RTSP/1.0\r\nCSeq: 9\r\n"
        "Content-Type: application/x-apple-binary-plist\r\nContent-Length: " + std::to_string(size) + "\r\n\r\n";
    message.append(data, size);
    plist_mem_free(data);
    plist_free(body);
    return message;
}

static void test_audio_sequence(logger_t *logger)
{
    // Empty audio packets occupy sequence numbers without requesting resends.
    const unsigned char key[16]{}, iv[16]{};
    auto *buffer = raop_buffer_init(logger, key, iv);
    check(buffer != nullptr, "audio buffer initialization failed");
    unsigned char packet[16]{0x80, 0x60};
    const unsigned char marker[] = {0, 0x68, 0x34, 0};
    std::memcpy(packet + 12, marker, sizeof(marker));
    for (unsigned char sequence : {10, 11}) {
        packet[3] = sequence;
        check(raop_buffer_enqueue(buffer, packet, sizeof(packet), 1) == 1, "empty audio packet was not queued");
    }
    int resends = 0;
    raop_buffer_handle_resends(buffer, [](void *opaque, unsigned short, unsigned short) {
        ++*static_cast<int *>(opaque);
        return 0;
    }, &resends);
    check(resends == 0, "empty audio packets triggered a resend");
    for (unsigned short expected : {10, 11}) {
        unsigned int length = 0;
        uint32_t timestamp = 0;
        unsigned short sequence = 0;
        void *payload = raop_buffer_dequeue(buffer, &length, &timestamp, &sequence, 0);
        check(payload && length == sizeof(marker) && sequence == expected &&
              std::memcmp(payload, marker, sizeof(marker)) == 0, "empty audio sequence was not preserved");
        std::free(payload);
    }
    raop_buffer_destroy(buffer);
}

static void test_clocks(logger_t *logger)
{
    // Both timed and untimed clients must produce Unix-clock media timestamps.
    for (timing_protocol_t timing : {NTP, TP_NONE}) {
        raop_callbacks_t callbacks{};
        callbacks.video_process = video;
        callbacks.audio_process = audio;
        auto *clock = raop_ntp_init(logger, &callbacks, "127.0.0.1", 4, 9, &timing);
        check(clock != nullptr, "clock initialization failed");
        const uint64_t before = raop_ntp_get_local_time();
        const auto adjusted = raop_ntp_adjust_remote_timestamp_offset(clock, 1ULL << 32, true);
        const uint64_t timestamp = raop_ntp_timestamp_to_nano_seconds(clock, adjusted);
        const uint64_t local = raop_ntp_convert_remote_time(clock, timestamp);
        const uint64_t after = raop_ntp_get_local_time();
        check(local + 1000 >= before && local <= after && after - before <= 1000000000ULL,
              "media timestamp is outside the local clock interval");
        raop_ntp_destroy(clock);
    }
}

static void test_booleans()
{
    struct BooleanRead { plist_t node; uint8_t expected; };
    for (const auto &item : {BooleanRead{plist_new_bool(1), 1}, BooleanRead{plist_new_bool(0), 0},
                            BooleanRead{plist_new_uint(UINT64_MAX), 0xa5}, BooleanRead{plist_new_string("true"), 0xa5}}) {
        uint8_t value[] = {0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5};
        plist_get_bool_val(item.node, value);
        plist_free(item.node);
        check(value[0] == item.expected, "boolean value changed");
        for (size_t i = 1; i < sizeof(value); ++i)
            check(value[i] == 0xa5, "boolean getter overwrote adjacent bytes");
    }
}

static void test_requests()
{
    for (const char *protocol : {"HTTP/1.1", "RTSP/1.0"}) {
        auto *request = http_request_init();
        std::string message = std::string("GET /info ") + protocol + "\r\nX-Empty:\r\ncseq: 1\r\n\r\n";
        for (char byte : message) {
            check(http_request_add_data(request, &byte, 1) == 0 && !http_request_has_error(request),
                  "fragmented request parsing failed");
        }
        check(http_request_is_complete(request) && !strcmp(http_request_get_url(request), "/info") &&
              !strcmp(http_request_get_protocol(request), protocol), "request URL or protocol changed");
        const char *empty = http_request_get_header(request, "X-Empty");
        const char *sequence = http_request_get_header(request, "CSeq");
        check(empty && !empty[0] && sequence && !strcmp(sequence, "1"), "empty header changed the following CSeq");
        http_request_destroy(request);
    }
    for (const char *reply : {"HTTP/1.1 200 OK\r\n\r\n", "EVENT/1.0 200 OK\r\n\r\n"}) {
        auto *request = http_request_init();
        for (const char *byte = reply; *byte; ++byte) {
            check(http_request_add_data(request, byte, 1) == 0 && !http_request_has_error(request),
                  "fragmented reverse response parsing failed");
        }
        check(http_request_is_reverse(request), "reverse response was not recognized");
        http_request_destroy(request);
    }
    auto *oversized = http_request_init();
    check(oversized && http_request_add_data(oversized, "", 16 * 1024 * 1024 + 1) < 0 &&
          http_request_has_error(oversized), "oversized request was accepted");
    http_request_destroy(oversized);
}

static void test_pairing()
{
    int created = 0;
    auto *pairing = pairing_init_generate("02:11:22:33:44:55", "", &created);
    auto *session = pairing_session_init(pairing);
    auto *peer = x25519_key_generate();
    check(pairing && session && peer, "pairing fixture initialization failed");
    unsigned char peer_key[32]{}, signing_key[32]{}, server_key[32]{}, secret[32]{}, expected[32]{};
    x25519_key_get_raw(peer_key, peer);
    pairing_get_public_key(pairing, signing_key);
    const unsigned char invalid[32]{};
    check(pairing_session_handshake(session, invalid, signing_key) < 0, "invalid X25519 key was accepted");
    check(!pairing_get_ecdh_secret_key(session, secret), "failed handshake exposed a shared secret");
    for (int i = 0; i < 1000; ++i) {
        check(!pairing_session_handshake(session, peer_key, signing_key) &&
              !pairing_session_get_public_key(session, server_key) &&
              pairing_get_ecdh_secret_key(session, secret), "pairing retry failed");
        auto *server = x25519_key_from_raw(server_key);
        check(!x25519_derive_secret(expected, peer, server) && !std::memcmp(secret, expected, sizeof(secret)),
              "pairing secret does not match the client");
        x25519_key_destroy(server);
    }
    pairing_session_destroy(session);
    pairing_destroy(pairing);
    x25519_key_destroy(peer);
    std::puts("1,000 pairing retries and invalid key rejection passed");
}

static void test_mirror_cipher(logger_t *logger)
{
    // Split encrypted data at every AES boundary and re-key the same buffer.
    unsigned char audio_key[16]{}, key[64]{}, iv[64]{};
    auto derive = [&](const char *label, unsigned char *digest) {
        std::string input(label);
        input.append(reinterpret_cast<const char *>(audio_key), sizeof(audio_key));
        unsigned int size = 0;
        check(EVP_Digest(input.data(), input.size(), digest, &size, EVP_sha512(), nullptr) == 1 && size == 64,
              "mirror test key derivation failed");
    };
    derive("AirPlayStreamKey1", key);
    derive("AirPlayStreamIV1", iv);
    unsigned char plain[257], encrypted[sizeof(plain) + 16]{};
    for (size_t i = 0; i < sizeof(plain); ++i) plain[i] = static_cast<unsigned char>(i);
    auto *cipher = EVP_CIPHER_CTX_new();
    int size = 0;
    check(cipher && EVP_EncryptInit_ex(cipher, EVP_aes_128_ctr(), nullptr, key, iv) == 1 &&
          EVP_EncryptUpdate(cipher, encrypted, &size, plain, sizeof(plain)) == 1 && size == sizeof(plain),
          "mirror test encryption failed");
    EVP_CIPHER_CTX_free(cipher);
    auto *buffer = mirror_buffer_init(logger, audio_key);
    check(buffer != nullptr, "mirror buffer initialization failed");
    const uint64_t stream = 1;
    for (size_t chunk = 1; chunk <= 31; ++chunk) {
        mirror_buffer_init_aes(buffer, &stream);
        for (size_t offset = 0; offset < sizeof(plain); offset += chunk) {
            const size_t count = std::min(chunk, sizeof(plain) - offset);
            std::vector<unsigned char> input(encrypted + offset, encrypted + offset + count);
            std::vector<unsigned char> output(count + 1, 0xa5);
            mirror_buffer_decrypt(buffer, input.data(), output.data(), static_cast<int>(count));
            check(!std::memcmp(output.data(), plain + offset, count) && output.back() == 0xa5,
                  "fragmented mirror decryption changed data or overwrote the buffer");
        }
    }
    mirror_buffer_destroy(buffer);
}

static void test_receiver()
{
    for (int iteration = 0; iteration < 3; ++iteration) {
        raop_callbacks_t callbacks{};
        callbacks.video_process = video;
        callbacks.audio_process = audio;
        callbacks.conn_feedback = [](void *) {};
        callbacks.audio_set_client_volume = [](void *) { return 0.0; };
        auto *receiver = raop_init(&callbacks);
        check(receiver && raop_init2(receiver, 1, "02:11:22:33:44:55", "") >= 0, "receiver initialization failed");
        raop_set_log_callback(receiver, [](void *, int, const char *message) {
            std::fprintf(stderr, "%s\n", message);
        }, nullptr);
        int error = 0;
        const char mac[] = {2, 17, 34, 51, 68, 85};
        auto *discovery = dnssd_init("OBS-Air-test", 12, mac, 6, 0, &error);
        check(discovery && !error, "DNS-SD initialization failed");
        dnssd_set_airplay_features(discovery, 27, 0);
        raop_set_dnssd(receiver, discovery);
        unsigned short port = 0;
        check(raop_start_httpd(receiver, &port) >= 0 && port &&
              !dnssd_register_raop(discovery, port) && !dnssd_register_airplay(discovery, port),
              "receiver or DNS-SD registration failed");
        check(discovery_test(discovery, port), "service discovery response is invalid");
        struct Request { std::string message; const char *status; };
        std::vector<Request> requests = {
            {"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", "200 OK"},
            {"GET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n", "200 OK"},
            {"POST /feedback RTSP/1.0\r\nCSeq: 3\r\nContent-Length: 0\r\n\r\n", "200 OK"},
            {"POST /audioMode RTSP/1.0\r\nCSeq: 4\r\nContent-Length: 0\r\n\r\n", "400 Bad Request"},
            {"GET /info HTTP/1.1\r\nCSeq: 2\r\n\r\n", "200 OK"},
            {"GET /playback-info HTTP/1.1\r\n\r\n", "501 Not Implemented"}};
        requests.push_back({plist_request("/audioMode", plist_new_dict()), "400 Bad Request"});
        auto *mode = plist_new_dict();
        plist_dict_set_item(mode, "audioMode", plist_new_string("default"));
        requests.push_back({plist_request("/audioMode", mode), "200 OK"});
        requests.push_back({"POST /pair-pin-start RTSP/1.0\r\nCSeq: 5\r\nContent-Length: 0\r\n\r\n", "470 Client Authentication Failure"});
        requests.push_back({plist_request("/pair-setup-pin", plist_new_dict()), "470 Client Authentication Failure"});
        for (const auto &request : requests) {
            std::fprintf(stderr, "Testing %.*s\n", static_cast<int>(request.message.find("\r")), request.message.c_str());
            SOCKET client = connect_client(port);
            check(send(client, request.message.data(), static_cast<int>(request.message.size()), 0) ==
                  static_cast<int>(request.message.size()), "protocol request send failed");
            char response[4096]{};
            const int count = recv(client, response, sizeof(response) - 1, 0);
            CLOSESOCKET(client);
            if (count <= 0 || !strstr(response, request.status)) {
                std::fprintf(stderr, "Failed request: %s; response: %s\n", request.message.c_str(), response);
                check(false, "unexpected protocol response");
            }
        }
        // A peer leaving the request prefix incomplete must not block shutdown.
        SOCKET partial = connect_client(port);
        send(partial, "OP", 2, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        raop_stop_httpd(receiver);
        CLOSESOCKET(partial);
        raop_destroy(receiver);
        dnssd_destroy(discovery);
    }
}

int main()
{
#ifdef _WIN32
    WSADATA network{};
    check(WSAStartup(MAKEWORD(2, 2), &network) == 0, "Winsock initialization failed");
#endif
    auto *logger = logger_init();
    check(logger != nullptr, "logger initialization failed");
    test_audio_sequence(logger);
    test_clocks(logger);
    test_mirror_cipher(logger);
    logger_destroy(logger);
    test_booleans();
    test_pairing();
    test_requests();
    test_receiver();
#ifdef _WIN32
    WSACleanup();
#endif
    std::puts("Audio sequence, clocks, parser, disabled PIN and DNS-SD restart passed");
    return 0;
}
