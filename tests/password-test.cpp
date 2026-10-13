#include "compat.h"
#include "raop.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <openssl/evp.h>
extern "C" {
#include "plist/plist.h"
}
#ifndef _WIN32
using SOCKET = int;
#endif

static void check(bool success, const char *message)
{
    if (!success) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(1);
    }
}

static std::string md5(const std::string &text)
{
    unsigned char bytes[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    check(EVP_Digest(text.data(), text.size(), bytes, &size, EVP_md5(), nullptr) == 1, "client MD5 failed");
    char result[33]{};
    for (unsigned int i = 0; i < size; ++i)
        std::snprintf(result + i * 2, 3, "%02x", bytes[i]);
    return result;
}

static std::string authorization(const std::string &password, const std::string &nonce, bool qop = false)
{
    const auto ha1 = md5("iPhone:raop:" + password), ha2 = md5("SETUP:/test");
    const auto response = md5(ha1 + ":" + nonce + (qop ? ":00000001:client:auth:" : ":") + ha2);
    return "Digest username=\"iPhone\", realm=\"raop\", nonce=\"" + nonce +
        "\", uri=\"/test\", response=\"" + response + "\"" +
        (qop ? ", qop=auth, nc=00000001, cnonce=\"client\"" : "");
}

static std::string setup_body(bool mirror = false)
{
    auto *body = plist_new_dict();
    if (mirror) {
        auto *streams = plist_new_array(), *stream = plist_new_dict();
        plist_dict_set_item(stream, "type", plist_new_uint(110));
        plist_dict_set_item(stream, "streamConnectionID", plist_new_uint(1));
        plist_array_append_item(streams, stream);
        plist_dict_set_item(body, "streams", streams);
    } else {
    const char iv[16]{}, key[72]{};
    plist_dict_set_item(body, "deviceID", plist_new_string("02:11:22:33:44:55"));
    plist_dict_set_item(body, "eiv", plist_new_data(iv, sizeof(iv)));
    plist_dict_set_item(body, "ekey", plist_new_data(key, sizeof(key)));
    plist_dict_set_item(body, "timingProtocol", plist_new_string("NTP"));
    plist_dict_set_item(body, "timingPort", plist_new_uint(9));
    }
    char *bytes = nullptr;
    uint32_t size = 0;
    plist_to_bin(body, &bytes, &size);
    std::string result(bytes, size);
    plist_mem_free(bytes);
    plist_free(body);
    return result;
}

struct Client {
    SOCKET socket_fd;
    explicit Client(unsigned short port)
    {
        socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        check(connect(socket_fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "client connect failed");
#ifdef _WIN32
        DWORD timeout = 3000;
#else
        timeval timeout{3, 0};
#endif
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
    }
    ~Client() { CLOSESOCKET(socket_fd); }
    std::string request(const char *method, const char *path, const std::string &body = "",
                        const std::string &auth = "")
    {
        std::string data = std::string(method) + " " + path + " RTSP/1.0\r\nCSeq: 1\r\n";
        if (!auth.empty()) data += "Authorization: " + auth + "\r\n";
        data += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        check(send(socket_fd, data.data(), static_cast<int>(data.size()), 0) == static_cast<int>(data.size()), "request send failed");
        std::string response;
        for (;;) {
            char buffer[4096];
            int count = recv(socket_fd, buffer, sizeof(buffer), 0);
            check(count > 0, "response missing or connection closed unexpectedly");
            response.append(buffer, count);
            auto end = response.find("\r\n\r\n");
            if (end == std::string::npos) continue;
            size_t size = 0;
            auto length = response.find("Content-Length: ");
            if (length < end) size = std::stoul(response.substr(length + 16));
            if (response.size() >= end + 4 + size) return response;
        }
    }
    void fairplay()
    {
        std::string handshake(164, '\0');
        handshake[4] = 3;
        check(request("POST", "/fp-setup", handshake).find("200 OK") != std::string::npos, "FairPlay handshake failed");
    }
    bool closed()
    {
        char byte;
        int result = recv(socket_fd, &byte, 1, 0);
        int error = SOCKET_GET_ERROR();
        return !result || (result < 0 && (error == SOCKET_ERRORNAME(ECONNRESET) || error == SOCKET_ERRORNAME(ECONNABORTED)));
    }
};

static std::string challenge(const std::string &response)
{
    check(response.find("401 Unauthorized") != std::string::npos, "password challenge missing");
    auto begin = response.find("nonce=\"");
    check(begin != std::string::npos, "nonce missing");
    begin += 7;
    return response.substr(begin, response.find('"', begin) - begin);
}

struct State {
    std::string password;
    std::atomic<int> takeovers{0};
    std::atomic<int> password_warnings{0};
    std::atomic<int> takeover_warnings{0};
    std::atomic<bool> password_logged{false};
};

int main()
{
#ifdef _WIN32
    WSADATA network{};
    check(WSAStartup(MAKEWORD(2, 2), &network) == 0, "client Winsock initialization failed");
#endif
    unsigned short port = 7603;
    const auto body = setup_body();
    for (bool block_takeover : {false, true}) {
    for (const char *password : {"", "old-pass", "new-pass", ""}) {
        State state;
        state.password = password;
        raop_callbacks_t callbacks{};
        callbacks.cls = &state;
        callbacks.audio_process = [](void *, raop_ntp_t *, audio_decode_struct *) {};
        callbacks.video_process = [](void *, raop_ntp_t *, video_decode_struct *) {};
        callbacks.conn_feedback = [](void *) {};
        callbacks.audio_set_client_volume = [](void *) { return 0.0; };
        callbacks.passwd = [](void *opaque, int *length) {
            auto &password = static_cast<State *>(opaque)->password;
            *length = static_cast<int>(password.size());
            return password.c_str();
        };
        callbacks.video_reset = [](void *opaque, reset_type_t type) {
            if (type == RESET_TYPE_NOHOLD) ++static_cast<State *>(opaque)->takeovers;
        };
        auto *receiver = raop_init(&callbacks);
        raop_set_log_callback(receiver, [](void *opaque, int, const char *message) {
            auto &state = *static_cast<State *>(opaque);
            if (strstr(message, "Connection rejected: password authentication failed")) ++state.password_warnings;
            if (strstr(message, "Connection rejected: takeover blocked")) ++state.takeover_warnings;
            if (!state.password.empty() && strstr(message, state.password.c_str())) state.password_logged = true;
            std::fprintf(stderr, "%s\n", message);
        }, &state);
        check(raop_init2(receiver, !block_takeover, "02:11:22:33:44:55", "") == 0, "receiver init failed");
        unsigned short tcp[] = {7703, 7603}, udp[] = {7614, 7615, 7616};
        raop_set_tcp_ports(receiver, tcp);
        raop_set_udp_ports(receiver, udp);
        int error = 0;
        const char mac[] = {2, 17, 34, 51, 68, 85};
        auto *discovery = dnssd_init("OBS-Air-password-test", 21, mac, 6, state.password.empty() ? 0 : 2, &error);
        check(discovery && !error, "discovery init failed");
        dnssd_set_airplay_features(discovery, 27, 0);
        check(!(dnssd_get_airplay_features(discovery) & (1ULL << 27)), "legacy PIN pairing must not be advertised");
        raop_set_dnssd(receiver, discovery);
        check(raop_start_httpd(receiver, &port) > 0, "receiver restart failed");
        check(!dnssd_register_raop(discovery, port) && !dnssd_register_airplay(discovery, port), "discovery registration failed");
        Client first(port);
        int txt_size = 0;
        const char *txt = dnssd_get_airplay_txt(discovery, &txt_size);
        const auto expected_pw = state.password.empty() ? "pw=false" : "pw=true";
        bool pw_found = false;
        for (int offset = 0; offset < txt_size;) {
            int size = static_cast<unsigned char>(txt[offset++]);
            check(offset + size <= txt_size, "invalid AirPlay TXT record");
            pw_found |= std::string(txt + offset, size) == expected_pw;
            offset += size;
        }
        check(pw_found, "advertised password mode does not match settings");
        check(first.request("POST", "/pair-pin-start").find("470 Client Authentication Failure") != std::string::npos,
              "disabled PIN mode must not create a random code");
        first.fairplay();
        if (state.password.empty()) {
            check(first.request("SETUP", "/test", body).find("200 OK") != std::string::npos, "empty password must allow SETUP");
        } else {
            // Cached credentials without a current nonce still need a normal challenge.
            challenge(first.request("SETUP", "/test", body, authorization(state.password, "cached")));
            check(state.password_warnings == 0, "preemptive credentials were logged as a failure");
            auto nonce = challenge(first.request("SETUP", "/test", body));
            check(state.password_warnings == 0, "normal password challenge was logged as a failure");
            nonce = challenge(first.request("SETUP", "/test", body, authorization("wrong", nonce)));
            check(state.password_warnings == 1, "wrong password was not logged");
            nonce = challenge(first.request("SETUP", "/test", body, authorization("wrong", nonce)));
            check(state.password_warnings == 1, "repeated failure duplicated the log");
            check(state.takeovers == 0, "wrong password caused a takeover");
            check(first.request("SETUP", "/test", body, authorization(state.password, nonce)).find("200 OK") != std::string::npos,
                  "correct password SETUP failed");
        }
        check(first.request("SETUP", "/test", body).find("455") != std::string::npos, "duplicate key setup was accepted");
        check(first.request("SETUP", "/test", setup_body(true)).find("200 OK") != std::string::npos, "primary mirror setup failed");
        Client first_mirror(7703);
        Client second(port), pending(port);
        check(second.request("GET", "/info").find("200 OK") != std::string::npos, "discovery request failed");
        check(second.request("TEARDOWN", "/test").find("455") != std::string::npos, "unadmitted client control was allowed");
        second.fairplay();
        if (!state.password.empty()) {
            auto nonce = challenge(second.request("SETUP", "/test", body));
            challenge(pending.request("SETUP", "/test", body));
            check(state.password_warnings == 1, "new password challenge was logged as a failure");
            check(first.request("OPTIONS", "*").find("200 OK") != std::string::npos && state.takeovers == 0,
                  "unverified phone interrupted the current session");
            nonce = challenge(second.request("SETUP", "/test", body, authorization("wrong", nonce)));
            check(state.password_warnings == 2, "second client's failure was not logged separately");
            check(first.request("OPTIONS", "*").find("200 OK") != std::string::npos && state.takeovers == 0,
                  "wrong password interrupted the current session");
            if (state.password == "new-pass")
                nonce = challenge(second.request("SETUP", "/test", body, authorization("old-pass", nonce)));
            challenge(pending.request("SETUP", "/test", body));
            auto invalid = second.request("SETUP", "/test", "invalid", authorization(state.password, nonce, true));
            check(invalid.find("400") != std::string::npos && state.takeovers == 0,
                  "invalid SETUP interrupted the current session");
        }
        if (block_takeover) {
            check(second.request("SETUP", "/test", body).find("409") != std::string::npos, "protected receiver allowed takeover");
            check(state.takeover_warnings == 1, "blocked takeover was not logged");
            check(second.request("SETUP", "/test", body).find("409") != std::string::npos, "repeated takeover was accepted");
            check(state.takeover_warnings == 1, "repeated takeover duplicated the log");
            check(first.request("OPTIONS", "*").find("200 OK") != std::string::npos && state.takeovers == 0,
                  "protected primary connection was interrupted");
            raop_destroy(receiver);
            check(first.closed() && first_mirror.closed(), "protected receiver restart left connections open");
            dnssd_destroy(discovery);
            check(!state.password_logged, "password content appeared in the log");
            continue;
        }
        check(second.request("SETUP", "/test", body).find("200 OK") != std::string::npos, "authenticated replacement failed");
        check(state.takeovers == 1 && first.closed(), "verified replacement did not disconnect the previous client");
        check(first_mirror.closed(), "verified replacement did not close the old media socket");
        check(second.request("SETUP", "/test", setup_body(true)).find("200 OK") != std::string::npos, "replacement media port could not be rebound");
        Client second_mirror(7703);
        raop_destroy(receiver); // password changes join workers and drop authenticated connections
        check(second.closed(), "restart left an old authenticated connection open");
        check(second_mirror.closed(), "restart left an old media connection open");
        dnssd_destroy(discovery);
        check(state.takeover_warnings == 0 && !state.password_logged, "unexpected rejection or password content in log");
    }
    }
    std::puts("Passwords, rejection diagnostics, session protection, takeover and reconnect passed");
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
