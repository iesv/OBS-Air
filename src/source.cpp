// SPDX-License-Identifier: GPL-3.0-or-later
#include "decoders.hpp"
#include "media.hpp"
#include "compat.h"

#include <obs-module.h>
#include <util/platform.h>
#include <QRandomGenerator>
#include <QString>

#include <atomic>
#include <algorithm>
#include <condition_variable>
#include <cmath>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

extern "C" {
#include "raop.h"
#include "logger.h"
}

namespace {

// Only one receiver owns media ports in an OBS process.
std::atomic<bool> receiver_claimed{false};
constexpr int default_port = 7800;
constexpr size_t max_video_size = 16 * 1024 * 1024;
constexpr uint64_t max_queue_age = 150000000;

bool password_character(unsigned char character)
{
    return character >= 0x21 && character <= 0x7e;
}

bool password_modified(obs_properties_t *properties, obs_property_t *, obs_data_t *settings)
{
    // Property construction must not rewrite saved passwords.
    auto &initial = *static_cast<bool *>(obs_properties_get_param(properties));
    if (initial) {
        initial = false;
        return false;
    }
    const std::string original = obs_data_get_string(settings, "password");
    auto filtered = original;
    filtered.erase(std::remove_if(filtered.begin(), filtered.end(), [](unsigned char character) {
        return !password_character(character);
    }), filtered.end());
    if (filtered == original)
        return false; // Ordinary typing must not rebuild the input widget.
    obs_data_set_string(settings, "password", filtered.c_str());
    return true;
}

struct VideoPacket {
    std::vector<uint8_t> bytes;
    uint64_t timestamp = 0;
    uint64_t arrival = 0;
    bool reset = false;
    uint64_t generation = 0;
};

struct Source {
    obs_source_t *source;
    // Serialize UI restarts with OBS's deferred configuration updates.
    std::mutex lifecycle_mutex;
    raop_t *raop = nullptr;
    dnssd_t *discovery = nullptr;
    bool claimed = false;
    std::atomic<bool> stopping{true};
    std::atomic<int> connections{0};
    std::atomic<bool> mirroring{false};
    std::atomic<bool> audio_active{false};
    std::atomic<bool> audio_only{false};
    std::atomic<bool> follow_volume{false};
    std::atomic<double> device_gain{1.0};
    obs_hotkey_id restart_hotkey = OBS_INVALID_HOTKEY_ID;
    std::mutex clock_mutex;
    air::Clock clock;
    std::mutex audio_mutex;
    air::AudioDecoder audio;
    std::mutex queue_mutex;
    std::mutex output_mutex;
    std::atomic<uint64_t> generation{0};
    std::condition_variable wake;
    std::deque<VideoPacket> queue;
    std::vector<uint8_t> sps;
    std::vector<uint8_t> pps;
    size_t queued_bytes = 0;
    bool waiting_idr = true;
    std::thread video_thread;
    std::string name;
    std::string password;
    std::string device_id;
    std::mutex info_mutex;
    std::string client;
    std::atomic<uint64_t> dimensions{0};
    unsigned short failed_port = 0;
    bool failed_tcp = false;
    int socket_error = 0;
    std::atomic<const char *> error{nullptr};
    std::atomic<const char *> video_error{nullptr};
    std::atomic<const char *> audio_error{nullptr};
    std::atomic<uint32_t> ipv4{0};
    int resolution = 0;
    int fps = 60;
    std::atomic<int> port{default_port};
    std::atomic<bool> enabled{true};
    bool block_takeover = true;

    explicit Source(obs_source_t *value) : source(value) {}

    void set_decode_error(std::atomic<const char *> &slot, const char *message)
    {
        if (stopping || slot.exchange(message) == message)
            return;
        if (message)
            blog(LOG_WARNING, "[OBS-Air] %s", obs_module_text(message));
        obs_source_update_properties(source);
    }

    uint64_t timestamp(uint64_t remote)
    {
        std::lock_guard<std::mutex> lock(clock_mutex);
        return clock.map(remote, os_gettime_ns());
    }

    void reset_video()
    {
        // Lock output before queue and invalidate earlier frame generations.
        std::lock_guard<std::mutex> output_lock(output_mutex);
        std::lock_guard<std::mutex> lock(queue_mutex);
        ++generation;
        queue.clear();
        queued_bytes = 0;
        sps.clear();
        pps.clear();
        waiting_idr = true;
        dimensions = 0;
    }

    void reset_session()
    {
        std::lock_guard<std::mutex> audio_lock(audio_mutex);
        reset_video();
        {
            std::lock_guard<std::mutex> clock_lock(clock_mutex);
            clock.reset();
        }
        audio.reset();
        video_error = nullptr;
        audio_error = nullptr;
    }

    void video_loop()
    {
        air::VideoDecoder decoder;
        if (!decoder.open()) {
            blog(LOG_ERROR, "[OBS-Air] H.264 decoder could not be initialized");
            set_decode_error(error, "VideoDecoderError");
            return;
        }
        for (;;) {
            VideoPacket packet;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                wake.wait(lock, [&] { return stopping || !queue.empty(); });
                if (stopping)
                    return;
                packet = std::move(queue.front());
                queue.pop_front();
                queued_bytes -= packet.bytes.size();
            }
            if (packet.reset)
                decoder.reset();
            std::unique_lock<std::mutex> output_lock(output_mutex);
            if (packet.generation != generation || stopping)
                continue;
            const uint64_t begin = os_gettime_ns();
            const bool decoded = decoder.decode(source, packet.bytes.data(), packet.bytes.size(), packet.timestamp);
            const uint64_t size = (uint64_t(decoder.width) << 32) | decoder.height;
            const bool resized = decoded && size && dimensions.exchange(size) != size;
            if (!decoded) {
                std::lock_guard<std::mutex> lock(queue_mutex);
                queue.clear();
                queued_bytes = 0;
                waiting_idr = true;
            }
            const uint64_t elapsed = os_gettime_ns() - begin;
            output_lock.unlock();
            if (resized && !stopping)
                obs_source_update_properties(source);
            if (packet.generation == generation)
                set_decode_error(video_error, decoded ? nullptr : "VideoDecodeError");
            if (elapsed > 50000000)
                blog(LOG_DEBUG, "[OBS-Air] video decode took %.1f ms; queue wait %.1f ms",
                     elapsed / 1000000.0, (begin - packet.arrival) / 1000000.0);
        }
    }

    void stop()
    {
        stopping = true;
        wake.notify_all();
        // The protocol joins all media callbacks before their data is freed.
        if (raop)
            raop_stop_httpd(raop);
        if (video_thread.joinable())
            video_thread.join();
        if (discovery) {
            // Send discovery goodbyes before releasing Winsock.
            dnssd_destroy(discovery);
            discovery = nullptr;
        }
        if (raop) {
            raop_destroy(raop);
            raop = nullptr;
        }
        reset_session();
        connections = 0;
        mirroring = false;
        audio_active = audio_only = false;
        device_gain = 1.0;
        ipv4 = 0;
        {
            std::lock_guard<std::mutex> lock(info_mutex);
            client.clear();
        }
        if (claimed) {
            receiver_claimed = false;
            claimed = false;
        }
        obs_source_output_video(source, nullptr);
    }

    bool start();
};

void video_process(void *opaque, raop_ntp_t *, video_decode_struct *data)
{
    auto &s = *static_cast<Source *>(opaque);
    if (s.stopping || !data || !data->data || data->data_len <= 0 ||
        static_cast<size_t>(data->data_len) > max_video_size || data->is_h265)
        return;
    const uint64_t now = os_gettime_ns();
    const uint64_t timestamp = s.timestamp(data->ntp_time_local);
    auto info = air::inspect_h264(data->data, data->data_len);
    std::lock_guard<std::mutex> lock(s.queue_mutex);
    if (s.stopping)
        return;
    if (!info.sps.empty())
        s.sps = std::move(info.sps);
    if (!info.pps.empty())
        s.pps = std::move(info.pps);
    if (!s.queue.empty() && (now - s.queue.front().arrival > max_queue_age ||
                            s.queued_bytes + data->data_len > max_video_size)) {
        s.queue.clear();
        s.queued_bytes = 0;
        s.waiting_idr = true;
        blog(LOG_WARNING, "[OBS-Air] video backlog exceeded limit; recovering at next IDR");
    }
    // Resume at an IDR after discarding dependent frames.
    if (s.waiting_idr && !info.idr)
        return;
    const size_t prefix_size = s.waiting_idr ? s.sps.size() + s.pps.size() : 0;
    if (prefix_size > max_video_size - static_cast<size_t>(data->data_len))
        return;
    VideoPacket packet;
    packet.timestamp = timestamp;
    packet.arrival = now;
    packet.reset = s.waiting_idr;
    packet.generation = s.generation;
    if (packet.reset) {
        packet.bytes = s.sps;
        packet.bytes.insert(packet.bytes.end(), s.pps.begin(), s.pps.end());
    }
    packet.bytes.insert(packet.bytes.end(), data->data, data->data + data->data_len);
    s.waiting_idr = false;
    s.queued_bytes += packet.bytes.size();
    s.queue.push_back(std::move(packet));
    s.wake.notify_one();
}

void audio_process(void *opaque, raop_ntp_t *, audio_decode_struct *data)
{
    auto &s = *static_cast<Source *>(opaque);
    if (s.stopping || !data || !data->data || data->data_len <= 0 || data->data_len > 1024 * 1024)
        return;
    bool decoded;
    {
        std::lock_guard<std::mutex> lock(s.audio_mutex);
        if (s.stopping)
            return;
        const uint64_t timestamp = s.timestamp(data->ntp_time_local);
        decoded = s.audio.decode(s.source, data->ct, data->data, data->data_len, timestamp,
                                 s.follow_volume ? s.device_gain.load() : 1.0);
    }
    s.set_decode_error(s.audio_error, decoded ? nullptr : "AudioDecodeError");
}

void conn_init(void *opaque)
{
    auto &s = *static_cast<Source *>(opaque);
    if (s.connections.fetch_add(1) == 0) {
        s.reset_session();
        if (!s.stopping)
            obs_source_update_properties(s.source);
    }
}

void conn_destroy(void *opaque)
{
    auto &s = *static_cast<Source *>(opaque);
    if (s.connections.fetch_sub(1) == 1 && !s.stopping) {
        obs_source_update_properties(s.source);
    }
}

void conn_reset(void *opaque, int)
{
    auto &s = *static_cast<Source *>(opaque);
    if (!s.stopping)
        s.reset_session();
}

void video_reset(void *opaque, reset_type_t)
{
    conn_reset(opaque, 0);
}

void video_flush(void *opaque)
{
    auto &s = *static_cast<Source *>(opaque);
    if (!s.stopping && s.connections == 0)
        s.reset_video();
}

void audio_flush(void *opaque)
{
    auto &s = *static_cast<Source *>(opaque);
    std::lock_guard<std::mutex> lock(s.audio_mutex);
    s.audio.reset();
}

void mirror_running(void *opaque, bool running)
{
    auto &s = *static_cast<Source *>(opaque);
    s.mirroring = running;
    if (!running && !s.stopping)
        s.reset_video();
    if (!s.stopping)
        obs_source_update_properties(s.source);
}

void audio_running(void *opaque, bool running)
{
    auto &s = *static_cast<Source *>(opaque);
    s.audio_active = running;
    if (!s.stopping)
        obs_source_update_properties(s.source);
}

void audio_volume(void *opaque, float volume)
{
    if (!std::isfinite(volume))
        return;
    // AirPlay uses decibels; -30 dB and the -144 dB sentinel mean mute.
    static_cast<Source *>(opaque)->device_gain = volume <= -30.0f ? 0.0 :
        std::pow(10.0, std::min(volume, 0.0f) / 20.0);
}

void client_connected(void *opaque, const char *model, const char *name)
{
    auto &s = *static_cast<Source *>(opaque);
    s.device_gain = 1.0;
    s.audio_only = false;
    {
        std::lock_guard<std::mutex> lock(s.info_mutex);
        s.client = name && name[0] ? name : model && model[0] ? model : "AirPlay";
        s.failed_port = 0;
        const char *error = s.error.load();
        if (error && !strcmp(error, "PortError"))
            s.error = nullptr;
    }
    obs_source_update_properties(s.source);
    blog(LOG_INFO, "[OBS-Air] client connected: %s (%s)", name ? name : "", model ? model : "");
}

void client_disconnected(void *opaque)
{
    auto &s = *static_cast<Source *>(opaque);
    {
        std::lock_guard<std::mutex> lock(s.info_mutex);
        s.client.clear();
    }
    s.mirroring = false;
    s.audio_active = s.audio_only = false;
    s.device_gain = 1.0;
    s.reset_session();
    {
        std::lock_guard<std::mutex> lock(s.output_mutex);
        obs_source_output_video(s.source, nullptr);
    }
    if (!s.stopping)
        obs_source_update_properties(s.source);
}

void port_failure(void *opaque, const char *protocol, unsigned short port, int code)
{
    auto &s = *static_cast<Source *>(opaque);
    {
        std::lock_guard<std::mutex> lock(s.info_mutex);
        s.failed_port = port;
        s.failed_tcp = !strcmp(protocol, "TCP");
        s.socket_error = code;
        s.error = "PortError";
    }
    blog(LOG_WARNING, "[OBS-Air] Cannot bind %s %u (socket error %d)", protocol, port, code);
    if (!s.stopping)
        obs_source_update_properties(s.source);
}

int set_codec(void *, video_codec_t codec)
{
    return codec == VIDEO_CODEC_H264 ? 0 : -1;
}

void protocol_log(void *, int level, const char *text)
{
    blog(level <= LOGGER_ERR ? LOG_ERROR : level <= LOGGER_WARNING ? LOG_WARNING :
         level <= LOGGER_INFO ? LOG_INFO : LOG_DEBUG, "[OBS-Air/UxPlay] %s", text);
}

bool Source::start()
{
    error = nullptr;
    {
        std::lock_guard<std::mutex> lock(info_mutex);
        failed_port = 0;
    }
    if (port < 1024 || port > 65000) {
        error = "PortError";
        return false;
    }
    for (unsigned char character : password) {
        if (!password_character(character)) {
            error = "PasswordError";
            blog(LOG_WARNING, "[OBS-Air] %s", obs_module_text("PasswordError"));
            return false;
        }
    }
    bool expected = false;
    if (!receiver_claimed.compare_exchange_strong(expected, true)) {
        error = "AlreadyRunning";
        return false;
    }
    claimed = true;
    raop_callbacks_t callbacks{};
    callbacks.cls = this;
    callbacks.video_process = video_process;
    callbacks.audio_process = audio_process;
    callbacks.conn_init = conn_init;
    callbacks.conn_destroy = conn_destroy;
    callbacks.conn_reset = conn_reset;
    callbacks.video_reset = video_reset;
    callbacks.video_flush = video_flush;
    callbacks.audio_flush = audio_flush;
    callbacks.video_set_codec = set_codec;
    callbacks.video_pause = [](void *) {};
    callbacks.video_resume = [](void *) {};
    callbacks.conn_feedback = [](void *) {};
    callbacks.audio_set_client_volume = [](void *opaque) {
        const auto &s = *static_cast<Source *>(opaque);
        const double gain = s.follow_volume ? s.device_gain.load() : 1.0;
        return gain > 0.0 ? 20.0 * std::log10(gain) : -144.0;
    };
    callbacks.audio_set_volume = audio_volume;
    callbacks.audio_stream_running = audio_running;
    callbacks.audio_get_format = [](void *opaque, unsigned char *, unsigned short *, bool *screen, bool *, uint64_t *) {
        // Mode comes from SETUP metadata, so silence does not change it.
        static_cast<Source *>(opaque)->audio_only = !*screen;
    };
    callbacks.mirror_video_running = mirror_running;
    callbacks.client_connected = client_connected;
    callbacks.client_disconnected = client_disconnected;
    callbacks.port_error = port_failure;
    callbacks.passwd = [](void *opaque, int *length) {
        const auto &password = static_cast<Source *>(opaque)->password;
        *length = static_cast<int>(password.size());
        return password.c_str();
    };
    raop = raop_init(&callbacks);
    if (!raop) {
        error = "ProtocolError";
        stop();
        return false;
    }
    raop_set_log_callback(raop, protocol_log, nullptr);
    raop_set_log_level(raop, LOGGER_INFO);
    if (raop_init2(raop, !block_takeover, device_id.c_str(), "") != 0) {
        error = "ProtocolError";
        stop();
        return false;
    }
    // Automatic mode preserves the sender's dimensions and orientation.
    if (resolution) {
        raop_set_plist(raop, "width", resolution == 720 ? 1280 : 1920);
        raop_set_plist(raop, "height", resolution);
    }
    raop_set_plist(raop, "refreshRate", fps);
    raop_set_plist(raop, "maxFPS", fps);
    unsigned short tcp[2] = {static_cast<unsigned short>(port + 100), static_cast<unsigned short>(port)};
    unsigned short udp[3] = {static_cast<unsigned short>(port + 11),
                             static_cast<unsigned short>(port + 12), static_cast<unsigned short>(port + 13)};
    raop_set_tcp_ports(raop, tcp);
    raop_set_udp_ports(raop, udp);
    unsigned char mac[6]{};
    unsigned int octets[6]{};
    if (sscanf(device_id.c_str(), "%x:%x:%x:%x:%x:%x", &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5]) != 6) {
        error = "ProtocolError";
        stop();
        return false;
    }
    for (size_t i = 0; i < 6; ++i)
        mac[i] = static_cast<unsigned char>(octets[i]);
    int discovery_error = 0;
    discovery = dnssd_init(name.c_str(), static_cast<int>(name.size()),
                           reinterpret_cast<const char *>(mac), 6, password.empty() ? 0 : 2, &discovery_error);
    if (!discovery) {
#ifdef _WIN32
        error = "DiscoveryError";
#else
        error = "BonjourError";
#endif
        stop();
        return false;
    }
    dnssd_set_airplay_features(discovery, 0, 0);  // mirror mode, no HLS player
    dnssd_set_airplay_features(discovery, 4, 0);
    dnssd_set_airplay_features(discovery, 42, 0); // H.264 only
    // Fixed passwords use Digest authentication without legacy PIN pairing.
    dnssd_set_airplay_features(discovery, 27, 0);
    raop_set_dnssd(raop, discovery);
    stopping = false;
    video_thread = std::thread(&Source::video_loop, this);
    unsigned short actual_port = static_cast<unsigned short>(port);
    if (raop_start_httpd(raop, &actual_port) < 0 || actual_port != port) {
        port_failure(this, "TCP", static_cast<unsigned short>(port), SOCKET_GET_ERROR());
        stop();
        return false;
    }
    int registration_error = dnssd_register_raop(discovery, actual_port);
    if (!registration_error)
        registration_error = dnssd_register_airplay(discovery, actual_port);
    if (registration_error) {
        blog(LOG_ERROR, "[OBS-Air] DNS-SD registration failed: %d", registration_error);
#ifdef _WIN32
        error = "DiscoveryError";
#else
        error = "BonjourError";
#endif
        stop();
        return false;
    }
    in_addr address{};
    address.s_addr = dnssd_get_ipv4(discovery);
    ipv4 = address.s_addr;
    char ip_text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &address, ip_text, sizeof(ip_text));
    blog(LOG_INFO, "[OBS-Air] '%s' ready; receiver IP %s; TCP %d/%d; UDP %d-%d",
         name.c_str(), ip_text, port.load(), port + 100, port + 11, port + 13);
    return true;
}

void update(void *opaque, obs_data_t *settings)
{
    auto &s = *static_cast<Source *>(opaque);
    std::lock_guard<std::mutex> lifecycle_lock(s.lifecycle_mutex);
    QString name = QString::fromUtf8(obs_data_get_string(settings, "server_name")).trimmed();
    name.replace('.', '-');
    if (name.isEmpty())
        name = QStringLiteral("OBS-Air");
    while (name.toUtf8().size() > 40)
        name.chop(name.at(name.size() - 1).isLowSurrogate() ? 2 : 1);
    const auto new_name = name.toUtf8().toStdString();
    const std::string password = obs_data_get_string(settings, "password");
    const auto requested_resolution = obs_data_get_int(settings, "resolution");
    const int resolution = requested_resolution == 720 || requested_resolution == 1080 ?
                           static_cast<int>(requested_resolution) : 0;
    const int fps = obs_data_get_int(settings, "fps") == 30 ? 30 : 60;
    const auto requested_port = obs_data_get_int(settings, "port");
    const int port = requested_port >= 1024 && requested_port <= 65000 ?
                     static_cast<int>(requested_port) : 0;
    const bool enabled = obs_data_get_bool(settings, "enabled");
    const bool block_takeover = obs_data_get_bool(settings, "block_takeover");
    const bool unbuffered = obs_data_get_bool(settings, "low_latency");
    const bool changed = s.name != new_name || s.password != password || s.resolution != resolution || s.fps != fps ||
                         s.port != port || s.enabled != enabled || s.block_takeover != block_takeover;
    if (changed)
        s.stop(); // Join callbacks before replacing receiver settings.
    s.name = new_name;
    s.password = password;
    s.resolution = resolution;
    s.fps = fps;
    s.port = port;
    s.enabled = enabled;
    s.block_takeover = block_takeover;
    s.follow_volume = obs_data_get_bool(settings, "follow_volume");
    obs_source_set_async_unbuffered(s.source, unbuffered);
    if (changed) {
        if (enabled) {
            s.start();
        } else {
            s.error = nullptr;
        }
        obs_source_update_properties(s.source);
    }
}

bool restart_receiver(obs_properties_t *, obs_property_t *, void *opaque);

void *create(obs_data_t *settings, obs_source_t *source)
{
    auto *s = new Source(source);
    s->device_id = obs_data_get_string(settings, "device_id");
    if (s->device_id.empty()) {
        uint8_t mac[6];
        for (auto &byte : mac)
            byte = static_cast<uint8_t>(QRandomGenerator::system()->generate());
        mac[0] = (mac[0] & 0xfc) | 2;
        char text[18];
        snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        s->device_id = text;
        obs_data_set_string(settings, "device_id", text);
    }
    update(s, settings);
    s->restart_hotkey = obs_hotkey_register_source(source, "OBS-Air.Restart", obs_module_text("RestartReceiver"),
        [](void *opaque, obs_hotkey_id, obs_hotkey_t *, bool pressed) {
            if (pressed)
                restart_receiver(nullptr, nullptr, opaque);
        }, s);
    return s;
}

void destroy(void *opaque)
{
    auto *s = static_cast<Source *>(opaque);
    // Unregister before locking: a hotkey callback may be restarting.
    obs_hotkey_unregister(s->restart_hotkey);
    {
        std::lock_guard<std::mutex> lifecycle_lock(s->lifecycle_mutex);
        s->stop();
    }
    delete s;
}

void defaults(obs_data_t *settings)
{
    obs_data_set_default_string(settings, "server_name", "OBS-Air");
    obs_data_set_default_string(settings, "password", "");
    obs_data_set_default_int(settings, "resolution", 0);
    obs_data_set_default_int(settings, "fps", 60);
    obs_data_set_default_int(settings, "port", default_port);
    obs_data_set_default_bool(settings, "enabled", true);
    obs_data_set_default_bool(settings, "low_latency", true);
    obs_data_set_default_bool(settings, "block_takeover", true);
    obs_data_set_default_bool(settings, "follow_volume", false);
}

bool restart_receiver(obs_properties_t *, obs_property_t *, void *opaque)
{
    auto *s = static_cast<Source *>(opaque);
    if (!s)
        return false;
    std::lock_guard<std::mutex> lifecycle_lock(s->lifecycle_mutex);
    if (s->enabled) {
        // Restart with applied settings; pending edits remain unapplied.
        s->stop();
        s->start();
        obs_source_update_properties(s->source);
    }
    return false;
}

obs_properties_t *properties(void *opaque)
{
    auto *p = obs_properties_create_param(new bool(true), [](void *value) {
        delete static_cast<bool *>(value);
    });
    obs_properties_set_flags(p, OBS_PROPERTIES_DEFER_UPDATE);
    obs_properties_add_bool(p, "enabled", obs_module_text("Enabled"));
    obs_properties_add_text(p, "server_name", obs_module_text("ServerName"), OBS_TEXT_DEFAULT);
    auto *password = obs_properties_add_text(p, "password", obs_module_text("ConnectionPassword"), OBS_TEXT_DEFAULT);
    obs_property_set_long_description(password, obs_module_text("PasswordDescription"));
    obs_property_set_modified_callback(password, password_modified);
    auto *takeover = obs_properties_add_bool(p, "block_takeover", obs_module_text("BlockTakeover"));
    obs_property_set_long_description(takeover, obs_module_text("BlockTakeoverDescription"));
    auto *resolution = obs_properties_add_list(p, "resolution", obs_module_text("Resolution"),
                                               OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);
    obs_property_list_add_int(resolution, obs_module_text("NativeResolution"), 0);
    obs_property_list_add_int(resolution, "1920 × 1080", 1080);
    obs_property_list_add_int(resolution, "1280 × 720", 720);
    obs_property_set_long_description(resolution, obs_module_text("ResolutionDescription"));
    auto *fps = obs_properties_add_list(p, "fps", obs_module_text("FrameRate"),
                                       OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);
    obs_property_list_add_int(fps, "60", 60);
    obs_property_list_add_int(fps, "30", 30);
    obs_properties_add_bool(p, "low_latency", obs_module_text("LowLatency"));
    auto *volume = obs_properties_add_bool(p, "follow_volume", obs_module_text("FollowVolume"));
    obs_property_set_long_description(volume, obs_module_text("FollowVolumeDescription"));
    auto *port = obs_properties_add_int(p, "port", obs_module_text("Port"), 1024, 65000, 1);
    auto *s = static_cast<Source *>(opaque);
    const int base_port = s ? s->port.load() : default_port;
#ifdef _WIN32
    const char *port_description = obs_module_text("PortDescription");
#else
    const char *port_description = obs_module_text("PortDescriptionMac");
#endif
    const auto port_hint = QString::fromUtf8(port_description)
        .arg(base_port).arg(base_port + 100).arg(base_port + 11).arg(base_port + 13).toUtf8();
    obs_property_set_long_description(port, port_hint.constData());
    in_addr address{};
    address.s_addr = s && !s->stopping ? s->ipv4.load() : 0;
    char ipv4[INET_ADDRSTRLEN]{};
    if (address.s_addr)
        inet_ntop(AF_INET, &address, ipv4, sizeof(ipv4));
    const auto address_text = QString::fromUtf8(obs_module_text("ReceiverAddress"))
        .arg(address.s_addr ? ipv4 : obs_module_text("Unavailable"));
    const char *error = s ? s->error.load() : nullptr;
    const char *status = !s ? obs_module_text("Waiting") : error ? obs_module_text(error) :
                         s->stopping ? obs_module_text("Stopped") : s->mirroring ?
                         obs_module_text("Connected") : s->audio_active && s->audio_only ?
                         obs_module_text("AudioOnly") : obs_module_text("Waiting");
    auto status_text = QString::fromUtf8(status);
    QString connection_text;
    if (s) {
        std::lock_guard<std::mutex> lock(s->info_mutex);
        if (s->failed_port)
            status_text = QString::fromUtf8(obs_module_text("PortBindError"))
                .arg(s->failed_tcp ? "TCP" : "UDP").arg(s->failed_port).arg(s->socket_error);
        const uint64_t size = s->dimensions;
        if (!s->client.empty()) {
            if (!error && !s->stopping && !s->mirroring && !(s->audio_active && s->audio_only))
                status_text = QString::fromUtf8(obs_module_text("Connecting"));
            const auto size_text = size ? QStringLiteral("%1 × %2")
                .arg(static_cast<qulonglong>(size >> 32)).arg(static_cast<qulonglong>(size & 0xffffffff)) :
                                         QString::fromUtf8(obs_module_text("NoVideo"));
            connection_text = QString::fromUtf8(obs_module_text("DeviceInfo"))
                .arg(QString::fromUtf8(s->client.c_str()));
            if (!(s->audio_active && s->audio_only) || s->mirroring)
                connection_text += QStringLiteral(" · %1")
                    .arg(QString::fromUtf8(obs_module_text("VideoInfo")).arg(size_text));
        }
    }
    const auto receiver_status = QStringLiteral("%1 · %2")
        .arg(address_text, status_text);
    const auto information = connection_text.isEmpty() ? receiver_status.toUtf8() :
        QStringLiteral("<p style=\"margin-top:0;margin-bottom:0;\"><nobr>%1&nbsp;&nbsp;|&nbsp;&nbsp;%2</nobr></p>")
            .arg(receiver_status.toHtmlEscaped(), connection_text.toHtmlEscaped()).toUtf8();
    auto *status_property = obs_properties_add_text(p, "status", information.constData(), OBS_TEXT_INFO);
    obs_property_text_set_info_word_wrap(status_property, false);
    if (const char *message = s ? s->video_error.load() : nullptr)
        obs_properties_add_text(p, "video_error", obs_module_text(message), OBS_TEXT_INFO);
    if (const char *message = s ? s->audio_error.load() : nullptr)
        obs_properties_add_text(p, "audio_error", obs_module_text(message), OBS_TEXT_INFO);
    auto *restart = obs_properties_add_button2(p, "restart", obs_module_text("RestartReceiver"), restart_receiver, s);
    obs_property_set_enabled(restart, s && s->enabled);
    obs_property_set_long_description(restart, obs_module_text("RestartDescription"));
    auto plugin_text = QString::fromUtf8(obs_module_text("PluginInfo")).arg(OBS_AIR_VERSION).toHtmlEscaped();
    // OBS info labels open links through the default browser.
    plugin_text.replace(QStringLiteral("haliluya.net"),
                        QStringLiteral("<a href=\"https://haliluya.net/\">haliluya.net</a>"));
    const auto plugin_info = QStringLiteral("<p align=\"right\" style=\"margin-top:0;margin-bottom:0;\"><nobr>%1</nobr></p>")
        .arg(plugin_text).toUtf8();
    obs_properties_add_text(p, "plugin_info", plugin_info.constData(), OBS_TEXT_INFO);
    return p;
}

} // namespace

void register_air_source()
{
    obs_source_info info{};
    info.id = "obs_air_source";
    info.type = OBS_SOURCE_TYPE_INPUT;
    info.output_flags = OBS_SOURCE_ASYNC_VIDEO | OBS_SOURCE_AUDIO | OBS_SOURCE_DO_NOT_DUPLICATE;
    info.get_name = [](void *) { return obs_module_text("SourceName"); };
    info.create = create;
    info.destroy = destroy;
    info.update = update;
    info.get_defaults = defaults;
    info.get_properties = properties;
    info.icon_type = OBS_ICON_TYPE_MEDIA;
    obs_register_source(&info);
}
