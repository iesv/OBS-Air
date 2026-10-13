// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the production receiver and video queue without an OBS compositor.
#include "../src/source.cpp"
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <openssl/evp.h>
extern "C" {
#include "fairplay.h"
#include "plist/plist.h"
}

static std::mutex pages_mutex;
static std::condition_variable pages_ready;
static std::vector<int> pages;

extern "C" void obs_source_output_video(obs_source_t *, const obs_source_frame *frame)
{
    if (!frame) return;
    std::lock_guard<std::mutex> lock(pages_mutex);
    pages.push_back((int(frame->data[0][0]) - 16) / 2);
    pages_ready.notify_one();
}
extern "C" void obs_source_output_audio(obs_source_t *, const obs_source_audio *) {}
extern "C" void obs_source_update_properties(obs_source_t *) {}
extern "C" const char *obs_module_text(const char *text) { return text; }

static void check(bool value, const char *message)
{
    if (!value) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(1);
    }
}

static int connect_to(unsigned short port)
{
    int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    check(connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "slide client connect failed");
#ifdef _WIN32
    DWORD timeout = 3000;
#else
    timeval timeout{3, 0};
#endif
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout)),
          "slide client timeout failed");
    return fd;
}

static void send_all(int fd, const unsigned char *data, size_t length)
{
    while (length) {
        int count = send(fd, reinterpret_cast<const char *>(data), static_cast<int>(length), 0);
        check(count > 0, "slide send failed");
        data += count;
        length -= count;
    }
}

static void request(int fd, const char *method, const char *path, const std::string &body)
{
    std::string message = std::string(method) + " " + path + " RTSP/1.0\r\nCSeq: 1\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body;
    send_all(fd, reinterpret_cast<const unsigned char *>(message.data()), message.size());
    std::string reply;
    size_t total = 0;
    do {
        char bytes[4096];
        int count = recv(fd, bytes, sizeof(bytes), 0);
        check(count > 0, "slide control response missing");
        reply.append(bytes, count);
        const size_t end = reply.find("\r\n\r\n");
        if (end != std::string::npos) {
            const size_t field = reply.find("Content-Length: ");
            total = end + 4 + (field < end ? std::stoul(reply.substr(field + 16)) : 0);
        }
    } while (!total || reply.size() < total);
    check(reply.find("200 OK") != std::string::npos, "slide control request rejected");
}

static std::string serialize(plist_t node)
{
    char *bytes = nullptr;
    uint32_t length = 0;
    plist_to_bin(node, &bytes, &length);
    check(bytes != nullptr, "slide plist encoding failed");
    std::string data(bytes, length);
    plist_mem_free(bytes);
    plist_free(node);
    return data;
}

static std::vector<unsigned char> nal_payload(const AVPacket *packet)
{
    // AirPlay carries big-endian NAL lengths instead of Annex B prefixes.
    std::vector<unsigned char> data;
    int start = -1;
    for (int i = 0; i <= packet->size; ++i) {
        int prefix = 0;
        if (i + 3 <= packet->size && !packet->data[i] && !packet->data[i + 1]) {
            if (packet->data[i + 2] == 1) prefix = 3;
            else if (i + 4 <= packet->size && !packet->data[i + 2] && packet->data[i + 3] == 1) prefix = 4;
        }
        if (prefix || i == packet->size) {
            if (start >= 0 && i > start) {
                unsigned int size = static_cast<unsigned int>(i - start);
                for (int shift : {24, 16, 8, 0}) data.push_back(static_cast<unsigned char>(size >> shift));
                data.insert(data.end(), packet->data + start, packet->data + i);
            }
            if (prefix) {
                i += prefix - 1;
                start = i + 1;
            }
        }
    }
    check(!data.empty(), "slide encoder did not output Annex B video");
    return data;
}

int main()
{
    Source receiver(nullptr);
    receiver.name = "OBS-Air-slide-test";
    receiver.device_id = "02:11:22:33:44:66";
    receiver.port = 11000;
    check(receiver.start(), "slide receiver startup failed");
    const int control = connect_to(11000);
    unsigned char handshake[164]{}, answer[32]{}, encrypted_key[72]{}, audio_key[16]{};
    handshake[4] = 3;
    request(control, "POST", "/fp-setup", std::string(reinterpret_cast<char *>(handshake), sizeof(handshake)));
    auto *logger = logger_init();
    auto *fairplay = fairplay_init(logger);
    check(fairplay && !fairplay_handshake(fairplay, handshake, answer) &&
          !fairplay_decrypt(fairplay, encrypted_key, audio_key), "slide session key failed");
    fairplay_destroy(fairplay);
    logger_destroy(logger);
    auto *setup = plist_new_dict();
    const char zero[16]{};
    plist_dict_set_item(setup, "deviceID", plist_new_string("02:11:22:33:44:55"));
    plist_dict_set_item(setup, "eiv", plist_new_data(zero, sizeof(zero)));
    plist_dict_set_item(setup, "ekey", plist_new_data(reinterpret_cast<char *>(encrypted_key), sizeof(encrypted_key)));
    plist_dict_set_item(setup, "timingProtocol", plist_new_string("None"));
    request(control, "SETUP", "/slides", serialize(setup));
    setup = plist_new_dict();
    auto *streams = plist_new_array(), *stream = plist_new_dict();
    plist_dict_set_item(stream, "type", plist_new_uint(110));
    plist_dict_set_item(stream, "streamConnectionID", plist_new_uint(1));
    plist_array_append_item(streams, stream);
    plist_dict_set_item(setup, "streams", streams);
    request(control, "SETUP", "/slides", serialize(setup));
    const int media = connect_to(11100);
    unsigned char key[64]{}, iv[64]{};
    auto derive = [&](const char *label, unsigned char *output) {
        std::string data(label);
        data.append(reinterpret_cast<char *>(audio_key), sizeof(audio_key));
        unsigned int size = 0;
        check(EVP_Digest(data.data(), data.size(), output, &size, EVP_sha512(), nullptr) == 1, "slide AES key failed");
    };
    derive("AirPlayStreamKey1", key);
    derive("AirPlayStreamIV1", iv);
    auto *cipher = EVP_CIPHER_CTX_new();
    check(cipher && EVP_EncryptInit_ex(cipher, EVP_aes_128_ctr(), nullptr, key, iv) == 1, "slide cipher failed");
    auto *encoder = avcodec_alloc_context3(avcodec_find_encoder_by_name("libx264"));
    check(encoder != nullptr, "slide encoder missing");
    encoder->width = 1920;
    encoder->height = 1080;
    encoder->pix_fmt = AV_PIX_FMT_YUV420P;
    encoder->time_base = {1, 5};
    encoder->gop_size = 30;
    encoder->max_b_frames = 0;
    encoder->thread_count = 1;
    AVDictionary *options = nullptr;
    av_dict_set(&options, "preset", "ultrafast", 0);
    av_dict_set(&options, "tune", "zerolatency", 0);
    av_dict_set(&options, "crf", "0", 0);
    check(avcodec_open2(encoder, encoder->codec, &options) == 0, "slide encoder open failed");
    av_dict_free(&options);
    auto *frame = av_frame_alloc();
    auto *packet = av_packet_alloc();
    check(frame && packet, "slide allocation failed");
    frame->format = encoder->pix_fmt;
    frame->width = encoder->width;
    frame->height = encoder->height;
    check(!av_frame_get_buffer(frame, 32), "slide frame allocation failed");
    const auto began = std::chrono::steady_clock::now();
    for (int page = 1; page <= 100; ++page) {
        check(!av_frame_make_writable(frame), "slide frame is not writable");
        for (int plane = 0; plane < 3; ++plane)
            std::memset(frame->data[plane], plane ? 128 : 16 + page * 2,
                        frame->linesize[plane] * (plane ? frame->height / 2 : frame->height));
        frame->pts = page;
        check(!avcodec_send_frame(encoder, frame) && !avcodec_receive_packet(encoder, packet), "slide encoding failed");
        const auto plain = nal_payload(packet);
        std::vector<unsigned char> payload(plain.size() + 16);
        int size = 0;
        check(EVP_EncryptUpdate(cipher, payload.data(), &size, plain.data(), static_cast<int>(plain.size())) == 1 &&
              size == static_cast<int>(plain.size()), "slide encryption failed");
        unsigned char header[128]{};
        for (int i = 0; i < 4; ++i) header[i] = static_cast<unsigned char>(size >> (i * 8));
        header[5] = packet->flags & AV_PKT_FLAG_KEY ? 0x10 : 0;
        const uint64_t timestamp = (100ULL << 32) + uint64_t(page) * (1ULL << 32) / 5;
        for (int i = 0; i < 8; ++i) header[8 + i] = static_cast<unsigned char>(timestamp >> (i * 8));
        send_all(media, header, sizeof(header));
        send_all(media, payload.data(), size);
        av_packet_unref(packet);
        // The sender keeps its own cadence while the receiver decodes independently.
        const auto next = began + std::chrono::milliseconds(page * 200);
        check(std::chrono::steady_clock::now() <= next, "slide sender missed its cadence");
        std::this_thread::sleep_until(next);
    }
    {
        std::unique_lock<std::mutex> lock(pages_mutex);
        check(pages_ready.wait_for(lock, std::chrono::seconds(2), [&] { return pages.size() >= 100; }),
              "slide missing or final frame delayed");
        check(pages.size() == 100, "slide count changed");
        for (int page = 1; page <= 100; ++page)
            check(pages[page - 1] == page, "slide identity or order changed");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    {
        std::lock_guard<std::mutex> lock(pages_mutex);
        check(pages.size() == 100 && pages.back() == 100, "final slide was not retained");
    }
    CLOSESOCKET(media);
    CLOSESOCKET(control);
    receiver.stop();
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&encoder);
    EVP_CIPHER_CTX_free(cipher);
    std::puts("100 encrypted 1080p loopback slides passed in order; final slide 100 required no following frame");
    return 0;
}
