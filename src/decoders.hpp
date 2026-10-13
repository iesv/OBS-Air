#pragma once

#include <obs.h>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
}

namespace air {

struct VideoDecoder {
    AVCodecContext *context = nullptr;
    AVFrame *frame = nullptr;
    AVFrame *converted = nullptr;
    AVPacket *packet = nullptr;
    SwsContext *scale = nullptr;
    uint32_t width = 0, height = 0;

    ~VideoDecoder();
    bool open();
    void reset();
    bool decode(obs_source_t *source, const uint8_t *data, size_t size, uint64_t timestamp);
    bool output(obs_source_t *source, uint64_t timestamp);
};

struct AudioDecoder {
    AVCodecContext *context = nullptr;
    AVFrame *frame = nullptr;
    AVPacket *packet = nullptr;
    uint8_t compression = 0;
    std::vector<int16_t> pcm;

    ~AudioDecoder();
    bool open(uint8_t type);
    void reset();
    bool decode(obs_source_t *source, uint8_t type, const uint8_t *data, size_t size,
                uint64_t timestamp, double gain = 1.0);
    bool output(obs_source_t *source, uint64_t &timestamp, double gain = 1.0);
};

} // namespace air
