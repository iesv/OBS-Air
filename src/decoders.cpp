// SPDX-License-Identifier: GPL-3.0-or-later
#include "decoders.hpp"

#include <algorithm>
#include <climits>
#include <cstring>

extern "C" {
#include <libavutil/imgutils.h>
}

namespace air {

template<typename T>
static void attenuate(uint8_t *data, size_t count, double gain)
{
    auto *samples = reinterpret_cast<T *>(data);
    for (size_t i = 0; i < count; ++i)
        samples[i] = static_cast<T>(samples[i] * gain);
}

static bool codec_error(const char *operation, int error)
{
    char text[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(error, text, sizeof(text));
    blog(LOG_WARNING, "[OBS-Air] %s: %s", operation, text);
    return false;
}

VideoDecoder::~VideoDecoder()
{
    sws_freeContext(scale);
    av_packet_free(&packet);
    av_frame_free(&converted);
    av_frame_free(&frame);
    avcodec_free_context(&context);
}

bool VideoDecoder::open()
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec)
        return false;
    context = avcodec_alloc_context3(codec);
    frame = av_frame_alloc();
    converted = av_frame_alloc();
    packet = av_packet_alloc();
    if (!context || !frame || !converted || !packet)
        return false;
    context->pkt_timebase = {1, 1000000000};
    context->thread_count = 2;
    context->thread_type = FF_THREAD_SLICE;
    context->flags |= AV_CODEC_FLAG_LOW_DELAY;
    context->max_pixels = 8192LL * 8192;
    return avcodec_open2(context, codec, nullptr) >= 0;
}

void VideoDecoder::reset()
{
    width = height = 0;
    if (context)
        avcodec_flush_buffers(context);
}

bool VideoDecoder::output(obs_source_t *source, uint64_t timestamp)
{
    if (frame->width <= 0 || frame->height <= 0 || frame->width > 8192 || frame->height > 8192)
        return false;
    AVFrame *image = frame;
    enum video_format format;
    if (frame->format == AV_PIX_FMT_YUV420P || frame->format == AV_PIX_FMT_YUVJ420P) {
        format = VIDEO_FORMAT_I420;
    } else if (frame->format == AV_PIX_FMT_NV12) {
        format = VIDEO_FORMAT_NV12;
    } else {
        av_frame_unref(converted);
        converted->format = AV_PIX_FMT_YUV420P;
        converted->width = frame->width;
        converted->height = frame->height;
        if (av_frame_get_buffer(converted, 32) < 0)
            return false;
        scale = sws_getCachedContext(scale, frame->width, frame->height,
                                    static_cast<AVPixelFormat>(frame->format), frame->width,
                                    frame->height, AV_PIX_FMT_YUV420P, SWS_BILINEAR,
                                    nullptr, nullptr, nullptr);
        if (!scale || sws_scale(scale, frame->data, frame->linesize, 0, frame->height,
                                converted->data, converted->linesize) <= 0)
            return false;
        image = converted;
        format = VIDEO_FORMAT_I420;
    }
    obs_source_frame output{};
    output.format = format;
    output.width = image->width;
    output.height = image->height;
    output.timestamp = frame->pts != AV_NOPTS_VALUE && frame->pts > 0 ? frame->pts : timestamp;
    output.full_range = frame->color_range == AVCOL_RANGE_JPEG || frame->format == AV_PIX_FMT_YUVJ420P;
    const auto space = frame->colorspace == AVCOL_SPC_BT709 ? VIDEO_CS_709 : VIDEO_CS_601;
    video_format_get_parameters(space, output.full_range ? VIDEO_RANGE_FULL : VIDEO_RANGE_PARTIAL,
                                output.color_matrix, output.color_range_min, output.color_range_max);
    for (size_t i = 0; i < 3; ++i) {
        if (image->linesize[i] < 0)
            return false;
        output.data[i] = image->data[i];
        output.linesize[i] = image->linesize[i];
    }
    obs_source_output_video(source, &output);
    width = output.width;
    height = output.height;
    return true;
}

bool VideoDecoder::decode(obs_source_t *source, const uint8_t *data, size_t size, uint64_t timestamp)
{
    if (!context || !size || size > INT_MAX)
        return false;
    av_packet_unref(packet);
    int result = av_new_packet(packet, static_cast<int>(size));
    if (result < 0)
        return codec_error("video allocation", result);
    std::memcpy(packet->data, data, size);
    packet->pts = packet->dts = static_cast<int64_t>(timestamp);
    result = avcodec_send_packet(context, packet);
    if (result == AVERROR(EAGAIN)) {
        while ((result = avcodec_receive_frame(context, frame)) >= 0) {
            if (!output(source, timestamp))
                return false;
        }
        if (result != AVERROR(EAGAIN))
            return codec_error("video receive", result);
        result = avcodec_send_packet(context, packet);
    }
    if (result < 0)
        return codec_error("video send", result);
    while ((result = avcodec_receive_frame(context, frame)) >= 0) {
        if (!output(source, timestamp))
            return false;
    }
    return result == AVERROR(EAGAIN) || codec_error("video receive", result);
}

AudioDecoder::~AudioDecoder()
{
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
}

bool AudioDecoder::open(uint8_t type)
{
    // AudioSpecificConfig and ALAC cookie match UxPlay's mirror/audio caps.
    static constexpr uint8_t eld[] = {0xf8, 0xe8, 0x50, 0x00};
    static constexpr uint8_t lc[] = {0x12, 0x10};
    static constexpr uint8_t alac[] = {
        0, 0, 0, 0x24, 'a', 'l', 'a', 'c', 0, 0, 0, 0,
        0, 0, 1, 0x60, 0, 0x10, 0x28, 0x0a, 0x0e, 2, 0, 0xff,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x44};
    const uint8_t *extra = nullptr;
    size_t extra_size = 0;
    AVCodecID id = AV_CODEC_ID_AAC;
    if (type == 2) {
        id = AV_CODEC_ID_ALAC;
        extra = alac;
        extra_size = sizeof(alac);
    } else if (type == 4 || type == 8) {
        extra = type == 4 ? lc : eld;
        extra_size = type == 4 ? sizeof(lc) : sizeof(eld);
    } else {
        return false;
    }
    avcodec_free_context(&context);
    compression = 0;
    const AVCodec *codec = avcodec_find_decoder(id);
    if (!codec)
        return false;
    context = avcodec_alloc_context3(codec);
    if (!frame)
        frame = av_frame_alloc();
    if (!packet)
        packet = av_packet_alloc();
    if (!context || !frame || !packet)
        return false;
    context->extradata = static_cast<uint8_t *>(av_mallocz(extra_size + AV_INPUT_BUFFER_PADDING_SIZE));
    if (!context->extradata)
        return false;
    std::memcpy(context->extradata, extra, extra_size);
    context->extradata_size = static_cast<int>(extra_size);
    context->sample_rate = 44100;
    context->pkt_timebase = {1, 1000000000};
    av_channel_layout_default(&context->ch_layout, 2);
    const int result = avcodec_open2(context, codec, nullptr);
    if (result < 0) {
        avcodec_free_context(&context);
        return codec_error("audio open", result);
    }
    compression = type;
    return true;
}

void AudioDecoder::reset()
{
    if (context)
        avcodec_flush_buffers(context);
}

bool AudioDecoder::decode(obs_source_t *source, uint8_t type, const uint8_t *data, size_t size,
                          uint64_t timestamp, double gain)
{
    if (!size || size > INT_MAX)
        return false;
    if (type == 1) {
        if (size % 4)
            return false;
        obs_source_audio output{};
        output.data[0] = data;
        if (gain != 1.0) {
            // Keep the protocol's packet untouched; reuse storage for PCM gain.
            pcm.resize(size / sizeof(int16_t));
            std::memcpy(pcm.data(), data, size);
            attenuate<int16_t>(reinterpret_cast<uint8_t *>(pcm.data()), pcm.size(), gain);
            output.data[0] = reinterpret_cast<const uint8_t *>(pcm.data());
        }
        output.frames = static_cast<uint32_t>(size / 4);
        output.speakers = SPEAKERS_STEREO;
        output.format = AUDIO_FORMAT_16BIT;
        output.samples_per_sec = 44100;
        output.timestamp = timestamp;
        obs_source_output_audio(source, &output);
        return true;
    }
    if ((compression != type || !context) && !open(type))
        return false;
    av_packet_unref(packet);
    int result = av_new_packet(packet, static_cast<int>(size));
    if (result < 0)
        return codec_error("audio allocation", result);
    std::memcpy(packet->data, data, size);
    packet->pts = packet->dts = static_cast<int64_t>(timestamp);
    result = avcodec_send_packet(context, packet);
    uint64_t next_timestamp = timestamp;
    if (result == AVERROR(EAGAIN)) {
        while ((result = avcodec_receive_frame(context, frame)) >= 0) {
            if (!output(source, next_timestamp, gain))
                return false;
        }
        if (result != AVERROR(EAGAIN))
            return codec_error("audio receive", result);
        result = avcodec_send_packet(context, packet);
    }
    if (result < 0)
        return codec_error("audio send", result);
    while ((result = avcodec_receive_frame(context, frame)) >= 0) {
        if (!output(source, next_timestamp, gain))
            return false;
    }
    return result == AVERROR(EAGAIN) || codec_error("audio receive", result);
}

bool AudioDecoder::output(obs_source_t *source, uint64_t &next_timestamp, double gain)
{
    obs_source_audio output{};
    const int channels = frame->ch_layout.nb_channels;
    if ((channels != 1 && channels != 2) || frame->sample_rate < 8000 ||
        frame->sample_rate > 192000 || frame->nb_samples <= 0 || frame->nb_samples > 8192)
        return false;
    switch (frame->format) {
    case AV_SAMPLE_FMT_FLTP: output.format = AUDIO_FORMAT_FLOAT_PLANAR; break;
    case AV_SAMPLE_FMT_FLT: output.format = AUDIO_FORMAT_FLOAT; break;
    case AV_SAMPLE_FMT_S16P: output.format = AUDIO_FORMAT_16BIT_PLANAR; break;
    case AV_SAMPLE_FMT_S16: output.format = AUDIO_FORMAT_16BIT; break;
    case AV_SAMPLE_FMT_S32P: output.format = AUDIO_FORMAT_32BIT_PLANAR; break;
    case AV_SAMPLE_FMT_S32: output.format = AUDIO_FORMAT_32BIT; break;
    default: return false;
    }
    if (gain != 1.0) {
        // Attenuate decoded samples without changing OBS's mixer volume.
        if (av_frame_make_writable(frame) < 0)
            return false;
        const bool planar = av_sample_fmt_is_planar(static_cast<AVSampleFormat>(frame->format));
        const int planes = planar ? channels : 1;
        const size_t count = static_cast<size_t>(frame->nb_samples) * (planar ? 1 : channels);
        for (int i = 0; i < planes; ++i) {
            switch (frame->format) {
            case AV_SAMPLE_FMT_FLTP:
            case AV_SAMPLE_FMT_FLT: attenuate<float>(frame->extended_data[i], count, gain); break;
            case AV_SAMPLE_FMT_S16P:
            case AV_SAMPLE_FMT_S16: attenuate<int16_t>(frame->extended_data[i], count, gain); break;
            case AV_SAMPLE_FMT_S32P:
            case AV_SAMPLE_FMT_S32: attenuate<int32_t>(frame->extended_data[i], count, gain); break;
            default: break;
            }
        }
    }
    for (int i = 0; i < channels; ++i)
        output.data[i] = frame->extended_data[i];
    output.frames = frame->nb_samples;
    output.speakers = channels == 2 ? SPEAKERS_STEREO : SPEAKERS_MONO;
    output.samples_per_sec = frame->sample_rate;
    output.timestamp = frame->pts != AV_NOPTS_VALUE && frame->pts > 0 ?
                       std::max(static_cast<uint64_t>(frame->pts), next_timestamp) : next_timestamp;
    obs_source_output_audio(source, &output);
    next_timestamp = output.timestamp + static_cast<uint64_t>(frame->nb_samples) * 1000000000ULL / frame->sample_rate;
    return true;
}

} // namespace air
