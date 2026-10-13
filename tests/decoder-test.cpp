#include "decoders.hpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>

static int video_frames = 0;
static int audio_frames = 0;
static uint32_t width = 0, height = 0;
static uint64_t video_timestamp = 0;
static uint64_t audio_timestamp = 0;
static std::vector<double> samples;

extern "C" void obs_source_output_video(obs_source_t *, const obs_source_frame *frame)
{
    ++video_frames;
    width = frame->width;
    height = frame->height;
    video_timestamp = frame->timestamp;
}
extern "C" void obs_source_output_audio(obs_source_t *, const obs_source_audio *audio)
{
    if (audio->frames && audio->data[0] && audio->samples_per_sec == 44100)
        ++audio_frames;
    audio_timestamp = audio->timestamp;
    samples.clear();
    const bool planar = audio->format == AUDIO_FORMAT_FLOAT_PLANAR ||
                        audio->format == AUDIO_FORMAT_16BIT_PLANAR || audio->format == AUDIO_FORMAT_32BIT_PLANAR;
    const int channels = audio->speakers == SPEAKERS_STEREO ? 2 : 1;
    for (uint32_t i = 0; i < audio->frames; ++i) {
        for (int channel = 0; channel < channels; ++channel) {
            const uint8_t *data = audio->data[planar ? channel : 0];
            const size_t index = planar ? i : i * channels + channel;
            switch (audio->format) {
            case AUDIO_FORMAT_FLOAT_PLANAR:
            case AUDIO_FORMAT_FLOAT: samples.push_back(reinterpret_cast<const float *>(data)[index]); break;
            case AUDIO_FORMAT_16BIT_PLANAR:
            case AUDIO_FORMAT_16BIT: samples.push_back(reinterpret_cast<const int16_t *>(data)[index]); break;
            case AUDIO_FORMAT_32BIT_PLANAR:
            case AUDIO_FORMAT_32BIT: samples.push_back(reinterpret_cast<const int32_t *>(data)[index]); break;
            default: samples.push_back(-1); break;
            }
        }
    }
}
extern "C" bool video_format_get_parameters(video_colorspace, video_range_type, float *, float *, float *)
{
    return true;
}
extern "C" void blog(int, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    std::fputc('\n', stderr);
    va_end(args);
}

static std::vector<uint8_t> read(const char *name)
{
    std::ifstream file(std::string(FIXTURE_DIR) + "/" + name, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

template<typename T>
static void fill(uint8_t *data, size_t count)
{
    auto *values = reinterpret_cast<T *>(data);
    for (size_t i = 0; i < count; ++i)
        values[i] = i % 2 ? std::numeric_limits<T>::lowest() : std::numeric_limits<T>::max();
}

int main(int argc, char **argv)
{
    air::VideoDecoder video;
    if (!video.open())
        return 1;
    const auto landscape = read("landscape.h264");
    if (!video.decode(nullptr, landscape.data(), landscape.size(), 1000000000ULL) ||
        video_frames != 1 || width != 128 || height != 72 || video.width != width ||
        video.height != height || video_timestamp != 1000000000ULL)
        return 2; // The single final picture must not wait for a second packet.
    const auto portrait = read("portrait.h264");
    video.reset();
    if (!video.decode(nullptr, portrait.data(), portrait.size(), 2000000000ULL) ||
        video_frames != 2 || width != 72 || height != 128 || video.width != width || video.height != height)
        return 3;
    air::AudioDecoder audio;
    const auto aac = read("audio.aac");
    size_t position = 0;
    uint64_t timestamp = 1000000000ULL;
    while (position + 7 <= aac.size()) {
        const auto *header = aac.data() + position;
        const size_t length = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5);
        if (length < 7 || position + length > aac.size() ||
            !audio.decode(nullptr, 4, header + 7, length - 7, timestamp) || audio_timestamp != timestamp)
            return 4;
        position += length;
        timestamp += 1024ULL * 1000000000 / 44100;
    }
    if (position != aac.size() || audio_frames != 2)
        return 5;
    // Gain must cover every supported sample layout and preserve shared buffers.
    for (auto format : {AV_SAMPLE_FMT_FLT, AV_SAMPLE_FMT_FLTP, AV_SAMPLE_FMT_S16,
                        AV_SAMPLE_FMT_S16P, AV_SAMPLE_FMT_S32, AV_SAMPLE_FMT_S32P}) {
        for (double gain : {1.0, 0.5, 0.0}) {
            av_frame_unref(audio.frame);
            audio.frame->format = format;
            audio.frame->sample_rate = 44100;
            audio.frame->nb_samples = 2;
            av_channel_layout_default(&audio.frame->ch_layout, 2);
            if (av_frame_get_buffer(audio.frame, 0) < 0)
                return 6;
            const bool planar = av_sample_fmt_is_planar(format);
            for (int i = 0; i < (planar ? 2 : 1); ++i) {
                const size_t count = planar ? 2 : 4;
                if (format == AV_SAMPLE_FMT_FLT || format == AV_SAMPLE_FMT_FLTP) {
                    auto *values = reinterpret_cast<float *>(audio.frame->extended_data[i]);
                    for (size_t j = 0; j < count; ++j)
                        values[j] = j % 2 ? -0.5f : 0.75f;
                } else if (format == AV_SAMPLE_FMT_S16 || format == AV_SAMPLE_FMT_S16P) {
                    fill<int16_t>(audio.frame->extended_data[i], count);
                } else {
                    fill<int32_t>(audio.frame->extended_data[i], count);
                }
            }
            AVFrame *shared = av_frame_clone(audio.frame);
            uint64_t next = 3000000000ULL;
            if (!shared || !audio.output(nullptr, next, 1.0) || samples.size() != 4)
                return 7;
            const auto original = samples;
            if (!audio.output(nullptr, next, gain) || samples.size() != original.size())
                return 8;
            for (size_t i = 0; i < samples.size(); ++i) {
                double expected = original[i] * gain;
                if (format == AV_SAMPLE_FMT_S16 || format == AV_SAMPLE_FMT_S16P)
                    expected = static_cast<int16_t>(expected);
                else if (format == AV_SAMPLE_FMT_S32 || format == AV_SAMPLE_FMT_S32P)
                    expected = static_cast<int32_t>(expected);
                if (samples[i] != expected)
                    return 9;
            }
            if (std::memcmp(shared->extended_data[0], audio.frame->extended_data[0],
                            av_get_bytes_per_sample(format) * 2) == 0 && gain != 1.0)
                return 10;
            av_frame_free(&shared);
        }
    }
    const int16_t pcm[] = {32767, -32768, 12000, -12000};
    if (!audio.decode(nullptr, 1, reinterpret_cast<const uint8_t *>(pcm), sizeof(pcm), timestamp, 0.5) ||
        samples != std::vector<double>{16383, -16384, 6000, -6000} || pcm[0] != 32767)
        return 11;
    if (!audio.decode(nullptr, 1, reinterpret_cast<const uint8_t *>(pcm), sizeof(pcm), timestamp, 0.0) ||
        samples != std::vector<double>(4, 0.0))
        return 12;
    if (!audio.decode(nullptr, 1, reinterpret_cast<const uint8_t *>(pcm), sizeof(pcm), timestamp) ||
        samples != std::vector<double>{32767, -32768, 12000, -12000})
        return 13;
    if (argc > 1 && !std::strcmp(argv[1], "--stress")) {
        // Repeat rotation and audio resets without recreating decoder objects.
        for (int iteration = 0; iteration < 10000; ++iteration) {
            const auto &image = iteration % 2 ? portrait : landscape;
            timestamp += 33333333;
            video.reset();
            const int before_video = video_frames;
            if (!video.decode(nullptr, image.data(), image.size(), timestamp) ||
                video_frames != before_video + 1 || video_timestamp != timestamp ||
                width != (iteration % 2 ? 72U : 128U) || height != (iteration % 2 ? 128U : 72U))
                return 14;
            audio.reset();
            const int before_audio = audio_frames;
            for (size_t offset = 0; offset + 7 <= aac.size();) {
                const auto *header = aac.data() + offset;
                const size_t length = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5);
                if (!audio.decode(nullptr, 4, header + 7, length - 7, timestamp, iteration % 2 ? 0.5 : 1.0) ||
                    audio_timestamp != timestamp)
                    return 15;
                offset += length;
                timestamp += 1024ULL * 1000000000 / 44100;
            }
            if (audio_frames != before_audio + 2)
                return 16;
        }
        std::puts("10,000 video rotations and 20,000 AAC packets passed");
    }
    std::puts("Immediate final frame, rotation reset, AAC audio and PCM/planar/packed gain passed");
    return 0;
}
