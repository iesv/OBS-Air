#include "media.hpp"
#include <iostream>

static int failures = 0;
static void check(bool condition, const char *description)
{
    if (!condition) {
        std::cerr << description << '\n';
        ++failures;
    }
}

int main()
{
    air::Clock clock;
    constexpr uint64_t wall = 1700000000000000000ULL;
    check(clock.map(wall, 10000000000ULL) == 10000000000ULL, "first timestamp anchors to OBS clock");
    check(clock.map(wall + 16000000, 10020000000ULL) == 10016000000ULL, "packet jitter does not replace presentation time");
    check(clock.map(wall + 10000000000ULL, 10100000000ULL) == 10100000000ULL, "clock jump reanchors");
    clock.reset();
    check(clock.map(wall, 20000000000ULL) == 20000000000ULL, "new session resets clock");
    check(clock.map(0, 20010000000ULL) == 20010000000ULL, "missing timestamp uses arrival time");
    check(clock.map(UINT64_MAX, 20020000000ULL) == 20020000000ULL, "invalid large timestamp cannot overflow the OBS clock");
    const uint8_t stream[] = {0,0,0,1,0x67,0x11,0x22,0,0,1,0x68,0x33,0,0,0,1,0x65,0x44};
    const auto info = air::inspect_h264(stream, sizeof(stream));
    check(info.idr, "mixed Annex B prefixes detect IDR");
    check(info.sps.size() + info.pps.size() == 12, "recovery keeps SPS and PPS, excluding image data");
    const uint8_t predicted[] = {0,0,1,0x41,0x55};
    check(!air::inspect_h264(predicted, sizeof(predicted)).idr, "P picture cannot restart decoder");
    const uint8_t truncated[] = {0,0,0,1};
    check(!air::inspect_h264(truncated, sizeof(truncated)).idr, "empty NAL is safe");
    check(!air::inspect_h264(nullptr, 0).idr, "empty buffer is safe");
    return failures ? 1 : 0;
}
