#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace air {

// AirPlay uses a wall clock; OBS expects a monotonic nanosecond clock.
struct Clock {
    uint64_t remote = 0;
    uint64_t local = 0;

    void reset() { remote = local = 0; }
    uint64_t map(uint64_t timestamp, uint64_t now)
    {
        if (!timestamp)
            return now;
        if (!remote) {
            remote = timestamp;
            local = now;
        }
        uint64_t mapped = now;
        if (timestamp >= remote) {
            const uint64_t delta = timestamp - remote;
            if (delta <= UINT64_MAX - local)
                mapped = local + delta;
        } else {
            const uint64_t delta = remote - timestamp;
            if (delta < local)
                mapped = local - delta;
        }
        const uint64_t drift = mapped >= now ? mapped - now : now - mapped;
        if (drift > 3000000000ULL) {
            remote = timestamp;
            local = now;
            return now;
        }
        return mapped;
    }
};

struct NalInfo {
    bool idr = false;
    std::vector<uint8_t> sps;
    std::vector<uint8_t> pps;
};

inline NalInfo inspect_h264(const uint8_t *data, size_t size)
{
    NalInfo info;
    size_t start = size;
    size_t payload = size;
    for (size_t i = 0; i + 3 <= size;) {
        size_t prefix = 0;
        if (data[i] == 0 && data[i + 1] == 0) {
            if (data[i + 2] == 1)
                prefix = 3;
            else if (i + 4 <= size && data[i + 2] == 0 && data[i + 3] == 1)
                prefix = 4;
        }
        if (!prefix) {
            ++i;
            continue;
        }
        if (payload < i) {
            const uint8_t type = data[payload] & 31;
            info.idr |= type == 5;
            if (type == 7)
                info.sps.assign(data + start, data + i);
            if (type == 8)
                info.pps.assign(data + start, data + i);
        }
        start = i;
        payload = i + prefix;
        i = payload;
    }
    if (payload < size) {
        const uint8_t type = data[payload] & 31;
        info.idr |= type == 5;
        if (type == 7)
            info.sps.assign(data + start, data + size);
        if (type == 8)
            info.pps.assign(data + start, data + size);
    }
    return info;
}

} // namespace air
