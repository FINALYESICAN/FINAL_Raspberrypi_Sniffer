#include "alert_parse.h"
#include <algorithm>
#include <cstring>
#include <arpa/inet.h>

// ------- helpers -------
static inline uint16_t rd16_be(const uint8_t* p) {
    return (uint16_t(p[0])<<8) | uint16_t(p[1]);
}
static inline uint32_t rd32_be(const uint8_t* p) {
    return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]);
}

static std::string ip4_to_str(const uint8_t* p4) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr a; 
    std::memcpy(&a.s_addr, p4, 4);
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? std::string(buf) : std::string();
}
static std::string ip6_to_str(const uint8_t* p16) {
    char buf[INET6_ADDRSTRLEN]{};
    in6_addr a{}; std::memcpy(&a, p16, 16);
    return inet_ntop(AF_INET6, &a, buf, sizeof(buf)) ? std::string(buf) : std::string();
}

// ------- main -------
bool build_alert_view(const AlertRecord& a, AlertView& out) {
    out = AlertView{}; // reset
    out.ts_sec  = a.ts_sec;
    out.ts_usec = a.ts_usec;
    out.policy  = a.msg;     // 정책명 대용
    out.action  = "ALERT";   // alert_unixsock는 DROP정보 없음

    const uint8_t* pkt = a.pkt;
    size_t cap = a.pkt_size;
    if (!pkt || cap == 0) return false;

    // L3 시작 오프셋: Snort가 준 net_off를 우선 신뢰
    const size_t l3_off = (a.net_off < cap) ? a.net_off : 0;
    if (l3_off >= cap) return false;

    // IPv4/IPv6 판별 (첫 nibble = version)
    const uint8_t v = pkt[l3_off] >> 4;

    if (v == 4) {
        // IPv4 header 최소 20B
        if (cap < l3_off + 20) return false;
        const uint8_t* ip = pkt + l3_off;
        const uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || cap < l3_off + ihl) return false;

        const uint8_t proto = ip[9];
        out.src_ip = ip4_to_str(ip + 12);
        out.dst_ip = ip4_to_str(ip + 16);

        // L4 위치: Snort trans_off 우선, 없으면 IHL 뒤
        size_t l4_off = (a.trans_off && a.trans_off < cap) ? a.trans_off : (l3_off + ihl);
        if (l4_off >= cap) return true; // IP까지만

        if (proto == 6 /*TCP*/ || proto == 17 /*UDP*/) {
            if (cap >= l4_off + 4) {
                out.src_port = rd16_be(pkt + l4_off + 0);
                out.dst_port = rd16_be(pkt + l4_off + 2);
            }
        }
        return true;

    } else if (v == 6) {
        // IPv6 기본 헤더 40B
        if (cap < l3_off + 40) return false;
        const uint8_t* ip6 = pkt + l3_off;
        const uint8_t next_hdr = ip6[6]; // 단, 확장헤더가 있을 수 있음

        out.src_ip = ip6_to_str(ip6 + 8);
        out.dst_ip = ip6_to_str(ip6 + 24);

        // Snort가 trans_off를 줬으면 확장헤더 고려 끝난 위치
        size_t l4_off = (a.trans_off && a.trans_off < cap) ? a.trans_off : (l3_off + 40);
        if (l4_off >= cap) return true;

        if (next_hdr == 6 /*TCP*/ || next_hdr == 17 /*UDP*/) {
            if (cap >= l4_off + 4) {
                out.src_port = rd16_be(pkt + l4_off + 0);
                out.dst_port = rd16_be(pkt + l4_off + 2);
            }
        }
        return true;
    }

    // L3 미식별
    return false;
}