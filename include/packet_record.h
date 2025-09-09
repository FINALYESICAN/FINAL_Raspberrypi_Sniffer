#pragma once
#include <cstdint>
#include <array>
#include <vector>

struct PacketRecord {
    // 패킷 고유 ID값
    uint64_t id{};
    // ts / length
    uint64_t ts_ns{};
    uint32_t caplen{};
    uint32_t wirelen{};

    // packet offset
    uint32_t l2_off{};
    uint32_t l3_off{};
    uint32_t l4_off{};
    uint32_t l4_hdr_len{};

    // L2
    int dlt{};
    std::array<uint8_t, 6> dst_mac{};
    std::array<uint8_t, 6> src_mac{};
    uint16_t ethertype{};

    // L3
    uint8_t  ip_version{};   // 4/6 (0=non-IP)
    uint8_t  l4_proto{};     // TCP=6, UDP=17, ICMP=1
    uint32_t ipv4_src{};
    uint32_t ipv4_dst{};
    uint8_t  ipv4_ttl{};
    uint16_t ipv4_hdr_len{};

    // L4
    uint16_t sport{};
    uint16_t dport{};
    uint32_t tcp_seq{};
    uint32_t tcp_ack{};
    uint8_t  tcp_flags{};
    uint8_t  tcp_hdr_len{};

    // payload
    uint32_t payload_off{};
    uint32_t payload_len{};
    std::vector<uint8_t> payload_copy; // up to PAYLOAD_STORE_LIMIT
};