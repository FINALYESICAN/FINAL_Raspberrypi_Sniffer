// decoder.h
#pragma once
#include <pcap.h>
#include <cstdint>
#include "packet_record.h"

class Decoder {
public:
    void decode(pcap_t& pcap, const pcap_pkthdr& h, const u_char* bytes, PacketRecord& out);
private:
    static uint64_t tv_to_ns(const timeval& tv){
        return (uint64_t)tv.tv_sec*1000000000ull + (uint64_t)tv.tv_usec*1000ull;
    }
    void parse_l2_l3_l4(int dlt, const u_char* bytes, uint32_t caplen, PacketRecord& rec);
    void parse_ipv4(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t* base);
    void parse_arp (const uint8_t* p, uint32_t len);
    void parse_ipv6(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t* base);
};

