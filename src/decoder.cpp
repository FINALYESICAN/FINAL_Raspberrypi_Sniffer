// decoder.cpp
#include "decoder.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <cstring>

#ifndef PAYLOAD_STORE_LIMIT
#define PAYLOAD_STORE_LIMIT 256
#endif

// Linux SLL v1
struct sll_header {
    uint16_t pkttype, hatype, halen;
    uint8_t  addr[8];
    uint16_t proto;
} __attribute__((packed));

void Decoder::decode(pcap_t& pcap, const pcap_pkthdr& h, const u_char* bytes, PacketRecord& rec){
    rec.ts_ns  = tv_to_ns(h.ts);
    rec.caplen = h.caplen;
    rec.wirelen= h.len;
    rec.dlt    = pcap_datalink(&pcap);
    rec.l2_off = 0U;

    parse_l2_l3_l4(rec.dlt, bytes, h.caplen, rec);

    // payload 위치/길이 계산
    if (rec.l4_off && rec.l4_hdr_len && rec.caplen >= rec.l4_off + rec.l4_hdr_len) {
        uint32_t after = rec.l4_off + rec.l4_hdr_len;
        rec.payload_off = after;
        rec.payload_len = (rec.caplen >= after) ? (rec.caplen - after) : 0;
    } else {
        rec.payload_off = rec.payload_len = 0;
    }
    if (rec.payload_len){
        uint32_t to_copy = rec.payload_len > PAYLOAD_STORE_LIMIT ? PAYLOAD_STORE_LIMIT : rec.payload_len;
        rec.payload_copy.assign(bytes + rec.payload_off, bytes + rec.payload_off + to_copy);
    }
}

void Decoder::parse_l2_l3_l4(int dlt, const u_char* p, uint32_t rem, PacketRecord& rec){
    if (dlt == DLT_EN10MB){
        if (rem < sizeof(ether_header)) return;
        const auto* eth = reinterpret_cast<const ether_header*>(p);
        std::memcpy(rec.dst_mac.data(), eth->ether_dhost, 6);
        std::memcpy(rec.src_mac.data(), eth->ether_shost, 6);
        uint16_t etype = ntohs(eth->ether_type);
        rec.ethertype = etype;
        p   += sizeof(*eth);
        rem -= sizeof(*eth);
        rec.l3_off = static_cast<uint32_t>(p - (const u_char*)nullptr); // 정보용(미사용)
        switch (etype){
            case ETHERTYPE_IP:   parse_ipv4(p, rem, rec, (const uint8_t*)nullptr); break;
            case ETHERTYPE_ARP:  parse_arp (p, rem); break;
            case ETHERTYPE_IPV6: parse_ipv6(p, rem, rec, (const uint8_t*)nullptr); break;
            default: break;
        }
    } else if (dlt == DLT_LINUX_SLL){
        if (rem < sizeof(sll_header)) return;
        const auto* s = reinterpret_cast<const sll_header*>(p);
        uint16_t proto = ntohs(s->proto);
        p   += sizeof(*s);
        rem -= sizeof(*s);
        switch (proto){
            case ETHERTYPE_IP:   parse_ipv4(p, rem, rec, (const uint8_t*)nullptr); break;
            case ETHERTYPE_ARP:  parse_arp (p, rem); break;
            case ETHERTYPE_IPV6: parse_ipv6(p, rem, rec, (const uint8_t*)nullptr); break;
            default: break;
        }
    } else if (dlt == DLT_RAW){
        if (rem>=1){
            uint8_t v = (p[0]>>4)&0xF;
            if (v==4) parse_ipv4(p, rem, rec, (const uint8_t*)nullptr);
            else if (v==6) parse_ipv6(p, rem, rec, (const uint8_t*)nullptr);
        }
    }
}

void Decoder::parse_ipv4(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t* base){
    if (len < sizeof(ip)) return;
    const ip* iph = reinterpret_cast<const ip*>(p);
    uint32_t ip_hl = static_cast<uint32_t>(iph->ip_hl)*4U;

    rec.ip_version   = 4;
    rec.l4_proto     = iph->ip_p;
    rec.ipv4_ttl     = iph->ip_ttl;
    rec.ipv4_hdr_len = (uint16_t)ip_hl;
    std::memcpy(&rec.ipv4_src, &iph->ip_src, 4);
    std::memcpy(&rec.ipv4_dst, &iph->ip_dst, 4);
    rec.l4_off = (uint32_t)( (p + ip_hl) - (base ? base : (const uint8_t*)0) );

    const uint8_t* l4 = p + ip_hl;
    uint32_t l4len = len - ip_hl;

    if (iph->ip_p == IPPROTO_TCP && l4len >= sizeof(tcphdr)){
        const tcphdr* th = reinterpret_cast<const tcphdr*>(l4);
        uint32_t thl = (uint32_t)th->doff * 4U;
        rec.sport       = ntohs(th->source);
        rec.dport       = ntohs(th->dest);
        rec.tcp_seq     = ntohl(th->seq);
        rec.tcp_ack     = ntohl(th->ack_seq);
        rec.tcp_flags   = (uint8_t)((th->urg<<5)|(th->ack<<4)|(th->psh<<3)|(th->rst<<2)|(th->syn<<1)|th->fin);
        rec.tcp_hdr_len = (uint8_t)thl;
        rec.l4_hdr_len  = rec.tcp_hdr_len;
    } else if (iph->ip_p == IPPROTO_UDP && l4len >= sizeof(udphdr)){
        const udphdr* uh = reinterpret_cast<const udphdr*>(l4);
        rec.sport      = ntohs(uh->source);
        rec.dport      = ntohs(uh->dest);
        rec.l4_hdr_len = sizeof(udphdr);
    } else if (iph->ip_p == IPPROTO_ICMP && l4len >= 2){
        rec.l4_hdr_len = 0;
    }
}

void Decoder::parse_arp(const uint8_t* p, uint32_t len){
    (void)p; (void)len; // 필요 시 요약만
}

void Decoder::parse_ipv6(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t* base){
    if (len < sizeof(ip6_hdr)) return;
    const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(p);
    rec.ip_version = 6;
    rec.l4_proto   = ip6->ip6_nxt;
    (void)base;
}
