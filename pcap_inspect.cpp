// pcap_inspect.cpp (C++17)
// RasPi/libpcap: 캡처 + 구조체/헤더 필드 출력 예제 (C++ 리팩토링)
// 빌드: g++ -O2 -Wall -std=c++17 -o pcap_inspect pcap_inspect.cpp -lpcap
// 실행:
//   sudo ./pcap_inspect
//   sudo ./pcap_inspect eth0
//   sudo ./pcap_inspect eth0 "tcp"
//   sudo ./pcap_inspect eth0 "tcp" nano

#define _GNU_SOURCE
#include <pcap.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <sys/time.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>
#include <vector>
#include <deque>
#include <memory>
#include <array>
#include <iostream>
#include <iomanip>
#include <optional>

#include "packet_record.h"  //PacketRecord 구조체 정의
#include "session_table.h"  //TCP/UDP 세션 테이블 로직

#ifndef PAYLOAD_STORE_LIMIT
#define PAYLOAD_STORE_LIMIT 256  //저장할 페이로드 최대 크기
#endif

// ===== Global =====
static volatile sig_atomic_t g_stop = 0; //ctrl+C 플래그
static pcap_t* g_pcap = nullptr;         //pcap 세션 핸들
static SessionTable g_sess;              //세션 테이블

// ===== Helpers =====
//timeval -> 나노초 단위 정수 변환
static inline uint64_t tv_to_ns(const timeval& tv) {
    return static_cast<uint64_t>(tv.tv_sec) * 1000000000ULL
         + static_cast<uint64_t>(tv.tv_usec) * 1000ULL;
}

// 데이터링크 이름 반환
static const char* dlt_name(int dlt) {
    switch (dlt) {
        case DLT_EN10MB: return "DLT_EN10MB (Ethernet)";
        case DLT_LINUX_SLL: return "DLT_LINUX_SLL (Cooked v1)";
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2: return "DLT_LINUX_SLL2 (Cooked v2)";
#endif
        case DLT_RAW: return "DLT_RAW (no L2)";
        case DLT_IEEE802_11_RADIO: return "DLT_IEEE802_11_RADIO (Radiotap)";
        default: return "DLT_???";
    }
}

// Linux SLL v1 header
struct sll_header {
    uint16_t pkttype;
    uint16_t hatype;
    uint16_t halen;
    uint8_t  addr[8];
    uint16_t proto;
} __attribute__((packed));

/*============================================
* PacketList : 캡쳐한 패킷을 메모리에 저장하는 리스트
* std::deque를 통해 구현
* =============================================*/

struct PacketList {
    std::deque<std::unique_ptr<PacketRecord>> dq;
    size_t max_count = 50000;

    void push(std::unique_ptr<PacketRecord> rec) {
        dq.emplace_back(std::move(rec));
        while (dq.size() > max_count) {
            dq.pop_front();
        }
    }
    void clear() { dq.clear(); } //모든 패킷 삭제
    size_t size() const { return dq.size(); }

    //마지막 N개의 패킷 덤프
    void dump_tail(size_t N) const {
        if (dq.empty()) {
            std::puts("[packetlist] empty");
            return;
        }
        size_t start = (N >= dq.size()) ? 0 : (dq.size() - N);
        for (size_t i = start; i < dq.size(); ++i) {
            dump_summary(*dq[i], static_cast<uint32_t>(i));
        }
    }

    //패킷 요약 출력
    static void dump_summary(const PacketRecord& pr, uint32_t idx) {
        char sip[64] = {0}, dip[64] = {0};
        if (pr.ip_version == 4) {
            in_addr a{}, b{};
            a.s_addr = pr.ipv4_src;
            b.s_addr = pr.ipv4_dst;
            inet_ntop(AF_INET, &a, sip, sizeof sip);
            inet_ntop(AF_INET, &b, dip, sizeof dip);
        }
        std::printf("#%u  ts=%.6f  cap=%u  wire=%u  dlt=%d  "
                    "L3=%s  L4=%u  %s:%u -> %s:%u  payload=%u\n",
                    idx,
                    pr.ts_ns / 1e9,
                    pr.caplen, pr.wirelen, pr.dlt,
                    (pr.ip_version==4? "IPv4": (pr.ip_version==6? "IPv6":"-")),
                    pr.l4_proto,
                    sip, ntohs(pr.sport), dip, ntohs(pr.dport),
                    pr.payload_len);
    }
};

//전역 패킷 리스트
static PacketList g_pkts;

// ===== 페이로드 출력 =====
static void print_payload(const uint8_t* data, uint32_t len) {
    std::printf("  Payload (%u bytes):\n", len);
    for (uint32_t i = 0; i < len; ++i) {
        if (i % 16 == 0) std::printf("    ");
        std::printf("%02x ", data[i]);
        if ((i+1) % 16 == 0 || i+1 == len) std::printf("\n");
    }
}

// ===== IPv4/TCP/UDP/ICMP/ARP/IPv6 파서 =====
// IPv4 패킷 파싱
static void print_ipv4(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t* base) {
    if (len < sizeof(ip)) { std::puts("  IPv4: len too small"); return; }
    const ip* iph = reinterpret_cast<const ip*>(p);
    uint32_t ip_header_len = static_cast<uint32_t>(iph->ip_hl) * 4U;

    // IPv4 헤더 정보 저장
    rec.ip_version   = 4;
    rec.l4_proto     = iph->ip_p;
    rec.ipv4_ttl     = iph->ip_ttl;
    rec.ipv4_hdr_len = static_cast<uint16_t>(ip_header_len);
    std::memcpy(&rec.ipv4_src, &iph->ip_src, 4);
    std::memcpy(&rec.ipv4_dst, &iph->ip_dst, 4);
    rec.l4_off       = static_cast<uint32_t>((p + ip_header_len) - base);

    // IP 출력
    char src[64], dst[64];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));
    std::printf("  IPv4: %s -> %s, ihl=%u, ttl=%u, proto=%u\n",
                src, dst, iph->ip_hl, iph->ip_ttl, iph->ip_p);

    const uint8_t* l4 = p + ip_header_len;
    uint32_t l4len = len - ip_header_len;
    uint32_t header_len = ip_header_len;

    // TCP 파싱
    if (iph->ip_p == IPPROTO_TCP && l4len >= sizeof(tcphdr)) {
        const tcphdr* th = reinterpret_cast<const tcphdr*>(l4);
        uint32_t tcp_hdr_len = static_cast<uint32_t>(th->doff) * 4U;

        // TCP 헤더 정보 저장
        rec.sport       = ntohs(th->source);
        rec.dport       = ntohs(th->dest);
        rec.tcp_seq     = ntohl(th->seq);
        rec.tcp_ack     = ntohl(th->ack_seq);
        rec.tcp_flags   = static_cast<uint8_t>((th->urg<<5)|(th->ack<<4)|(th->psh<<3)|(th->rst<<2)|(th->syn<<1)|th->fin);
        rec.tcp_hdr_len = static_cast<uint8_t>(tcp_hdr_len);
        rec.l4_hdr_len  = rec.tcp_hdr_len;

        std::printf("    TCP: %u -> %u, seq=%u, ack=%u, flags=0x%02x, win=%u\n",
            ntohs(th->source), ntohs(th->dest),
            ntohl(th->seq), ntohl(th->ack_seq),
            rec.tcp_flags,
            ntohs(th->window));

        header_len += tcp_hdr_len;
        if (l4len > tcp_hdr_len) {
            print_payload(l4 + tcp_hdr_len, l4len - tcp_hdr_len);
        }
    } else if (iph->ip_p == IPPROTO_UDP && l4len >= sizeof(udphdr)) {
        // UDP 헤더 정보 저장
        const udphdr* uh = reinterpret_cast<const udphdr*>(l4);
        rec.sport      = ntohs(uh->source);
        rec.dport      = ntohs(uh->dest);
        rec.l4_hdr_len = sizeof(udphdr);

        std::printf("    UDP: %u -> %u, len=%u\n",
                    ntohs(uh->source), ntohs(uh->dest), ntohs(uh->len));
        if (l4len >= sizeof(udphdr)) {
            print_payload(l4 + sizeof(udphdr), l4len - sizeof(udphdr));
        }
    } else if (iph->ip_p == IPPROTO_ICMP && l4len >= 2) {
        // ICMP 헤더 정보는 넘어감.
        rec.l4_hdr_len = 0;
        std::printf("    ICMP: type=%u code=%u\n", l4[0], l4[1]);
    }
}

// ARP 파싱
static void print_arp(const uint8_t* p, uint32_t len, PacketRecord&) {
    if (len < sizeof(ether_arp)) { std::puts("  ARP: len too small"); return; }
    const ether_arp* arp = reinterpret_cast<const ether_arp*>(p);
    char spa[64], tpa[64];
    inet_ntop(AF_INET, arp->arp_spa, spa, sizeof(spa));
    inet_ntop(AF_INET, arp->arp_tpa, tpa, sizeof(tpa));
    std::printf("  ARP: op=%u, %s -> %s\n", ntohs(arp->ea_hdr.ar_op), spa, tpa);
}

// IPv6 파싱
static void print_ipv6(const uint8_t* p, uint32_t len, PacketRecord& rec, const uint8_t*) {
    if (len < sizeof(ip6_hdr)) { std::puts("  IPv6: len too small"); return; }
    const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(p);
    rec.ip_version = 6;
    rec.l4_proto   = ip6->ip6_nxt;

    char src[128], dst[128];
    inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
    std::printf("  IPv6: %s -> %s, nh=%u, hlim=%u\n",
                src, dst, ip6->ip6_nxt, ip6->ip6_hlim);
}

// EtherType에 따라 파싱 분기
static void print_l3_by_ethertype(uint16_t ethertype, const uint8_t* l3, uint32_t l3len, PacketRecord& rec, const uint8_t* base) {
    switch (ethertype) {
        case ETHERTYPE_IP:   print_ipv4(l3, l3len, rec, base); break;
        case ETHERTYPE_ARP:  print_arp(l3, l3len, rec);  break;
        case ETHERTYPE_IPV6: print_ipv6(l3, l3len, rec, base); break;
        default:
            std::printf("  L3: EtherType=0x%04x (not parsed)\n", ethertype);
    }
}

// ===== 인터페이스 목록 출력 =====
static void list_interfaces() {
    pcap_if_t* alldevs = nullptr;
    char err[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_findalldevs(&alldevs, err) != 0) {
        std::fprintf(stderr, "pcap_findalldevs error: %s\n", err);
        return;
    }
    std::puts("Available interfaces:");
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::printf("  %s  (%s)\n", d->name, d->description ? d->description : "");
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (!a->addr) continue;
            char buf[128] = {0};
            if (a->addr->sa_family == AF_INET) {
                auto* sin = reinterpret_cast<sockaddr_in*>(a->addr);
                inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                std::printf("     - IPv4: %s\n", buf);
            } else if (a->addr->sa_family == AF_INET6) {
                auto* sin6 = reinterpret_cast<sockaddr_in6*>(a->addr);
                inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
                std::printf("     - IPv6: %s\n", buf);
            }
        }
    }
    pcap_freealldevs(alldevs);
}

// ===== Signal 핸들러 =====
static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
    if (g_pcap) pcap_breakloop(g_pcap);
}

// ===== Packet handler (C API 콜백이므로 extern "C" 시그니처 준수) =====
// pcap_loop에서 패킷 들어올 때 마다 호출됨.
static void handle_packet_cb(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
    (void)user;

    std::puts("=== Packet ===");
    std::printf("ts: %ld.%06ld  caplen: %u  len: %u\n",
                static_cast<long>(h->ts.tv_sec),
                static_cast<long>(h->ts.tv_usec),
                h->caplen, h->len);

    int dlt = pcap_datalink(g_pcap);
    std::printf("DLT: %d (%s)\n", dlt, dlt_name(dlt));

    // PacketRecord 객체 동적 할당
    auto rec = std::make_unique<PacketRecord>();
    rec->ts_ns  = tv_to_ns(h->ts);
    rec->caplen = h->caplen;
    rec->wirelen= h->len;
    rec->dlt    = dlt;
    rec->l2_off = 0;

    const uint8_t* p = bytes;
    uint32_t rem = h->caplen;

    // 이더넷 헤더 파싱
    if (dlt == DLT_EN10MB) {
        if (rem < sizeof(ether_header)) { std::puts(" L2: truncated"); return; }
        const auto* eth = reinterpret_cast<const ether_header*>(p);

        std::memcpy(rec->dst_mac.data(), eth->ether_dhost, 6);
        std::memcpy(rec->src_mac.data(), eth->ether_shost, 6);
        rec->ethertype = ntohs(eth->ether_type);

        char smac[18], dmac[18];
        std::snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
                      eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                      eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        std::snprintf(dmac, sizeof(dmac), "%02x:%02x:%02x:%02x:%02x:%02x",
                      eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                      eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        uint16_t etype = ntohs(eth->ether_type);
        std::printf(" L2 Ethernet: %s -> %s  EtherType=0x%04x\n", smac, dmac, etype);

        p += sizeof(*eth); rem -= sizeof(*eth);
        rec->l3_off = static_cast<uint32_t>(p - bytes);

        print_l3_by_ethertype(etype, p, rem, *rec, bytes);

    } else if (dlt == DLT_LINUX_SLL) {
        // Linux SLL 헤더
        if (rem < sizeof(sll_header)) { std::puts(" L2: truncated"); return; }
        const auto* sll = reinterpret_cast<const sll_header*>(p);
        uint16_t proto = ntohs(sll->proto);
        std::printf(" L2 SLL: pkttype=%u hatype=%u halen=%u proto=0x%04x\n",
                    ntohs(sll->pkttype), ntohs(sll->hatype), ntohs(sll->halen), proto);
        p += sizeof(*sll); rem -= sizeof(*sll);

        print_l3_by_ethertype(proto, p, rem, *rec, bytes);

    } else if (dlt == DLT_RAW) {
        if (rem >= 1) {
            uint8_t v = (p[0] >> 4) & 0xF;
            if (v == 4) print_ipv4(p, rem, *rec, bytes);
            else if (v == 6) print_ipv6(p, rem, *rec, bytes);
            else std::printf(" L3: unknown IP version byte0=0x%02x\n", p[0]);
        }
    } else {
        std::puts(" L2 parser not implemented for this DLT");
    }

    // payload 계산
    if (rec->l4_off && rec->l4_hdr_len && rec->caplen >= rec->l4_off + rec->l4_hdr_len) {
        uint32_t after_l4 = rec->l4_off + rec->l4_hdr_len;
        if (rec->caplen >= after_l4) {
            rec->payload_off = after_l4;
            rec->payload_len = rec->caplen - after_l4;
        } else {
            rec->payload_off = rec->payload_len = 0;
        }
    } else {
        rec->payload_off = rec->payload_len = 0;
    }

    // payload 일부 복사
    if (rec->payload_len) {
        uint32_t to_copy = rec->payload_len > PAYLOAD_STORE_LIMIT ? PAYLOAD_STORE_LIMIT : rec->payload_len;
        rec->payload_copy.assign(bytes + rec->payload_off, bytes + rec->payload_off + to_copy);
    }

    g_sess.update_from_packet(*rec);
    g_pkts.push(std::move(rec));
}

// ===== main =====
int main(int argc, char** argv) {
    signal(SIGINT, on_sigint);

    if (argc == 1) {
        std::puts("Usage: sudo ./pcap_inspect <iface> [bpf_filter] [nano]");
        list_interfaces();
        return 0;
    }

    const char* dev = argv[1];
    const char* bpf = (argc >= 3 && std::strcmp(argv[2], "nano") != 0) ? argv[2] : nullptr;
    bool want_nano = (argc >= 3 && std::strcmp(argv[2], "nano") == 0)
                  || (argc >= 4 && std::strcmp(argv[3], "nano") == 0);

    char err[PCAP_ERRBUF_SIZE] = {0};
    g_pcap = pcap_create(dev, err);
    if (!g_pcap) {
        std::fprintf(stderr, "pcap_create: %s\n", err);
        return 1;
    }

    // 옵션
    pcap_set_snaplen(g_pcap, 65535);
    pcap_set_promisc(g_pcap, 1);
    pcap_set_timeout(g_pcap, 500);
    pcap_set_buffer_size(g_pcap, 4*1024*1024);
    if (want_nano) {
        if (pcap_set_tstamp_precision(g_pcap, PCAP_TSTAMP_PRECISION_NANO) != 0) {
            std::fprintf(stderr, "WARNING: nano precision not supported, fallback to usec\n");
        }
    }

    int rc = pcap_activate(g_pcap);
    if (rc < 0) {
        std::fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(g_pcap));
        return 2;
    }
    if (rc > 0) {
        std::fprintf(stderr, "pcap_activate warning: %s\n", pcap_geterr(g_pcap));
    }

    std::printf("Opened %s  dlt=%d (%s)\n",
                dev, pcap_datalink(g_pcap), dlt_name(pcap_datalink(g_pcap)));

    if (bpf && *bpf) {
        bpf_program fp{};
        if (pcap_compile(g_pcap, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            std::fprintf(stderr, "pcap_compile('%s'): %s\n", bpf, pcap_geterr(g_pcap));
            return 3;
        }
        if (pcap_setfilter(g_pcap, &fp) != 0) {
            std::fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(g_pcap));
            pcap_freecode(&fp);
            return 4;
        }
        pcap_freecode(&fp);
        std::printf("BPF applied: %s\n", bpf);
    }

    std::puts("Start capturing... (Ctrl+C to stop)");
    pcap_loop(g_pcap, -1, handle_packet_cb, nullptr);

    // 통계
    pcap_stat st{};
    if (pcap_stats(g_pcap, &st) == 0) {
        std::printf("\nCapture stats: ps_recv=%u ps_drop=%u ps_ifdrop=%u\n",
                    st.ps_recv, st.ps_drop, st.ps_ifdrop);
    }

    std::printf("[packetlist] count=%zu\n", g_pkts.size());
    std::puts("[packetlist] tail 5 packets:");
    g_pkts.dump_tail(5);

    g_sess.dump_top(10);

    if (g_pcap) { pcap_close(g_pcap); g_pcap = nullptr; }
    g_pkts.clear();
    std::puts("bye");
    return 0;
}
