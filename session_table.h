// session_table.hpp
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <vector>
#include <cstdio>
#include <arpa/inet.h>
#include "packet_record.h"

struct FiveTuple {
    uint32_t sip{};
    uint32_t dip{};
    uint16_t sport{};
    uint16_t dport{};
    uint8_t  proto{}; // 6=TCP,17=UDP

    // 캐노니컬 정렬: (sip,sport) <= (dip,dport) 이면 그대로, 아니면 swap
    // 이 구조체 자체는 "정규화된" 키만 저장하는 용도
    bool operator==(const FiveTuple& o) const {
        return sip==o.sip && dip==o.dip && sport==o.sport && dport==o.dport && proto==o.proto;
    }
};
struct FiveTupleHash {
    size_t operator()(const FiveTuple& k) const noexcept {
        // 간단한 합성 해시
        size_t h = 1469598103934665603ull; // FNV offset basis
        auto mix = [&](uint64_t v){ h ^= v; h *= 1099511628211ull; };
        mix(k.sip); mix(k.dip);
        mix(((uint64_t)k.sport<<16) | k.dport);
        mix(k.proto);
        return h;
    }
};

struct DirStats {
    uint64_t pkts{0}, bytes{0};
    uint64_t last_ts_ns{0};
    uint32_t last_seq{0}, last_ack{0};
    // 매우 단순한 RTT 측정을 위해 최근 전송 데이터의 seq_end 저장
    uint32_t last_data_seq_end{0};
    bool     have_last_data{false};
};

enum class TcpState : uint8_t {
    NONE, SYN_SENT, SYN_RECV, ESTABLISHED, FIN, RST, CLOSED
};

struct Session {
    FiveTuple key{};
    uint64_t first_ts_ns{0}, last_ts_ns{0};
    DirStats dir[2]; // 0=정규화 기준 (A->B), 1=반대(B->A)
    bool is_tcp{false};

    // TCP 상태/RTT
    TcpState state{TcpState::NONE};
    // SYN RTT
    bool     syn_ts_valid{false};
    uint64_t syn_ts_ns{0};      // A->B SYN 시간
    double   rtt_syn_ms{-1.0};  // SYN/SYN-ACK RTT (ms)

    // ACK 기반 최근 RTT 샘플
    double   rtt_ack_ms{-1.0};
};

class SessionTable {
public:
    // 세션 저장소
    std::unordered_map<FiveTuple, Session, FiveTupleHash> map;

    // 패킷으로부터 키 생성 + 방향 판정
    // ret.dir = 0 (A->B) or 1 (B->A) in canonical orientation.
    struct KeyDir { FiveTuple key; int dir; };
    static KeyDir canonical_from_packet(const PacketRecord& pr) {
        KeyDir kd{};
        kd.key.proto = pr.l4_proto;
        kd.key.sip   = pr.ipv4_src;
        kd.key.dip   = pr.ipv4_dst;
        kd.key.sport = pr.sport;
        kd.key.dport = pr.dport;
        // sort by (ip,port) pair
        bool keep = less_pair(kd.key.sip, kd.key.sport, kd.key.dip, kd.key.dport);
        if (!keep) {
            std::swap(kd.key.sip, kd.key.dip);
            std::swap(kd.key.sport, kd.key.dport);
            kd.dir = 1; // original was B->A
        } else {
            kd.dir = 0; // original was A->B
        }
        return kd;
    }

    // 세션 업데이트
    void update_from_packet(const PacketRecord& pr) {
        if (!(pr.ip_version==4) || (pr.l4_proto!=6 && pr.l4_proto!=17)) return; // TCP/UDP만

        auto kd = canonical_from_packet(pr);
        auto& sess = map[kd.key];
        if (sess.first_ts_ns==0) {
            sess.key = kd.key;
            sess.first_ts_ns = pr.ts_ns;
            sess.is_tcp = (pr.l4_proto==6);
        }
        sess.last_ts_ns = pr.ts_ns;

        DirStats& d = sess.dir[kd.dir];
        d.pkts  += 1;
        d.bytes += pr.wirelen;
        d.last_ts_ns = pr.ts_ns;

        // TCP 상태/RTT
        if (sess.is_tcp) update_tcp(sess, kd.dir, pr);
    }

    // 상위 N 세션(바이트 합계 기준) 덤프
    void dump_top(size_t N = 10) const {
        struct Row{
            const Session* s; uint64_t bytes;
        };
        std::vector<Row> rows;
        rows.reserve(map.size());
        for (auto& kv : map) {
            uint64_t b = kv.second.dir[0].bytes + kv.second.dir[1].bytes;
            rows.push_back({ &kv.second, b });
        }
        std::sort(rows.begin(), rows.end(), [](auto& a, auto& b){ return a.bytes>b.bytes; });
        if (rows.size()>N) rows.resize(N);

        std::puts("\n[session] top sessions:");
        for (size_t i=0;i<rows.size();++i) {
            const Session& s = *rows[i].s;
            char a[64]={0}, b[64]={0};
            in_addr ia{.s_addr=s.key.sip}, ib{.s_addr=s.key.dip};
            inet_ntop(AF_INET, &ia, a, sizeof(a));
            inet_ntop(AF_INET, &ib, b, sizeof(b));
            std::printf("%2zu) %s:%u <-> %s:%u  proto=%u  bytes=%llu  pkts=%llu "
                        "state=%s  rtt_syn=%.2fms  rtt_ack=%.2fms\n",
                i+1, a, ntohs(s.key.sport), b, ntohs(s.key.dport), s.key.proto,
                (unsigned long long)rows[i].bytes,
                (unsigned long long)(s.dir[0].pkts + s.dir[1].pkts),
                tcp_state_name(s.state),
                s.rtt_syn_ms, s.rtt_ack_ms);
        }
    }

private:
    static bool less_pair(uint32_t ip1, uint16_t p1, uint32_t ip2, uint16_t p2) {
        if (ip1!=ip2) return ip1<ip2;
        return p1<=p2;
    }

    static const char* tcp_state_name(TcpState st){
        switch(st){
            case TcpState::NONE: return "NONE";
            case TcpState::SYN_SENT: return "SYN_SENT";
            case TcpState::SYN_RECV: return "SYN_RECV";
            case TcpState::ESTABLISHED: return "ESTABLISHED";
            case TcpState::FIN: return "FIN";
            case TcpState::RST: return "RST";
            case TcpState::CLOSED: return "CLOSED";
        }
        return "?";
    }

    static void update_tcp(Session& s, int dir, const PacketRecord& pr){
        // 플래그
        const uint8_t f = pr.tcp_flags;
        const bool SYN = f & 0x02;
        const bool ACK = f & 0x10;
        const bool FIN = f & 0x01;
        const bool RST = f & 0x04;

        // 상태전이(아주 단순화)
        if (SYN && !ACK) {                 // A->B SYN
            if (dir==0) {
                s.state = TcpState::SYN_SENT;
                s.syn_ts_valid = true; s.syn_ts_ns = pr.ts_ns;
            } else {
                s.state = TcpState::SYN_RECV; // 비정상/재전송 케이스일 수도
            }
        } else if (SYN && ACK) {           // B->A SYN-ACK
            s.state = TcpState::SYN_RECV;
            if (dir==1 && s.syn_ts_valid && s.rtt_syn_ms<0) {
                s.rtt_syn_ms = (pr.ts_ns - s.syn_ts_ns) / 1e6; // ms
            }
        } else if (ACK && !SYN && !FIN && !RST) {
            if (s.state==TcpState::SYN_RECV || s.state==TcpState::SYN_SENT)
                s.state = TcpState::ESTABLISHED;
        }
        if (FIN) s.state = TcpState::FIN;
        if (RST) s.state = TcpState::RST;

        // 방향별 seq/ack 저장
        DirStats& me = s.dir[dir];
        DirStats& peer = s.dir[dir^1];
        me.last_seq = pr.tcp_seq;
        me.last_ack = pr.tcp_ack;

        // 페이로드가 있으면(헤더 이후 바이트) 데이터 전송으로 간주 → RTT 샘플 대상
        if (pr.payload_len>0) {
            // TCP seq는 첫 바이트 기준, seq_end = seq + payload_len
            me.last_data_seq_end = pr.tcp_seq + pr.payload_len;
            me.have_last_data = true;
        }
        // 반대편 ACK가 내 last_data_seq_end를 확인하면 RTT 산출
        if (peer.have_last_data && ACK) {
            if (pr.tcp_ack >= peer.last_data_seq_end) {
                double ms = (pr.ts_ns - peer.last_ts_ns) / 1e6; // 아주 러프한 근사
                if (ms >= 0.0) s.rtt_ack_ms = ms;
                peer.have_last_data = false; // 한 번 소모
            }
        }
    }
};
