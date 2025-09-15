// session_table.h
#pragma once

#include "packet_record.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <array>
#include <vector>

static inline double ns_to_sec(uint64_t ns){return ns/1e9;}

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
    //패킷 개수, 바이트수, 마지막 받은시간, 마지막 sequence num, 마지막 ack num
    uint64_t pkts{0}, bytes{0};
    uint64_t last_ts_ns{0};
    uint32_t last_seq{0}, last_ack{0};
    // RTT 측정을 위해 최근 전송 데이터의 seq_end 저장 = last_seq+데이터 바이트수
    uint32_t last_data_seq_end{0};
    bool     have_last_data{false};
    // RTT 타임스템프 추가됨
    bool     ts_recent_valid = false;
    uint32_t ts_recent_val   = 0;      
    uint64_t ts_recent_time_ns = 0;   

    // 마지막 페이로드가 있는 데이터 전송 시각 RTT에서 사용
    uint64_t last_data_ts_ns{0};

    // --- Throughput용 ---
    // 1초 슬라이딩 윈도우(간단): 윈도우 내 바이트/시간으로 즉시 bps 계산
    uint64_t win_start_ns{0};
    uint64_t win_bytes{0};
    double   inst_bps{0.0};    // 직전 윈도우에서 계산된 bps
    double   ewma_bps{0.0};    // 지수평활 - 최근 측정에 가중치 준다.

    // --- 재전송/순서 관련 ---
    uint32_t highest_seq_end{0}; // 지금까지 본 데이터 구간의 최댓값(우측 끝)
    uint64_t retrans_pkts{0};    // 재전송으로 판단된 패킷 수
    uint64_t ooo_pkts{0};        // out-of-order 판단 수(참고 통계)

    // --- 중복 ACK 감지(상대 방향 혼잡/재전송 트리거 힌트) ---
    uint32_t last_ack_val{0};
    uint32_t dup_ack_run{0};
};

enum class TcpState : uint8_t {
    NONE, SYN_SENT, SYN_RECV, ESTABLISHED, MID_ESTABLISHED, FIN, RST, CLOSED
};

struct Session {
    FiveTuple key{}; //세션 키
    uint64_t first_ts_ns{0}, last_ts_ns{0}; //
    //각 방향마다의 패킷 정보, 0=정규화 기준 (A->B), 1=반대(B->A)
    DirStats dir[2];
    bool is_tcp{false};

    // TCP 상태/RTT
    TcpState state{TcpState::NONE};
    bool midstream{false};
    
    // SYN RTT
    bool     syn_ts_valid{false};
    uint64_t syn_ts_ns{0};      // A->B SYN 시간
    double   rtt_syn_ms{-1.0};  // SYN/SYN-ACK RTT (ms)

    // ACK 기반 최근 RTT 샘플
    double   rtt_ack_ms{-1.0};

    // --- 상대 시퀀스 번호 정규화용 Initial Seq Num ---
    bool     isn_set[2]{false,false};
    uint32_t isn[2]{0,0}; // dir별 초기 시퀀스(상대측이 보낸 SYN의 seq)

    // TCP 타임스탬프(있으면 보다 정확한 RTT로 확장 가능)
    bool     tsopt_seen{false};
};

class SessionTable {
public:
    // 세션 저장소
    std::unordered_map<FiveTuple, Session, FiveTupleHash> map;
    // 패킷으로부터 키 생성 + 방향 판정
    // ret.dir = 0 (A->B) or 1 (B->A) in canonical orientation.
    struct KeyDir { FiveTuple key; int dir; };
    
    //packet으로부터 5tuple뽑아서 ip, port에 따라 direction 결정
    static KeyDir canonical_from_packet(const PacketRecord& pr);

    // 세션 업데이트 -> packetRecord를 받음, main에서 불러서 사용
    void update_from_packet(const PacketRecord& pr);
    
    // 상위 N 세션(바이트 합계 기준) 덤프
    void dump_top(size_t N = 10) const;

private:
    static bool less_pair(uint32_t ip1, uint16_t p1, uint32_t ip2, uint16_t p2);

    static const char* tcp_state_name(TcpState st);

    static void update_throughput_window(DirStats& d, uint64_t now_ns, uint64_t add_bytes);

    static uint32_t rel_seq(const Session& s, int dir, uint32_t seq);

    static void update_tcp(Session& s, int dir, const PacketRecord& pr);
};
