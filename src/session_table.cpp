#include "session_table.h"
#include <algorithm>
#include <cstdio>
#include <cmath>
#include <arpa/inet.h>

SessionTable::KeyDir SessionTable::canonical_from_packet(const PacketRecord& pr){
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
void SessionTable::update_from_packet(const PacketRecord& pr) 
{
    if (!(pr.ip_version==4) || (pr.l4_proto!=6 && pr.l4_proto!=17)) return; // TCP/UDP만
    //key direction결정
    auto kd = canonical_from_packet(pr);
    //세션 데이터를 확인하고, 만약 첫 데이터면 세션키 등록, 시간 등록, tcp 등록
    auto& sess = map[kd.key];
    if (sess.first_ts_ns==0) {
        sess.key = kd.key;
        sess.first_ts_ns = pr.ts_ns;
        sess.is_tcp = (pr.l4_proto==6);
    }
    //마지막 ts값으로 잡은 패킷값 처리.
    sess.last_ts_ns = pr.ts_ns;

    //방향에 맞는 세션 스탯 가져와서 거기에 패킷 데이터 저장.
    DirStats& d = sess.dir[kd.dir];
    d.pkts  += 1;
    d.bytes += pr.wirelen;
    d.last_ts_ns = pr.ts_ns;

    // TCP 상태/RTT
    if (sess.is_tcp) update_tcp(sess, kd.dir, pr);
}

//display tool
void SessionTable::dump_top(size_t N) const {
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
        std::printf(
            "%2zu) %s:%u <-> %s:%u  proto=%u  bytes=%llu  pkts=%llu  "
            "state=%s  rtt_syn=%.2fms  rtt_ack=%.2fms\n"
            "    A->B: inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n"
            "    B->A: inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n",
            i+1, a, s.key.sport, b, s.key.dport, s.key.proto,
            (unsigned long long)rows[i].bytes,
            (unsigned long long)(s.dir[0].pkts + s.dir[1].pkts),
            tcp_state_name(s.state),
            s.rtt_syn_ms, s.rtt_ack_ms,
            s.dir[0].inst_bps, s.dir[0].ewma_bps,
            (unsigned long long)s.dir[0].retrans_pkts, (unsigned long long)s.dir[0].ooo_pkts, s.dir[0].dup_ack_run,
            s.dir[1].inst_bps, s.dir[1].ewma_bps,
            (unsigned long long)s.dir[1].retrans_pkts, (unsigned long long)s.dir[1].ooo_pkts, s.dir[1].dup_ack_run
        );
    }
}

//ip port 크기비교
bool SessionTable::less_pair(uint32_t ip1, uint16_t p1, uint32_t ip2, uint16_t p2) {
    if (ip1!=ip2) return ip1<ip2;
    return p1<=p2;
}

// state name
const char* SessionTable::tcp_state_name(TcpState st){
    switch(st){
        case TcpState::NONE: return "NONE";
        case TcpState::SYN_SENT: return "SYN_SENT";
        case TcpState::SYN_RECV: return "SYN_RECV";
        case TcpState::ESTABLISHED: return "ESTABLISHED";
        case TcpState::MID_ESTABLISHED: return "MID_ESTABLISHED";
        case TcpState::FIN: return "FIN";
        case TcpState::RST: return "RST";
        case TcpState::CLOSED: return "CLOSED";
    }
    return "?";
}

//throughput 계산식
void SessionTable::update_throughput_window(DirStats& d, uint64_t now_ns, uint64_t add_bytes) {
    if (d.win_start_ns==0) d.win_start_ns = now_ns;
    d.win_bytes += add_bytes;
    uint64_t dt_ns = now_ns - d.win_start_ns;
    if (dt_ns >= 1000000000ull) { // 1초
        double secs = ns_to_sec(dt_ns);
        double bps  = (secs>0.0) ? (d.win_bytes * 8.0) / secs : 0.0;
        d.inst_bps = bps;

        // EWMA (tau = 3s 권장) ||(1-a)*ewma_bps + a+bps; a = 1-e^(-s/t);||
        double tau = 3.0;
        double alpha = 1.0 - std::exp(-secs / tau);
        d.ewma_bps = (1.0 - alpha) * d.ewma_bps + alpha * bps;

        d.win_start_ns = now_ns;
        d.win_bytes = 0;
    }
}

//relative sequence = 초기 seq값 0으로 보는거.
uint32_t SessionTable::rel_seq(const Session& s, int dir, uint32_t seq) {
    if (!s.isn_set[dir]) return seq; // ISN 미설정 시 원시값
    return seq - s.isn[dir];         // 32비트 wrap-safe
}

//패킷, 방향, 세션값으로 tcp 상태 확인하는 블록
void SessionTable::update_tcp(Session& s, int dir, const PacketRecord& pr){
    // 플래그
    const uint8_t f = pr.tcp_flags;
    const bool SYN = f & 0x02;
    const bool ACK = f & 0x10;
    const bool FIN = f & 0x01;
    const bool RST = f & 0x04;

    // 상태전이(아주 단순화)
    if (s.state == TcpState::NONE && !SYN) {
        s.state = TcpState::MID_ESTABLISHED;
        s.midstream = true;
        // rel_seq()가 먹히도록 해당 방향의 베이스라인을 바로 박제
        if (!s.isn_set[dir]) { s.isn[dir] = pr.tcp_seq; s.isn_set[dir] = true; }
    }
    if (SYN && !ACK) {                 // A->B SYN
        s.state = TcpState::SYN_SENT;
        s.syn_ts_valid = true;
        s.syn_ts_ns = pr.ts_ns;
        if(!s.isn_set[dir]){ s.isn[dir]= pr.tcp_seq; s.isn_set[dir]=true; }
    } else if (SYN && ACK) {           // B->A SYN-ACK
        s.state = TcpState::SYN_RECV;
        if (s.syn_ts_valid && s.rtt_syn_ms < 0) {
            s.rtt_syn_ms = (pr.ts_ns - s.syn_ts_ns) / 1e6; // ms
        }
        // ISN(B->A) (SYN-ACK의 seq도 ISN)
        if (!s.isn_set[dir]) { s.isn[dir] = pr.tcp_seq; s.isn_set[dir]=true; }
    } else if (ACK && !SYN && !FIN && !RST) {
        if (s.state==TcpState::SYN_RECV || s.state==TcpState::SYN_SENT)
            s.state = TcpState::ESTABLISHED;
    }
    if (FIN) s.state = TcpState::FIN;
    if (RST) s.state = TcpState::RST;

    // 양방향 관측되면 MID->ESTABLISHED
    if (s.state == TcpState::MID_ESTABLISHED && (s.dir[0].pkts > 0 && s.dir[1].pkts > 0)) {
        s.state = TcpState::ESTABLISHED;  
    }

    // 방향별 seq/ack 저장
    DirStats& me = s.dir[dir];
    DirStats& peer = s.dir[dir^1];
    me.last_seq = pr.tcp_seq;
    me.last_ack = pr.tcp_ack;

    if (pr.tcp_ts_present) {
        // 내가 '이 방향'에서 보낸 TSval 기록 (항상)
        me.ts_recent_val = pr.tcp_ts_val;
        me.ts_recent_time_ns = pr.ts_ns;
        me.ts_recent_valid = true;

        // ▼ '상대가 나의 마지막 데이터'를 확인하는 ACK 순간에만 TS RTT 측정
        if (ACK && peer.have_last_data) {
            uint32_t rack = rel_seq(s, dir, pr.tcp_ack);
            if (rack >= peer.last_data_seq_end &&
                peer.ts_recent_valid &&
                pr.tcp_ts_ecr != 0 &&
                pr.tcp_ts_ecr == peer.ts_recent_val) {

                const int64_t dt_ns = (int64_t)pr.ts_ns - (int64_t)peer.ts_recent_time_ns;
                // 0 <= RTT <= 3000ms (환경에 맞게 튜닝)
                if (dt_ns >= 0 && dt_ns <= 3000LL*1000*1000) {
                    s.rtt_ack_ms = (double)dt_ns / 1e6;
                }
                // 같은 TSval 반복 매칭 방지/다음 샘플을 위해 정리
                peer.have_last_data = false;
                peer.ts_recent_valid = false;
            }
        }
    }

    update_throughput_window(me, pr.ts_ns, pr.wirelen);

    // 페이로드가 있으면(헤더 이후 바이트) 데이터 전송으로 간주 → RTT 샘플 대상
    if (pr.payload_len>0) {
        uint32_t rseq      = rel_seq(s, dir, pr.tcp_seq);
        uint32_t rseq_end  = rseq + pr.payload_len;
        // TCP seq는 첫 바이트 기준, seq_end = seq + payload_len
        me.last_data_seq_end = rseq_end;
        me.have_last_data = true;
        me.last_data_ts_ns = pr.ts_ns;
        // --- 재전송/OOO 감지 ---
        // 1) rseq_end <= highest_seq_end : 완전 과거 범위 → 재전송으로 카운트
        // 2) rseq < highest_seq_end      : 일부 겹침 → 재전송으로 카운트
        if (rseq_end <= me.highest_seq_end) {
            me.retrans_pkts++;
        } else if (rseq < me.highest_seq_end) {
            me.retrans_pkts++;
            // 새 데이터의 우측 끝으로 확장
            me.highest_seq_end = std::max(me.highest_seq_end, rseq_end);
        } else {
            // 순방향 최신 데이터. 다만 큰 점프는 OOO로 참고 표기
            if (rseq > me.highest_seq_end && me.highest_seq_end!=0) {
                me.ooo_pkts++;
            }
            me.highest_seq_end = std::max(me.highest_seq_end, rseq_end);
        }
    }

    // 반대편 ACK가 내 last_data_seq_end를 확인하면 RTT 산출
    if (peer.have_last_data && ACK) {
        uint32_t rack = rel_seq(s, dir, pr.tcp_ack);
        if (rack >= peer.last_data_seq_end) {
            double ms = (pr.ts_ns - peer.last_data_ts_ns) / 1e6;
            if (ms >= 0.0 && ms <= 3000) s.rtt_ack_ms = ms;
            peer.have_last_data = false;
        }
    }

    // --- 중복 ACK 감지 (ACK only & ack 번호 정체) ---
    // 데이터/FIN/RST 없는 '순수 ACK'로 제한
    bool ack_only = (ACK && pr.payload_len==0 && !SYN && !FIN && !RST);
    if (ack_only) {
        uint32_t rack = rel_seq(s, dir, pr.tcp_ack);
        if (me.last_ack_val == rack) {
            me.dup_ack_run++;
        } else {
            me.last_ack_val = rack;
            me.dup_ack_run = 0;
        }
        // me.dup_ack_run >= 2 → "3중복 ACK" 달성 (0부터 세면 2가 3번째)
        // 필요하면 세션 단위로 "혼잡/손실 의심 이벤트" 카운트 추가 가능
    }
}