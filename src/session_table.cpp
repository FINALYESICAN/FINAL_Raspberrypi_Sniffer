#include "session_table.h"
#include <algorithm>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <arpa/inet.h>

// 상태별 권장 idle 타임아웃
static inline uint64_t tcp_idle_to(const Session& s, const SessionTimeouts& t)
{
    switch (s.state) {
        case TcpState::ESTABLISHED:     return t.tcp_est_ns;
        case TcpState::MID_ESTABLISHED: return t.tcp_mid_ns;
        case TcpState::SYN_SENT:
        case TcpState::SYN_RECV:        return t.tcp_handshake_ns;
        case TcpState::FIN:
        case TcpState::RST:
        case TcpState::CLOSED:          return t.closed_grace_ns; // 곧바로 정리 후보
        case TcpState::NONE:            return t.tcp_handshake_ns;
    }
    return t.tcp_mid_ns;
}

// session_table.cpp (새 함수) : 첫 TCP 패킷들로 client/server 확정
static void decide_tcp_direction_on_first(Session& s, int kd_dir, const PacketRecord& pr){
    const bool SYN = pr.tcp_flags & 0x02;
    const bool ACK = pr.tcp_flags & 0x10;

    if (SYN && !ACK) {             // 순수 SYN = 클라이언트
        s.client_ip   = pr.ipv4_src;
        s.client_port = pr.sport;
        s.server_ip   = pr.ipv4_dst;
        s.server_port = pr.dport;
        // 이번 패킷의 캐노니컬 방향(kd_dir)이 A->B(0)라면 A가 client, 아니면 B가 client
        s.client_is_A = (kd_dir == 0);
        s.direction_known = true;
    } else if (SYN && ACK) {       // SYN-ACK = 서버 응답
        s.client_ip   = pr.ipv4_dst;
        s.client_port = pr.dport;
        s.server_ip   = pr.ipv4_src;
        s.server_port = pr.sport;
        s.client_is_A = (kd_dir == 1); // 이 경우 보통 B->A(1)이므로 B가 client
        s.direction_known = true;
    } else if (!s.direction_known) {
        // 미드스트림/애매하면 임시 휴리스틱 (포트 비교 등)
        if (pr.sport > pr.dport) {
            s.client_ip = pr.ipv4_src; s.client_port = pr.sport;
            s.server_ip = pr.ipv4_dst; s.server_port = pr.dport;
            s.client_is_A = (kd_dir == 0);
        } else {
            s.client_ip = pr.ipv4_dst; s.client_port = pr.dport;
            s.server_ip = pr.ipv4_src; s.server_port = pr.sport;
            s.client_is_A = (kd_dir == 1);
        }
        s.direction_known = false; // 휴리스틱은 ‘임시’로 표시(나중에 SYN/SYN-ACK 오면 덮어씀)
    }
}

// 이번 패킷이 의미상 C->S(0)인지 S->C(1)인지 계산하고, 그걸 A/B 인덱스로 변환
static int map_logical_dir_to_AB(const Session&  s, const PacketRecord& pr, int kd_dir){
    // 의미 방향 계산: client_ip/port와 src가 같으면 C->S(0), 아니면 S->C(1)
    int logical = 0; // 0=C->S, 1=S->C
    if (s.direction_known) {
        bool from_client = (pr.ipv4_src == s.client_ip && pr.sport == s.client_port);
        logical = from_client ? 0 : 1;
    } else {
        // 아직 모르면 캐노니컬 방향(kd_dir)로 대체
        logical = (kd_dir == 0) ? 0 : 1;
    }
    // A/B 인덱스로 변환: A가 client이면 logical 그대로, B가 client면 뒤집기
    return s.client_is_A ? logical : (logical ^ 1);
}

// for throughput 정상화
// 표시 전용 throughput 미리보기(상태는 바꾸지 않음)
struct TpPreview { double inst{0.0}, ewma{0.0}; };

static inline TpPreview preview_throughput(const DirStats& d, uint64_t now_ns)
{
    TpPreview o{d.inst_bps, d.ewma_bps};
    if (d.win_start_ns == 0 || now_ns <= d.win_start_ns) return o;

    uint64_t dt = now_ns - d.win_start_ns;
    double secs = ns_to_sec(dt);
    if (secs <= 0.0) return o;

    double inst = (d.win_bytes > 0) ? (d.win_bytes * 8.0) / secs : 0.0;

    // EWMA 파라미터는 update_throughput_window와 동일하게
    double tau = 3.0;
    double alpha = 1.0 - std::exp(-secs / tau);
    double ewma = (1.0 - alpha) * d.ewma_bps + alpha * inst;

    // 보기 좋게 현재치 반영
    o.inst = std::max(o.inst, inst);
    o.ewma = ewma;
    return o;
}

// print 시 사용할 now_ns 선택
static inline uint64_t pick_now_for_display(const Session& s, uint64_t now_override_ns)
{
    if (now_override_ns) return now_override_ns;
    if (s.last_ts_ns)    return s.last_ts_ns;
    return std::max(s.dir[0].last_ts_ns, s.dir[1].last_ts_ns);
}


// print session
// ordinal>0 이면 "1) ..." 형태, ==0이면 [SESS] 형태의 브리프 라인
static void print_session(const Session& s, size_t ordinal, uint64_t total_bytes, bool detailed, uint64_t now_override_ns = 0)
{
    uint64_t now_ns = pick_now_for_display(s, now_override_ns);
    char a[64]={0}, b[64]={0};
    in_addr ia{.s_addr=s.key.sip}, ib{.s_addr=s.key.dip};
    inet_ntop(AF_INET, &ia, a, sizeof(a));
    inet_ntop(AF_INET, &ib, b, sizeof(b));

    if (ordinal > 0) {
        std::printf(
            "%2zu) %s:%u <-> %s:%u  proto=%u  bytes=%llu  pkts=%llu  "
            "state=%s  rtt_syn=%.2fms  rtt_ack=%.2fms\n",
            (size_t)ordinal,
            a, (unsigned)s.key.sport,
            b, (unsigned)s.key.dport,
            (unsigned)s.key.proto,
            (unsigned long long)total_bytes,
            (unsigned long long)(s.dir[0].pkts + s.dir[1].pkts),
            SessionTable::tcp_state_name(s.state),
            s.rtt_syn_ms, s.rtt_ack_ms
        );
    } else {
        // brief 라인
        const char* roleA = s.direction_known ? (s.client_is_A ? "CLIENT" : "SERVER") : "?";
        const char* roleB = s.direction_known ? (s.client_is_A ? "SERVER" : "CLIENT") : "?";
        std::printf(
            "[SESS] %s:%u(%s) <-> %s:%u(%s) proto=%u pkts=%llu state=%s dirKnown=%d\n"
            "rtt_syn=%.2fms  rtt_ack=%.2fms\n",
            a, s.key.sport, roleA,
            b, s.key.dport, roleB,
            s.key.proto,
            (unsigned long long)(s.dir[0].pkts + s.dir[1].pkts),
            SessionTable::tcp_state_name(s.state),
            (int)s.direction_known,
            s.rtt_syn_ms, s.rtt_ack_ms
        );
    }

    if (!detailed) return;

    if (s.direction_known) {
        // 의미 방향으로 재라벨링: C->S / S->C
        const DirStats& cs = s.client_is_A ? s.dir[0] : s.dir[1]; // C->S
        const DirStats& sc = s.client_is_A ? s.dir[1] : s.dir[0]; // S->C
        // preview for throughput
        TpPreview cs_tp = preview_throughput(cs, now_ns);
        TpPreview sc_tp = preview_throughput(sc, now_ns);

        char cstr[64] = "-", sstr[64] = "-";
        uint16_t cport = 0, sport = 0;
        in_addr ic{.s_addr=s.client_ip}, is{.s_addr=s.server_ip};
        inet_ntop(AF_INET, &ic, cstr, sizeof(cstr));
        inet_ntop(AF_INET, &is, sstr, sizeof(sstr));
        cport = s.client_port; sport = s.server_port;

        std::printf(
            "    Client: %s:%u  Server: %s:%u\n"
            "    C->S:  inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n"
            "    S->C:  inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n",
            cstr, cport, sstr, sport,
            //cs.inst_bps, cs.ewma_bps,
            cs_tp.inst, cs_tp.ewma,
            (unsigned long long)cs.retrans_pkts, (unsigned long long)cs.ooo_pkts, cs.dup_ack_run,
            //sc.inst_bps, sc.ewma_bps,
            sc_tp.inst,  sc_tp.ewma,
            (unsigned long long)sc.retrans_pkts, (unsigned long long)sc.ooo_pkts, sc.dup_ack_run
        );
    } else {
        // A/B 라벨에서도 미리보기 사용
        TpPreview a2b = preview_throughput(s.dir[0], now_ns);
        TpPreview b2a = preview_throughput(s.dir[1], now_ns);
        // 아직 모르면 기존 라벨(A/B)
        std::printf(
            "    A->B: inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n"
            "    B->A: inst=%.1f bps  ewma=%.1f bps  retrans=%llu  ooo=%llu  dupACKrun=%u\n",
            //s.dir[0].inst_bps, s.dir[0].ewma_bps,
            a2b.inst, a2b.ewma,
            (unsigned long long)s.dir[0].retrans_pkts, (unsigned long long)s.dir[0].ooo_pkts, s.dir[0].dup_ack_run,
            //s.dir[1].inst_bps, s.dir[1].ewma_bps,
            b2a.inst, b2a.ewma,
            (unsigned long long)s.dir[1].retrans_pkts, (unsigned long long)s.dir[1].ooo_pkts, s.dir[1].dup_ack_run
        );
    }
}
// 찗은버전
static void dump_session_line(const Session& s){
    uint64_t total_bytes = s.dir[0].bytes + s.dir[1].bytes;
    print_session(s, /*ordinal=*/0, total_bytes, /*detailed=*/false);
}

std::vector<SessionSummary> SessionTable::snapshot_top(size_t N, uint64_t now_ns) const{
    std::vector<SessionSummary> out;
    out.reserve(map.size());
    for (const auto& kv : map) {
        std::lock_guard<std::mutex> lk(mtx);
        const FiveTuple& k = kv.first;
        const Session&   s = kv.second;

        SessionSummary ss;
        ss.key  = k;
        // 합계 바이트/패킷
        ss.bytes     = s.dir[0].bytes + s.dir[1].bytes;
        
        ss.bytes_a2b = s.dir[0].bytes;
        ss.bytes_b2a = s.dir[1].bytes;

        ss.pkts_a2b  = s.dir[0].pkts;
        ss.pkts_b2a  = s.dir[1].pkts;

        // throughput (bps)
        ss.inst_a2b  = s.dir[0].inst_bps;
        ss.inst_b2a  = s.dir[1].inst_bps;
        ss.ewma_a2b  = s.dir[0].ewma_bps;
        ss.ewma_b2a  = s.dir[1].ewma_bps;

        // RTT / 상태 / 방향
        ss.rtt_syn_ms      = s.rtt_syn_ms;
        ss.rtt_ack_ms      = s.rtt_ack_ms;
        ss.state           = s.state;
        ss.direction_known = s.direction_known;
        ss.client_is_A     = s.client_is_A;

        out.push_back(std::move(ss));
    }
    // 바이트 합계 기준 내림차순 정렬 후 상위 N개만
    std::sort(out.begin(), out.end(),
              [](const SessionSummary& a, const SessionSummary& b){
                  return a.bytes > b.bytes;
              });
    if (out.size() > N) out.resize(N);
    return out;
}

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
    std::lock_guard<std::mutex> lock(mtx);
    auto& sess = map[kd.key];

    // 상태 초기화
    bool created_now = false;
    bool direction_became_known = false;
    TcpState prev_state = sess.state;
    
    if (sess.first_ts_ns==0) {
        sess.key = kd.key;
        sess.first_ts_ns = pr.ts_ns;
        sess.is_tcp = (pr.l4_proto==6);
        created_now = true;
    }
    //마지막 ts값으로 잡은 패킷값 처리.
    sess.last_ts_ns = pr.ts_ns;

    //방향에 맞는 세션 스탯 가져와서 거기에 패킷 데이터 저장.
    if(sess.is_tcp){
        bool before = sess.direction_known;
        decide_tcp_direction_on_first(sess, kd.dir, pr);
        if (!before && sess.direction_known) direction_became_known = true;
        // 의미 방향(C->S=0 / S->C=1) → A/B 인덱스로 매핑
        int ab_dir = map_logical_dir_to_AB(sess, pr, kd.dir);

        DirStats& d = sess.dir[ab_dir];
        d.pkts  += 1;
        d.bytes += pr.wirelen;
        d.last_ts_ns = pr.ts_ns;
        update_tcp(sess, ab_dir, pr);
    } else {
        DirStats& d = sess.dir[kd.dir];
        d.pkts  += 1;
        d.bytes += pr.wirelen;
        d.last_ts_ns = pr.ts_ns;
    }

    // ====== 여기서 '변경 이벤트'를 찍는다 ======
    if (created_now) {
        std::puts("[EVT] session_created");
        dump_session_line(sess);
    }
    if (direction_became_known) {
        std::puts("[EVT] direction_decided");
        dump_session_line(sess);
    }
    if (sess.state != prev_state) {
        std::printf("[EVT] tcp_state_change: %s -> %s\n",
            tcp_state_name(prev_state), tcp_state_name(sess.state));
        dump_session_line(sess);
    }
}

// display top 10
void SessionTable::dump_top(size_t N) const {
    // 스냅샷만 잠깐 복사
    std::vector<std::pair<Session, uint64_t>> snap; // (세션복사, bytes)
    {
        std::lock_guard<std::mutex> lk(mtx);
        snap.reserve(map.size());
        for (auto& kv : map) {
            uint64_t b = kv.second.dir[0].bytes + kv.second.dir[1].bytes;
            snap.emplace_back(kv.second, b); // Session 통째 복사
        }
    }
    // 락 해제 후 정렬/출력
    std::sort(snap.begin(), snap.end(),
              [](auto& a, auto& b){ return a.second > b.second; });
    if (snap.size() > N) snap.resize(N);

    std::puts("\n[session] top sessions:");
    for (size_t i=0;i<snap.size();++i) {
        const Session& s = snap[i].first;
        print_session(s,i+1,snap[i].second,true);
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

    auto finalize = [&](uint64_t dt_ns){
        double secs = ns_to_sec(dt_ns);
        double bps  = (secs>0.0) ? (d.win_bytes * 8.0) / secs : 0.0;
        d.inst_bps = bps;

        double tau = 3.0;
        double alpha = 1.0 - std::exp(-secs / tau);
        d.ewma_bps = (1.0 - alpha) * d.ewma_bps + alpha * bps;

        d.win_start_ns = now_ns;
        d.win_bytes = 0;
        d.last_rate_calc_ns = now_ns;
    };

    if (dt_ns >= 1000000000ull) { // 1초
        finalize(dt_ns);
        return;
    }
    if (d.last_rate_calc_ns == 0) 
        d.last_rate_calc_ns = d.win_start_ns;
    uint64_t idle_since_calc = now_ns - d.last_rate_calc_ns;
    if (idle_since_calc >= 300000000ull) {
        finalize(dt_ns ? dt_ns : 1); // dt_ns==0 보호
    }
}

//relative sequence = 초기 seq값 0으로 보는거.
uint32_t SessionTable::rel_seq(const Session& s, int dir, uint32_t seq) {
    if (!s.isn_set[dir]) return seq; // ISN 미설정 시 원시값
    return seq - s.isn[dir];         // 32비트 wrap-safe
}

size_t SessionTable::prune(uint64_t now_ns)
{
    std::lock_guard<std::mutex> lock(mtx);
    size_t removed = 0;
    for (auto it = map.begin(); it != map.end(); ) {
        Session& s = it->second;
        uint64_t idle_ns = (now_ns > s.last_ts_ns) ? (now_ns - s.last_ts_ns) : 0;

        bool fin_or_rst = (s.state == TcpState::FIN || s.state == TcpState::RST || s.closed);

        if (s.is_tcp) {
            if (fin_or_rst) {
                // FIN/RST 관찰: 마지막 활동 후 그레이스 지나면 제거
                if (idle_ns >= timeouts.closed_grace_ns) {
                    std::puts("[PRUNE] FIN/RST grace timeout → removing:");
                    uint64_t total_bytes = s.dir[0].bytes + s.dir[1].bytes;
                    print_session(s, /*ordinal=*/0, total_bytes, /*detailed=*/true);  // ★ 상세 로그
                    it = map.erase(it); ++removed; continue;
                }
            } else {
                if (idle_ns >= tcp_idle_to(s, timeouts)) {
                    std::puts("[PRUNE] TCP idle timeout → removing:");
                    uint64_t total_bytes = s.dir[0].bytes + s.dir[1].bytes;
                    print_session(s, /*ordinal=*/0, total_bytes, /*detailed=*/true);  // ★ 상세 로그
                    it = map.erase(it); ++removed; continue;
                }
            }
        } else {
            // UDP/기타: 단순 idle 타임아웃
            if (idle_ns >= timeouts.udp_ns) {
                std::puts("[PRUNE] UDP idle timeout → removing:");
                uint64_t total_bytes = s.dir[0].bytes + s.dir[1].bytes;
                print_session(s, /*ordinal=*/0, total_bytes, /*detailed=*/true);      // ★ 상세 로그
                it = map.erase(it); ++removed; continue;
            }
        }
        ++it;
    }
    return removed;
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
    if (FIN) {s.state = TcpState::FIN; s.closed = true;}
    if (RST) {s.state = TcpState::RST; s.closed = true;}

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

        // 상대방이 내 tsval을 echo했을 때만 RTT로 인정
        if (peer.ts_recent_valid &&
            pr.tcp_ts_ecr != 0 &&
            pr.tcp_ts_ecr == peer.ts_recent_val)
        {
            const int64_t dt_ns = (int64_t)pr.ts_ns - (int64_t)peer.ts_recent_time_ns;

            // 로컬 즉시-ACK (수십 µs) 무시, 1ms~3000ms 사이만 인정
            if (dt_ns >= 1LL*1000*1000 && dt_ns <= 3000LL*1000*1000) {
                std::printf("[TS-RTT] dir=%d dt=%.3f ms (tsecr=%u)\n",
                            dir, (double)dt_ns/1e6, pr.tcp_ts_ecr);
                s.rtt_ack_ms = (double)dt_ns / 1e6;
            }

            // 같은 TSval 반복 매칭 방지
            peer.ts_recent_valid = false;
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