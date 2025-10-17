#include "TelemetryServer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>   // memcpy
#include <string>

#include <nlohmann/json.hpp>

#include <poll.h>
#include <fcntl.h>
#include <errno.h>

using nlohmann::json;

static int make_listen(uint16_t port){
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) { 
        perror("socket"); 
        return -1; 
    }

    int one = 1; 
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); close(fd); return -1; }
    if (listen(fd, 1) < 0){ perror("listen"); close(fd); return -1; }
    return fd;
}

static std::string ip_to_str(uint32_t be_ip){
    char buf[64] = {0};
    in_addr ia;
    ia.s_addr = be_ip;
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    return std::string(buf);
}
static std::string tcp_flags_str(uint8_t f){ 
    std::string s; 
    if(f&0x02){s+="S";} 
    if(f&0x10){s+="A";}
    if(f&0x01){s+="F";} 
    if(f&0x04){s+="R";} 
    if(f&0x08){s+="P";}
    if(f&0x20){s+="U";}
    return s; 
}

static std::string b64encode(const uint8_t* data, size_t len){
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve((len+2)/3*4);
    size_t i=0;
    while (i+3 <= len){
        uint32_t v = (data[i]<<16)|(data[i+1]<<8)|data[i+2]; i+=3;
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]);
        out.push_back(T[(v>>6)&63]);  out.push_back(T[v&63]);
    }
    if (i<len){
        uint32_t v = data[i]<<16; 
        if (i+1<len) v |= data[i+1]<<8;
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]);
        out.push_back((i+1<len)?T[(v>>6)&63]:'=');
        out.push_back('=');
    }
    return out;
}

bool TelemetryServer::open_listen(uint16_t port){
    listen_fd_ = make_listen(port);
    if(listen_fd_<0) return false;
    int fl  =fcntl(listen_fd_, F_GETFL,0);
    fcntl(listen_fd_, F_SETFL, fl|O_NONBLOCK);
    return true;
}

bool TelemetryServer::start(SessionTable* table, PacketList* pkts, uint16_t port, int period_ms){
    if (!table) return false;
    sess_ = table;
    pkts_ = pkts;
    period_ms_ = period_ms;
    if (!open_listen(port)) return false;
    running_ = true;
    th_ = std::thread(&TelemetryServer::loop, this);
    std::printf("[TEL] started on port %u, period=%dms\n", port, period_ms_.load());
    return true;
}

void TelemetryServer::stop(){
    running_ = false;
    if (client_fd_ >= 0) { ::shutdown(client_fd_, SHUT_RDWR);close(client_fd_); client_fd_ = -1; }
    if (listen_fd_ >= 0) { ::shutdown(listen_fd_, SHUT_RDWR);close(listen_fd_); listen_fd_ = -1; }
    if (th_.joinable()) th_.join();
    std::puts("[TEL] stopped");
}

void TelemetryServer::set_period_ms(int ms){
    if (ms < 100) ms = 100;
    period_ms_ = ms;
}

void TelemetryServer::loop(){
    using namespace std::chrono;
    pollfd pfd{listen_fd_,POLLIN,0};

    while (running_){
        int pr = ::poll(&pfd,1,500);
        if(!running_)break;
        if (pr < 0){ if (errno==EINTR) continue; else continue; }
        if (pr == 0 || !(pfd.revents & POLLIN)) continue;

        sockaddr_in cli{}; socklen_t cl = sizeof(cli);
        std::puts("[TEL] waiting client...");
        int cfd = ::accept(listen_fd_, (sockaddr*)&cli, &cl);
        
        if (cfd < 0) { continue; }

        client_fd_ = cfd;
        std::printf("[TEL] client connected %s:%u\n",
                    inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));

        pollfd cpol{client_fd_, POLLIN, 0};

        while (running_){
            // 패킷 큐 드레인
            for (int i=0; i<500 && running_; ++i) {     // 한번에 너무 많이 안 보냄
                std::string one;
                {
                    std::lock_guard<std::mutex> lk(q_mtx_);
                    if (outq_.empty()) break;
                    one = std::move(outq_.front());
                    outq_.pop_front();
                }
                send_with_prefix(one);
                if (client_fd_ < 0) break; // 송신 에러로 끊김 감지
            }
            // 클라이언트 요청 수신
            int r = ::poll(&cpol, 1, 0);
            if (r > 0 && (cpol.revents & POLLIN)) {
                nlohmann::json req;
                if (!recv_one_json(req)) break; // 끊김
                auto t = req.value("type", std::string{});
                if (t == "PACKET_REQ") {
                    std::printf("[TEL] PACKET_REQ recv id=%lld\n", (long long)req.value("id",0));
                    handle_packet_req(req);
                }
                // (필요하면 다른 명령도 여기서 처리)
            }
            //session summary 보내기
            send_summary_once();
            int ms = period_ms_.load();
            for (int i=0;i<ms/50 && running_;++i) std::this_thread::sleep_for(milliseconds(50));
            if (client_fd_ < 0) break; // 송신 에러로 끊김 감지
        }

        if (client_fd_ >= 0) { ::close(client_fd_); client_fd_ = -1; }
        std::puts("[TEL] client disconnected");
    }
}

void TelemetryServer::send_line(const std::string& s){
    if (client_fd_ < 0) return;
    ssize_t n = ::send(client_fd_, s.data(), s.size(), MSG_NOSIGNAL);
    if (n < 0) { perror("send"); close(client_fd_); client_fd_ = -1; }
}

// ▼ 부분 전송 안전 송신
bool TelemetryServer::send_all(const void* buf, size_t len){
    const char* p = static_cast<const char*>(buf);
    size_t left = len;
    while (left > 0){
        ssize_t n = ::send(client_fd_, p, left, MSG_NOSIGNAL);
        if (n < 0){
            perror("send");
            close(client_fd_); client_fd_ = -1;
            return false;
        }
        if (n == 0){
            // peer closed
            close(client_fd_); client_fd_ = -1;
            return false;
        }
        p += n; left -= n;
    }
    return true;
}

// ▼ 길이 prefix + payload 송신
void TelemetryServer::send_with_prefix(const std::string& payload){
    if (client_fd_ < 0) return;
    uint32_t len = (uint32_t)payload.size();
    uint32_t nlen = htonl(len);
    if (!send_all(&nlen, 4)) return;
    if (!send_all(payload.data(), payload.size())) return;
}

//session summary 보내기.
void TelemetryServer::send_summary_once(){
    if (!sess_ || client_fd_ < 0) return;

    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto top = sess_->snapshot_top(10, now_ns);

    // JSON (type 필드 추가 권장)
    json j;
    j["type"] = "SUMMARY";
    j["ts_ns"] = now_ns;
    auto& arr = j["sessions"];
    arr = json::array();

    for (const auto& s : top) {
        // 방향 라벨링(HUD용): 방향을 알면 A/B를 C/S로 맵핑
        std::string roleA = "?";
        std::string roleB = "?";
        if (s.direction_known) {
            roleA = s.client_is_A ? "CLIENT" : "SERVER";
            roleB = s.client_is_A ? "SERVER" : "CLIENT";
        }

        json js;
        // 키/주소
        json fk = {
            {"proto",    (int)s.key.proto},
            {"src_ip",   ip_to_str(s.key.sip)},
            {"src_port", (int)s.key.sport},
            {"dst_ip",   ip_to_str(s.key.dip)},
            {"dst_port", (int)s.key.dport}
        };
        js["flow_key"] = fk;

        // 상태/역할/바이트/패킷
        json state = SessionTable::tcp_state_name(s.state);
        js["state"] = state;
        
        json roles = {
            {"directionKnown", s.direction_known},
            {"clientIsA",      s.client_is_A},
            {"A",              roleA},
            {"B",              roleB}
        };
        js["roles"] = roles;
        
        json bytes = s.bytes;
        js["bytes"] = bytes;

        json bytes_dir = {
            {"a2b", s.bytes_a2b},
            {"b2a", s.bytes_b2a}
        };
        js["bytes_dir"] = bytes_dir;

        json pkts = {
            {"a2b", s.pkts_a2b},
            {"b2a", s.pkts_b2a}
        };
        js["pkts"]  = pkts;

        // RTT(ms)
        json rtt_ms = {
            {"syn", s.rtt_syn_ms},
            {"ack", s.rtt_ack_ms}
        };
        js["rtt_ms"] = rtt_ms;
        // 스루풋(bps) — A<->B 기준 (클라이언트/서버 변환은 프론트에서 라벨 참고)
        json throughput_bps = {
            {"inst_a2b", s.inst_a2b},
            {"inst_b2a", s.inst_b2a},
            {"ewma_a2b", s.ewma_a2b},
            {"ewma_b2a", s.ewma_b2a}
        };
        js["throughput_bps"]  = throughput_bps;
        // (선택) 추후 확장 자리: 재전송/OOO/dupACK 누계 등 세션 통계 합산 버전
        // js["loss_hints"] = {...};

        arr.push_back(std::move(js));
    }

    // 여기서 prefix 방식으로 송신
    send_with_prefix(j.dump());
}

void TelemetryServer::push_session_report(const Session& s, const char* reason)
{
    if (client_fd_ < 0) return; // 연결 없으면 큐잉해도 되고, 여기선 즉시 송신 방식이면 가드

    // 총합
    uint64_t total_pkts  = s.dir[0].pkts + s.dir[1].pkts;
    uint64_t total_bytes = s.dir[0].bytes + s.dir[1].bytes;

    // 기간/평균 처리율
    double dur_sec = (s.last_ts_ns > s.first_ts_ns)
                     ? (double)(s.last_ts_ns - s.first_ts_ns) / 1e9 : 0.0;
    double avg_bps = (dur_sec > 0.0) ? (total_bytes / dur_sec) : 0.0;

    // RTT 대표값 (print와 동일 로직)
    double avg_rtt_ms = (s.rtt_ack_ms > 0) ? s.rtt_ack_ms
                       : (s.rtt_syn_ms > 0) ? s.rtt_syn_ms : -1.0;

    uint64_t retrans = s.dir[0].retrans_pkts + s.dir[1].retrans_pkts;

    nlohmann::json j;
    j["type"]   = "REPORT";     // ★ UI에서 구분
    j["reason"] = reason ? reason : "";
    j["time"]   = (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

    // 5-튜플
    j["flow_key"] = {
        {"proto", (int)s.key.proto},
        {"src_ip", ip_to_str(s.key.sip)},
        {"src_port", (int)s.key.sport},
        {"dst_ip", ip_to_str(s.key.dip)},
        {"dst_port", (int)s.key.dport}
    };

    // 요약 수치
    j["summary"] = {
        {"state", SessionTable::tcp_state_name(s.state)},
        {"total_pkts", (long long)total_pkts},
        {"total_bytes",(long long)total_bytes},
        {"duration_sec", dur_sec},
        {"avg_bps", avg_bps},
        {"avg_rtt_ms", avg_rtt_ms},
        {"retrans_pkts", (long long)retrans}
    };
    
    // 큐에 적재해서 기존 송신 루프가 prefix로 전송 (PACKET과 동일 경로)
    {
        std::lock_guard<std::mutex> lk(q_mtx_);
        if (outq_.size() >= outq_limit_) outq_.pop_front();
        outq_.push_back(j.dump());
    }
}

//패킷 데이터 송신
void TelemetryServer::push_packet(const PacketRecord& pr){
    json j;
    j["type"] = "PACKET";
    j["id"] = (long long)pr.id;
    j["ts_usec"] = (long long)(pr.ts_ns / 1000);

    json fk = {
        {"proto",     (int)pr.l4_proto},
        {"src_ip",    ip_to_str(pr.ipv4_src)},
        {"src_port",  (int)pr.sport},
        {"dst_ip",    ip_to_str(pr.ipv4_dst)},
        {"dst_port",  (int)pr.dport}
    };
    j["flow_key"] = fk;

    j["caplen"]   = (int)pr.caplen;
    j["l3"] = { {"version", (int)pr.ip_version}, {"proto", (int)pr.l4_proto},
                {"src", ip_to_str(pr.ipv4_src)}, {"dst", ip_to_str(pr.ipv4_dst)} };

    if (pr.l4_proto==6) {
        j["l4"] = { {"sport",(int)pr.sport}, {"dport",(int)pr.dport},
                    {"flags", tcp_flags_str(pr.tcp_flags)} };
    } else if(pr.l4_proto==1) {
        j["l4"] = { {"sport",(int)pr.sport}, {"dport",(int)pr.dport} };
    }

    if (!pr.payload_copy.empty()) {
        size_t n = std::min<size_t>(pr.payload_copy.size(),32);
        j["payload_b64"] = b64encode(pr.payload_copy.data(), n);
        //j["payload_head_len"] = (int)n;
    }

    std::lock_guard<std::mutex> lk(q_mtx_);
    if(outq_.size()>=outq_limit_) outq_.pop_front();
    outq_.push_back(j.dump());
}

// 경고 타입, 시간, 정책명, 동작(alert고정이긴함), 출발지/도착지, 페이로드 크기
void TelemetryServer::push_alert(const AlertView& view,
                                 const uint8_t* payload, size_t payload_len)
{
    nlohmann::json j;
    j["type"]    = "ALERT";

    // 시간
    j["ts_sec"]  = static_cast<long long>(view.ts_sec);
    j["ts_usec"] = static_cast<long long>(view.ts_usec);

    // 정책이름 (= rule msg)
    j["policy"]  = view.policy;

    // 동작 (unsock은 alert 고정)
    j["action"]  = view.action;  // "ALERT"

    // 출발지/도착지
    j["src"] = {
        {"ip",   view.src_ip},
        {"port", static_cast<int>(view.src_port)}
    };
    j["dst"] = {
        {"ip",   view.dst_ip},
        {"port", static_cast<int>(view.dst_port)}
    };

    // 페이로드 (과도한 전송 방지 위해 헤드 제한 — 필요하면 조절)
    const size_t MAX_TX = 2048;  // 1KB 정도 (원하면 더 키워도 됨)
    size_t n = (payload && payload_len) ? std::min(payload_len, MAX_TX) : 0;
    if (n > 0) {
        j["payload_b64"] = b64encode(payload, n);
        j["payload_len"] = static_cast<int>(payload_len); // 원래 총 길이도 함께 제공
        j["payload_head_len"] = static_cast<int>(n);
    } else {
        j["payload_b64"] = "";
        j["payload_len"] = 0;
        j["payload_head_len"] = 0;
    }

    // 큐에 적재 → 기존 송신 쓰레드가 길이 프리픽스 붙여 전송
    {
        std::lock_guard<std::mutex> lk(q_mtx_);
        if (outq_.size() >= outq_limit_) outq_.pop_front();
        outq_.push_back(j.dump());
    }
}

bool TelemetryServer::recv_all(void* buf, size_t len){
    char* p = static_cast<char*>(buf);
    size_t left = len;
    while (left > 0){
        ssize_t n = ::recv(client_fd_, p, left, 0);
        if (n < 0) { 
            if (errno==EINTR) continue; 
            if (errno==EAGAIN||errno==EWOULDBLOCK) 
                return false; 
            perror("recv"); 
            return false; 
        }
        if (n == 0) 
            return false; // peer closed
        p += n; left -= n;
    }
    return true;
}

bool TelemetryServer::recv_one_json(nlohmann::json& out){
    uint32_t nlen_be = 0;
    if (!recv_all(&nlen_be, 4)) return false;
    uint32_t nlen = ntohl(nlen_be);
    if (nlen==0 || nlen > (32u<<20)) return false; // 32MB 가드
    std::string body; body.resize(nlen);
    if (!recv_all(body.data(), nlen)) return false;
    out = nlohmann::json::parse(body, nullptr, false);
    return !out.is_discarded();
}

//base64로 변환하고 보내기.
void TelemetryServer::handle_packet_req(const nlohmann::json& req){
    // 우선 id 기반으로 찾기
    uint64_t id = req.value("id", 0ull);
    int want    = req.value("want_bytes", 512);

    nlohmann::json out;
    if (!pkts_ || id==0) {
        out = { {"type","PACKET_NA"}, {"reason","bad request"} };
        send_with_prefix(out.dump());
        return;
    }

    PacketRecord pr{};
    bool ok = pkts_->find_by_id(id, pr);                    // ★ PacketList 조회
    if (!ok) {
        out = { {"type","PACKET_NA"}, {"id",(long long)id}, {"reason","not found"} };
    } else {
        size_t n = std::min<size_t>(pr.payload_copy.size(), (size_t)want);
        std::string b64 = n? b64encode(pr.payload_copy.data(), n) : std::string();
        out = {
            {"type","PACKET_DATA"},
            {"id",(long long)id},
            {"ts_usec",(long long)(pr.ts_ns/1000)},
            {"caplen",(int)pr.caplen},
            {"payload_len",(int)n},
            {"payload_b64", b64}
        };
    }
    send_with_prefix(out.dump());
}