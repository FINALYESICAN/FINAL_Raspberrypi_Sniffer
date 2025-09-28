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

bool TelemetryServer::open_listen(uint16_t port){
    listen_fd_ = make_listen(port);
    if(listen_fd_<0) return false;
    int fl  =fcntl(listen_fd_, F_GETFL,0);
    fcntl(listen_fd_, F_SETFL, fl|O_NONBLOCK);
    return true;
}

bool TelemetryServer::start(SessionTable* table, uint16_t port, int period_ms){
    if (!table) return false;
    sess_ = table;
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
    if (listen_fd_ >= 0) { ::shutdown(client_fd_, SHUT_RDWR);close(listen_fd_); listen_fd_ = -1; }
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

        while (running_){
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

void TelemetryServer::send_summary_once(){
    if (!sess_ || client_fd_ < 0) return;

    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto top = sess_->snapshot_top(10, now_ns);

    // JSON (type 필드 추가 권장)
    json j;
    j["type"] = "SUMMARY";
    j["ts_ns"] = now_ns;
    j["session"] = json::array();
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
        json key = {
            {"sip",      s.key.sip},
            {"dip",      s.key.dip},
            {"sport",    s.key.sport},
            {"dport",    s.key.dport},
            {"proto",    s.key.proto},
            {"sip_str",  ip_to_str(s.key.sip)},
            {"dip_str",  ip_to_str(s.key.dip)}
        };
        js["key"] = key;

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
