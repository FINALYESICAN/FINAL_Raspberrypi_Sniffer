#include "TelemetryServer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>   // memcpy
#include <string>

static int make_listen(uint16_t port){
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); close(fd); return -1; }
    if (listen(fd, 1) < 0){ perror("listen"); close(fd); return -1; }
    return fd;
}

bool TelemetryServer::open_listen(uint16_t port){
    listen_fd_ = make_listen(port);
    return listen_fd_ >= 0;
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
    if (client_fd_ >= 0) { close(client_fd_); client_fd_ = -1; }
    if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    if (th_.joinable()) th_.join();
    std::puts("[TEL] stopped");
}

void TelemetryServer::set_period_ms(int ms){
    if (ms < 100) ms = 100;
    period_ms_ = ms;
}

void TelemetryServer::loop(){
    using namespace std::chrono;
    while (running_){
        sockaddr_in cli{}; socklen_t cl = sizeof(cli);
        std::puts("[TEL] waiting client...");
        int cfd = ::accept(listen_fd_, (sockaddr*)&cli, &cl);
        if (cfd < 0) { if (!running_) break; continue; }

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
    std::string j = "{\"type\":\"SUMMARY\",\"sessions\":[";
    for (size_t i=0;i<top.size();++i){
        const auto& s = top[i];
        char buf[1024];
        std::snprintf(buf,sizeof(buf),
          "{\"sip\":%u,\"dip\":%u,\"sport\":%u,\"dport\":%u,\"proto\":%u,"
          "\"bytes\":%llu,"
          "\"rtt_syn\":%.2f,\"rtt_ack\":%.2f,"
          "\"dirKnown\":%d,\"clientIsA\":%d,"
          "\"pkts_a2b\":%llu,\"pkts_b2a\":%llu,"
          "\"inst_a2b\":%.1f,\"inst_b2a\":%.1f,"
          "\"ewma_a2b\":%.1f,\"ewma_b2a\":%.1f,"
          "\"state\":\"%s\"}",
          s.key.sip, s.key.dip, s.key.sport, s.key.dport, s.key.proto,
          (unsigned long long)s.bytes,
          s.rtt_syn_ms, s.rtt_ack_ms,
          (int)s.direction_known, (int)s.client_is_A,
          (unsigned long long)s.pkts_a2b,(unsigned long long)s.pkts_b2a,
          s.inst_a2b,s.inst_b2a,s.ewma_a2b,s.ewma_b2a,
          SessionTable::tcp_state_name(s.state)
        );
        if (i) j.push_back(',');
        j += buf;
    }
    j += "]}";

    // ★ 여기서 prefix 방식으로 송신
    send_with_prefix(j);
}
