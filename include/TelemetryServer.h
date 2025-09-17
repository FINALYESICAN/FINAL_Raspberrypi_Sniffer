// telemetry_server.h
#pragma once
#include <thread>
#include <atomic>
#include <string>
#include "session_table.h"

class TelemetryServer {
public:
    bool start(SessionTable* table, uint16_t port = 55555, int period_ms = 1000);
    void stop();
    void set_period_ms(int ms);

private:
    SessionTable* sess_{nullptr};
    int listen_fd_{-1};
    int client_fd_{-1};
    std::thread th_;
    std::atomic<bool> running_{false};
    std::atomic<int> period_ms_{1000};

    bool open_listen(uint16_t port);
    void loop();

    // 기존 라인 송신은 안 씀
    void send_line(const std::string& s);

    // ▼ 추가: prefix 방식 송신
    void send_with_prefix(const std::string& payload);
    bool send_all(const void* buf, size_t len); // 부분 전송 대비
    void send_summary_once();
};
