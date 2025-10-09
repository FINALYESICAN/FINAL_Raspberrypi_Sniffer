// telemetry_server.h
#pragma once
#include <thread>
#include <atomic>
#include <string>
#include "session_table.h"
#include "packet_list.h"

#include <deque>
#include <mutex>
#include <nlohmann/json.hpp>

class TelemetryServer {
public:
    bool start(SessionTable* table, PacketList* pkts, uint16_t port = 55555, int period_ms = 1000);
    void stop();
    void set_period_ms(int ms);

    void push_packet(const PacketRecord& pr);

private:
    SessionTable* sess_{nullptr};
    PacketList* pkts_{nullptr};

    int listen_fd_{-1};
    int client_fd_{-1};
    std::thread th_;
    std::atomic<bool> running_{false};
    std::atomic<int> period_ms_{1000};

    std::mutex q_mtx_;
    std::deque<std::string> outq_;
    size_t outq_limit_ = 10000;

    bool open_listen(uint16_t port);
    void loop();

    // 기존 라인 송신은 안 씀
    void send_line(const std::string& s);

    // ▼ 추가: prefix 방식 송신
    void send_with_prefix(const std::string& payload);
    bool send_all(const void* buf, size_t len); // 부분 전송 대비
    void send_summary_once();

    // 수신 유틸리티, 요청 핸들러
    bool recv_all(void* buf, size_t len);
    bool recv_one_json(nlohmann::json& out);
    void handle_packet_req(const nlohmann::json& req);
};
