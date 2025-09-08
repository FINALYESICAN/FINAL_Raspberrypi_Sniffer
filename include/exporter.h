// exporter.h
#pragma once
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "packet_record.h"
#include "session_table.h"

class Exporter {
public:
    explicit Exporter(const char* url);
    ~Exporter();
    void enqueue(const PacketRecord& rec);     // 패킷 메타데이터
    void enqueue(const Session& sess);         // 세션 스냅샷
private:
    void run();
    std::string url_;
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::mutex m_;
    std::condition_variable cv_;
    std::queue<std::string> q_; // JSONL 문자열
};
