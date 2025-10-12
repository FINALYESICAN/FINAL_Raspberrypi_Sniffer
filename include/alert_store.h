#pragma once
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <algorithm>
#include <cstdint>

// Alert저장할 데이터
struct SavedAlert {
    std::string msg;
    uint32_t ts_sec{}, ts_usec{};
    uint32_t caplen{}, pktlen{};
    uint32_t dlt_off{}, net_off{}, trans_off{}, data_off{};
    uint32_t flags{};
    std::vector<uint8_t> pkt;  // payload 포함
};

// 안전하게 offset~end 구간 자르기
struct Span { const uint8_t* p; size_t n; };
inline Span slice(const std::vector<uint8_t>& buf, size_t off, size_t end_hint) {
    if (off >= buf.size()) return {nullptr, 0};
    size_t end = std::min(end_hint, buf.size());
    if (end <= off) return {nullptr, 0};
    return { buf.data() + off, end - off };
}
inline Span get_l2(const SavedAlert& a) { return slice(a.pkt, a.dlt_off, a.net_off ? a.net_off : a.pkt.size()); }
inline Span get_l3(const SavedAlert& a) { return slice(a.pkt, a.net_off, a.trans_off ? a.trans_off : a.data_off ? a.data_off : a.pkt.size()); }
inline Span get_l4(const SavedAlert& a) { return slice(a.pkt, a.trans_off, a.data_off ? a.data_off : a.pkt.size()); }
inline Span get_app(const SavedAlert& a){ return slice(a.pkt, a.data_off, a.pkt.size()); }

class AlertStore {
public:
    explicit AlertStore(size_t limit = 1000) : limit_(limit) {}

    void push(SavedAlert a) {
        std::lock_guard<std::mutex> lk(mx_);
        if (dq_.size() >= limit_) dq_.pop_front();
        dq_.push_back(std::move(a));
    }

    std::deque<SavedAlert> snapshot() const {
        std::lock_guard<std::mutex> lk(mx_);
        return dq_;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mx_);
        return dq_.size();
    }

private:
    size_t limit_;
    mutable std::mutex mx_;
    std::deque<SavedAlert> dq_;
};