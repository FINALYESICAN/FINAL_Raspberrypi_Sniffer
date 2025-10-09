// packet_list.h
#pragma once
#include <deque>
#include <utility>
#include <cstdio>
#include <arpa/inet.h>
#include <atomic>
#include "packet_record.h"
#include <mutex>

class PacketList {
    std::deque<PacketRecord> dq_;
    std::atomic<uint64_t> next_id_{1};
    mutable std::mutex mtx_;
public:
    size_t max_count = 50000;
    void push(PacketRecord&& rec){
        std::lock_guard<std::mutex> lk(mtx_);
        dq_.emplace_back(std::move(rec));
        while (dq_.size()>max_count) dq_.pop_front();
    }
    //다음 id값
    uint64_t reserved_id() {
        uint64_t id = next_id_.fetch_add(1, std::memory_order_relaxed);
        return id;
    }

    void clear(){ std::lock_guard<std::mutex> lk(mtx_); dq_.clear(); }
    size_t size() const { std::lock_guard<std::mutex> lk(mtx_); return dq_.size(); }

    bool find_by_id(uint64_t id, PacketRecord& out) const{
        std::lock_guard<std::mutex> lk(mtx_);
        for(const auto& pr: dq_){
            if(pr.id==id) {out = pr; return true;}
        }
        return false;
    }

    void dump_tail(size_t N) const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (dq_.empty()){ std::puts("[packetlist] empty"); return; }
        size_t start = (N>=dq_.size())?0:(dq_.size()-N);
        for (size_t i=start; i<dq_.size(); ++i){
            const auto& pr = dq_[i];
            char sip[64]={0}, dip[64]={0};
            if (pr.ip_version==4){
                in_addr a{.s_addr=pr.ipv4_src}, b{.s_addr=pr.ipv4_dst};
                inet_ntop(AF_INET, &a, sip, sizeof sip);
                inet_ntop(AF_INET, &b, dip, sizeof dip);
            }
            std::printf("#%zu ts=%.6f cap=%u wire=%u L3=%u L4=%u %s:%u -> %s:%u payload=%u\n",
                i, pr.ts_ns/1e9, pr.caplen, pr.wirelen, pr.ip_version, pr.l4_proto,
                sip, pr.sport, dip, pr.dport, pr.payload_len);
        }
    }
};
