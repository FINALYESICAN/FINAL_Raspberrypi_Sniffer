// packet_list.h
#pragma once
#include <deque>
#include <utility>
#include <cstdio>
#include <arpa/inet.h>
#include <atomic>
#include "packet_record.h"

class PacketList {
    std::deque<PacketRecord> dq_;
    std::atomic<uint64_t> next_id_{1};
public:
    size_t max_count = 50000;
    void push(PacketRecord&& rec){
        rec.id = next_id_.fetch_add(1, std::memory_order_relaxed);
        dq_.emplace_back(std::move(rec));
        while (dq_.size()>max_count) dq_.pop_front();
    }
    void clear(){ dq_.clear(); }
    size_t size() const { return dq_.size(); }

    void dump_tail(size_t N) const {
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
