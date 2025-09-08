// capture.h
#pragma once
#include <pcap.h>
#include <string>
#include <functional>

class Capture {
    pcap_t* p_{nullptr};
public:
    ~Capture(){ close(); }
    pcap_t* handle() const { return p_; }

    bool open(const char* dev, int snaplen, bool promisc, int timeout_ms,
              int buf_bytes, bool want_nano);
    bool apply_bpf(const char* bpf);
    void loop(std::function<void(const pcap_pkthdr*, const u_char*)> on_pkt,
              std::function<bool(void)> should_stop);
    void print_stats() const;
    void close();
    static void list_interfaces();
};
