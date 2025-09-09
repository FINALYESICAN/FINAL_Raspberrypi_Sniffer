// capture.cpp
#include "capture.h"
#include <cstdio>
#include <cstring>

bool Capture::open(const char* dev, int snap, bool prom, int to_ms,
                   int buf, bool nano){
    char err[PCAP_ERRBUF_SIZE] = {0};
    p_ = pcap_create(dev, err);
    if (!p_) { std::fprintf(stderr, "pcap_create: %s\n", err); return false; }
    //libpcap 옵션 설정
    pcap_set_snaplen(p_, snap);
    pcap_set_promisc(p_, prom ? 1 : 0);
    pcap_set_timeout(p_, to_ms);
    pcap_set_buffer_size(p_, buf);
    if (nano) {
        if (pcap_set_tstamp_precision(p_, PCAP_TSTAMP_PRECISION_NANO) != 0)
            std::fprintf(stderr, "WARNING: nano precision not supported\n");
    }
    int rc = pcap_activate(p_);
    if (rc < 0) { std::fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(p_)); return false; }
    if (rc > 0) { std::fprintf(stderr, "pcap_activate warn: %s\n", pcap_geterr(p_)); }
    std::printf("Opened %s  dlt=%d\n", dev, pcap_datalink(p_));
    return true;
}

bool Capture::apply_bpf(const char* bpf){
    bpf_program fp{};
    if (pcap_compile(p_, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        std::fprintf(stderr, "pcap_compile('%s'): %s\n", bpf, pcap_geterr(p_));
        return false;
    }
    if (pcap_setfilter(p_, &fp) != 0) {
        std::fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(p_));
        pcap_freecode(&fp); return false;
    }
    pcap_freecode(&fp);
    std::printf("BPF applied: %s\n", bpf);
    return true;
}

//on_pkt함수 / should_stop 함수
void Capture::loop(std::function<void(const pcap_pkthdr*, const u_char*)> on_pkt,
                   std::function<bool(void)> should_stop){
    while (!should_stop()) {
        pcap_pkthdr* h; const u_char* b;
        int rc = pcap_next_ex(p_, &h, &b);
        //다음 패킷을 main의 cb를 통해 처리한다.
        if (rc == 1) on_pkt(h, b);
        else if (rc == 0) continue;         // timeout
        else if (rc == -1) { std::fprintf(stderr,"pcap err: %s\n", pcap_geterr(p_)); break; }
        else if (rc == -2) break;           // breakloop
    }
}

void Capture::print_stats() const{
    pcap_stat st{};
    if (pcap_stats(p_, &st) == 0) {
        std::printf("Capture stats: ps_recv=%u ps_drop=%u ps_ifdrop=%u\n",
                    st.ps_recv, st.ps_drop, st.ps_ifdrop);
    }
}

void Capture::close(){ if (p_) { pcap_close(p_); p_ = nullptr; } }

void Capture::list_interfaces(){
    pcap_if_t* alldevs=nullptr;
    char err[PCAP_ERRBUF_SIZE]={0};
    if (pcap_findalldevs(&alldevs, err)!=0){
        std::fprintf(stderr, "pcap_findalldevs: %s\n", err); return;
    }
    std::puts("Available interfaces:");
    for (pcap_if_t* d=alldevs; d; d=d->next){
        std::printf("  %s  (%s)\n", d->name, d->description?d->description:"");
    }
    pcap_freealldevs(alldevs);
}
