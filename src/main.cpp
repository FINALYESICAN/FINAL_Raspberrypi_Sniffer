// main.cpp
#include <csignal>
#include <cstdio>
#include <cstring>
#include "capture.h"
#include "decoder.h"
#include "packet_list.h"
#include "session_table.h"
#include "packet_record.h"

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int){ g_stop = 1; }

int main(int argc, char** argv){
    std::signal(SIGINT, on_sigint);

    if (argc == 1){
        std::puts("Usage: sudo ./sniff <iface> [bpf] [nano]");
        Capture::list_interfaces();
        return 0;
    }
    const char* dev = argv[1];
    const char* bpf = (argc>=3 && std::strcmp(argv[2],"nano")!=0) ? argv[2] : nullptr;
    bool want_nano = (argc>=3 && std::strcmp(argv[2],"nano")==0) ||
                     (argc>=4 && std::strcmp(argv[3],"nano")==0);

    Capture cap;
    if (!cap.open(dev, /*snaplen=*/65535, /*promisc=*/true, /*timeout_ms=*/500,
                  /*bufsz=*/4*1024*1024, want_nano)) return 2;
    if (bpf && !cap.apply_bpf(bpf)) return 3;

    SessionTable sess;           // 세션 테이블 (기존 그대로 사용) :contentReference[oaicite:3]{index=3}
    PacketList   pkts;           // 최근 패킷 보관/디버깅
    Decoder      dec;            // L2/L3/L4 디코더

    auto cb = [&](const pcap_pkthdr* h, const u_char* bytes){
        PacketRecord rec;        // 메타데이터 저장 구조체 (기존) :contentReference[oaicite:4]{index=4}
        dec.decode(*cap.handle(), *h, bytes, rec);
        sess.update_from_packet(rec);
        pkts.push(std::move(rec));
    };

    std::puts("Start capturing... (Ctrl+C to stop)");
    cap.loop(cb, [&](){ return g_stop!=0; });

    cap.print_stats();
    std::printf("[packetlist] count=%zu\n", pkts.size());
    pkts.dump_tail(5);
    sess.dump_top(10);           // 바이트 상위 세션/RTT 출력(기존 API) :contentReference[oaicite:5]{index=5}
    return 0;
}
