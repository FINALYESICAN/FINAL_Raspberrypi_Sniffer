// main.cpp
#include <csignal>
#include <cstdio>
#include <cstring>
#include "capture.h"
#include "decoder.h"
#include "packet_list.h"
#include "session_table.h"
#include "packet_record.h"
//추가됨.
#include "mirror_rx.h"

static volatile sig_atomic_t g_stop = 0;
static Capture* g_cap = nullptr;
static void on_sigint(int){ 
    g_stop = 1; 
    if(g_cap){
        if(auto h = g_cap->handle()){
            pcap_breakloop(h);
        }
    }
}

int main(int argc, char** argv){
    //ctrl-c누르면 종료
    std::signal(SIGINT, on_sigint);

    if (argc == 1){
        std::puts("Usage: sudo ./sniff <iface|mirror> [bpf] [nano]");
        Capture::list_interfaces();
        return 0;
    }
    bool use_mirror = (std::strcmp(argv[1],"mirror")==0);

    SessionTable sess;           // 세션 테이블 
    PacketList   pkts;           // 최근 패킷 보관/디버깅
    Decoder      dec;            // L2/L3/L4 디코더

    if(use_mirror){
        MirrorReceiver rx;
        if(!rx.open_path()) return 2;
        std::puts("Start receiving from DAQ mirror socket...");
        rx.loop([&](const MirrorHdr& mh, const uint8_t* bytes){
            pcap_pkthdr h{};
            h.ts     = mh.ts;
            h.caplen = mh.caplen;
            h.len    = mh.pktlen;
            
            PacketRecord rec;
            // MirrorHdr → PacketRecord 변환
            rec.ts_ns = (uint64_t)mh.ts.tv_sec*1000000000ull + (uint64_t)mh.ts.tv_usec*1000ull;
            rec.caplen = mh.caplen;
            rec.wirelen = mh.pktlen;
            rec.dlt = mh.linktype;
            // Decoder::parse_l2_l3_l4 직접 호출
            dec.decode_dlt(mh.linktype, h, bytes, rec);
            sess.update_from_packet(rec);
            pkts.push(std::move(rec));
        }, [&](){return g_stop!=0;});
    }else{
        const char* dev = argv[1];
        const char* bpf = (argc>=3 && std::strcmp(argv[2],"nano")!=0) ? argv[2] : nullptr;
        bool want_nano = (argc>=3 && std::strcmp(argv[2],"nano")==0) ||
                        (argc>=4 && std::strcmp(argv[3],"nano")==0);

        Capture cap;
        if (!cap.open(dev, /*snaplen=*/65535, /*promisc=*/true, /*timeout_ms=*/500,
                    /*bufsz=*/4*1024*1024, want_nano)) return 2;
        g_cap = &cap;
        if (bpf && !cap.apply_bpf(bpf)) return 3;
        
        //콜백함수를 만든다. pkthdr값, 포인터 초기위치 받아서 시작함.
        auto cb = [&](const pcap_pkthdr* h, const u_char* bytes){
            PacketRecord rec;        // 메타데이터 저장 구조체 (기존) :contentReference[oaicite:4]{index=4}
            dec.decode(*cap.handle(), *h, bytes, rec, want_nano);
            sess.update_from_packet(rec);
            pkts.push(std::move(rec));
        };

        //캡쳐 루프 돈다.
        std::puts("Start capturing... (Ctrl+C to stop)");
        cap.loop(cb, [&](){ return g_stop!=0; });
        //상태정보 뽑기
        cap.print_stats();
        g_cap = nullptr;
    }

    std::printf("[packetlist] count=%zu\n", pkts.size());
    if(pkts.size()>0){
        pkts.dump_tail(5);
        sess.dump_top(10);           // 바이트 상위 세션/RTT 출력(기존 API) :contentReference[oaicite:5]{index=5}
    }
    return 0;
}
