// main.cpp
#include <cstdint>
#include <csignal>
#include <cstdio>
#include <cstring>
#include "capture.h"
#include "decoder.h"
#include "packet_list.h"
#include "session_table.h"
#include "packet_record.h"
//for mirroring snort
#include "mirror_rx.h"
#include "alert_rx.h"
#include "alert_parse.h"
#include "alert_store.h"
#include <thread>
#include <chrono>
//telemetric
#include "TelemetryServer.h"

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
    AlertStore   alert_store;    // 얼러트 저장

    TelemetryServer tel;
    tel.start(&sess, &pkts, 55555, 1000);

    // === 별도 프루닝 스레드: 1초마다 sess.prune() ===
    std::thread prune_worker([&]{
        using namespace std::chrono;
        while (!g_stop) {
            // rec.ts_ns가 epoch ns이므로 REALTIME epoch 사용
            auto now = system_clock::now();
            uint64_t now_ns = duration_cast<nanoseconds>(now.time_since_epoch()).count();
            size_t removed = sess.prune(now_ns);
            if (removed > 0) {
                std::printf("[PRUNE] removed=%zu, remaining=%zu\n", removed, sess.size());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
    std::thread alert_worker;

    uint64_t last_prune_ns = 0;

    if(use_mirror){
        MirrorReceiver rx;
        if(!rx.open_path()) return 2;
        
        AlertReceiver alerts;
        if(!alerts.open_path()) return 2;

        std::puts("Start receiving from DAQ mirror socket...");
        std::puts("Start receiving: /tmp/daq_mirror.sock (packets), /tmp/snort_alert (alerts)");
        
         // 알림 수신 스레드
        alert_worker = std::thread([&](){
            alerts.loop([&](const AlertRecord& a){
                // 1) 로그로 확인
                std::fprintf(stderr, "[ALERT] %s  ts=%u.%06u cap=%u wire=%u\n",
                            a.msg.c_str(), a.ts_sec, a.ts_usec, a.caplen, a.pktlen);
                // 2) alertView 파싱
                AlertView v;
                build_alert_view(a,v);

                const uint8_t* payload = nullptr;
                size_t payload_len = 0;
                if (a.pkt && a.data_off < a.pkt_size) {
                    payload = a.pkt + a.data_off;
                    payload_len = a.pkt_size - a.data_off;
                }
                // 3) 데이터 보내기
                tel.push_alert(v, payload, payload_len);
                // 4) savedAlert저장
                SavedAlert sa;
                sa.msg = a.msg;
                sa.ts_sec = a.ts_sec;
                sa.ts_usec = a.ts_usec;
                sa.caplen = a.caplen;
                sa.pktlen = a.pktlen;
                sa.dlt_off = a.dlt_off;
                sa.net_off = a.net_off;
                sa.trans_off = a.trans_off;
                sa.data_off = a.data_off;
                sa.flags = a.flags;
                sa.pkt.assign(a.pkt, a.pkt + a.pkt_size); // 깊은 복사

                alert_store.push(std::move(sa));
            }, [&]{ return g_stop!=0; });
            // detach 또는 join을 프로그램 종료 시점에
        });
        // 메인 루프
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
            uint64_t id = pkts.reserved_id();
            rec.id=id;
            tel.push_packet(rec);   //캡쳐 콜백에서 패킷보내기.
            pkts.push(std::move(rec));

            // if (last_prune_ns == 0) last_prune_ns = h.ts.tv_sec*1000000000ull + (uint64_t)h.ts.tv_usec*1000ull;
            // auto now_ns = (uint64_t)h.ts.tv_sec*1000000000ull + (uint64_t)h.ts.tv_usec*1000ull;
            // if (now_ns - last_prune_ns >= 1ULL*1000*1000*1000) {
            //     size_t removed = sess.prune(now_ns);
            //     printf("[prune] mirror removed=%zu, table=%zu\n", removed, sess.size());
            //     last_prune_ns = now_ns;
            // }        
        }, [&](){return g_stop!=0;});
    }else{
        const char* dev = argv[1];
        const char* user_bpf = (argc>=3 && std::strcmp(argv[2],"nano")!=0) ? argv[2] : nullptr;
        bool want_nano = (argc>=3 && std::strcmp(argv[2],"nano")==0) ||
                        (argc>=4 && std::strcmp(argv[3],"nano")==0);

        Capture cap;
        if (!cap.open(dev, /*snaplen=*/65535, /*promisc=*/true, /*timeout_ms=*/500,
                    /*bufsz=*/4*1024*1024, want_nano)) return 2;
        g_cap = &cap;

        std::string ctrl_excl = "not (host 192.168.2.234 and tcp port 55555)";
        std::string final_bpf;
        if(user_bpf){
            final_bpf = "(" + std::string(user_bpf)+") and " +ctrl_excl;
        }else{
            final_bpf = ctrl_excl;
        }
        if (!cap.apply_bpf(final_bpf.c_str())) return 3;
        
        //콜백함수를 만든다. pkthdr값, 포인터 초기위치 받아서 시작함.
        auto cb = [&](const pcap_pkthdr* h, const u_char* bytes){
            PacketRecord rec;        // 메타데이터 저장 구조체 (기존) :contentReference[oaicite:4]{index=4}
            dec.decode(*cap.handle(), *h, bytes, rec, want_nano);
            sess.update_from_packet(rec);
            uint64_t id = pkts.reserved_id();
            rec.id=id;
            tel.push_packet(rec);   //캡쳐 콜백에서 패킷보내기.
            pkts.push(std::move(rec));

            // // ★ 1초마다 프루닝
            // if (last_prune_ns == 0) last_prune_ns = rec.ts_ns;
            // if (rec.ts_ns - last_prune_ns >= 1ULL*1000*1000*1000) {
            //     size_t removed = sess.prune(rec.ts_ns);
            //     last_prune_ns = rec.ts_ns;
            // }
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
    if (prune_worker.joinable()) prune_worker.join();
    if (alert_worker.joinable()) alert_worker.join();
    tel.stop();
    return 0;
}
