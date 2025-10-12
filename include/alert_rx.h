// alert_rx.h
#pragma once
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <functional>
#include <errno.h>

// snort 2.9.20 unisock 포멧 파서
// 구조체 바이트 배열을 완전히 동일하게 맞추기 위한 설정값이다. -> 패딩을 제거한다.
#pragma pack(push, 1)
struct tv32 { uint32_t tv_sec; uint32_t tv_usec; };
struct pcap_pkthdr32 { tv32 ts; uint32_t caplen; uint32_t len; };

struct AlertUnixSockHead {
    uint8_t       alertmsg[256];      // ALERTMSG_LENGTH (Snort 기본 256)
    pcap_pkthdr32 pkth;               // 16 bytes
    uint32_t      dlthdr;             // L2 오프셋
    uint32_t      nethdr;             // L3 오프셋
    uint32_t      transhdr;           // L4 오프셋
    uint32_t      data;               // payload 오프셋
    uint32_t      val;                // 플래그
    // 이어서 pkt[caplen] 가 오며, 그 뒤로 Event가 붙을 수 있음(여기선 사용 안 함)
};
//패딩값 돌려놓기.
#pragma pack(pop)

struct AlertRecord {
    // 메시지/메타
    std::string msg;          // rule msg (NUL 비보장 → 안전 추출)
    uint32_t ts_sec = 0;      // seconds
    uint32_t ts_usec = 0;     // usec
    uint32_t caplen = 0;      // bytes in pkt[]
    uint32_t pktlen = 0;      // original wire length
    uint32_t dlt_off = 0;     // L2 offset
    uint32_t net_off = 0;     // L3 offset
    uint32_t trans_off = 0;   // L4 offset
    uint32_t data_off = 0;    // payload offset
    uint32_t flags = 0;       // val

    // 페이로드(패킷 바이트) - 소유하지 않고 뷰만 제공
    const uint8_t* pkt = nullptr; // pkt bytes start
    size_t         pkt_size = 0;  // = caplen (경계 검사 후 보정)
};

class AlertReceiver {
    int fd_ = -1;
public:
    ~AlertReceiver(){ if(fd_!=-1) ::close(fd_); }

    bool open_path(const char* path = "/tmp/snort_alert"){
        ::unlink(path); // 기존 소켓 제거
        fd_ = ::socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd_ < 0) { perror("socket"); return false; }
        sockaddr_un addr{}; addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (::bind(fd_, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return false; }

        // non-blocking
        int fl = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, fl | O_NONBLOCK);
        // 수신 버퍼 여유
        int rcvbuf = 1<<20; setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        return true;
    }

    template<typename Fn>
    void loop(Fn on_alert, std::function<bool(void)> should_stop){
        std::vector<uint8_t> buf(80*1024);//80kB
        pollfd pfd{fd_, POLLIN, 0};
        while(!should_stop()){
            int pr = ::poll(&pfd, 1, 500);
            if (pr < 0) { if (errno==EINTR) continue; continue; }
            if (pr == 0 || !(pfd.revents & POLLIN)) continue;

            for(;;){
                ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
                if (n < 0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                    if (errno==EINTR) continue;
                    break;
                }
                if (n == 0) break;
                
                if ((size_t)n < sizeof(AlertUnixSockHead)) {
                    // 잘린 datagram(너무 짧음)
                    continue;
                }

                // 안전 복사(정렬/패딩 이슈 회피)
                AlertUnixSockHead hdr{};
                std::memcpy(&hdr, buf.data(), sizeof(AlertUnixSockHead));

                // msg 추출 (NUL 보장 불가 → 수동 종료/트림)
                const size_t MSG_MAX = sizeof(hdr.alertmsg);
                size_t mlen = 0;
                while (mlen < MSG_MAX && hdr.alertmsg[mlen] != 0) ++mlen;
                std::string msg(reinterpret_cast<const char*>(hdr.alertmsg), mlen);

                // caplen 경계 검사
                uint32_t caplen = hdr.pkth.caplen;
                size_t pkt_off = sizeof(AlertUnixSockHead);
                size_t need = pkt_off + static_cast<size_t>(caplen);
                if (need > (size_t)n) {
                    // caplen이 수신 길이를 넘으면 잘라서 사용
                    if ((size_t)n >= pkt_off) caplen = (uint32_t)((size_t)n - pkt_off);
                    else caplen = 0;
                }

                AlertRecord rec;
                rec.msg      = std::move(msg);
                rec.ts_sec   = hdr.pkth.ts.tv_sec;
                rec.ts_usec  = hdr.pkth.ts.tv_usec;
                rec.caplen   = caplen;
                rec.pktlen   = hdr.pkth.len;
                rec.dlt_off  = hdr.dlthdr;
                rec.net_off  = hdr.nethdr;
                rec.trans_off= hdr.transhdr;
                rec.data_off = hdr.data;
                rec.flags    = hdr.val;

                rec.pkt      = (caplen>0) ? (buf.data() + pkt_off) : nullptr;
                rec.pkt_size = caplen;

                on_alert(rec);
            }
        }
    }
};