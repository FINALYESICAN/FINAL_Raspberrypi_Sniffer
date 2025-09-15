#pragma once
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

struct MirrorHdr {
    timeval ts;
    uint32_t caplen;
    uint32_t pktlen;
    uint32_t linktype; // DLT_*
};

class MirrorReceiver {
    int fd_ = -1;
public:
    ~MirrorReceiver(){ if(fd_!=-1) close(fd_); }
    bool open_path(const char* path="/tmp/daq_mirror.sock"){
        unlink(path); // 이전 소켓 제거
        fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd_ < 0) { perror("socket"); return false; }
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (bind(fd_, (sockaddr*)&addr, sizeof(addr))<0){ perror("bind"); return false; }
        return true;
    }
    template<typename Fn>
    void loop(Fn on_frame, std::function<bool(void)> should_stop){
        // non-blocking
        int fl = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, fl | O_NONBLOCK);

        // 수신 버퍼 조금 키움(선택)
        int rcvbuf = 2*1024*1024;
        setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        std::vector<uint8_t> buf(1<<20);
        pollfd pfd{fd_, POLLIN, 0};

        uint64_t idle_ticks = 0;
        bool first_seen = false;

        while(!should_stop()){
            int pr = ::poll(&pfd, 1, /*timeout ms*/ 500);
            if (pr < 0) {
                if (errno == EINTR) continue;
                // 기타 에러는 잠깐 쉬고 계속
                continue;
            }
            if (pr == 0) {
                // 타임아웃: 주기 로그(2초마다 한 번)
                if ((++idle_ticks % 4) == 0 && !first_seen) {
                    std::fprintf(stderr, "[mirror] waiting for sender on /tmp/daq_mirror.sock ...\n");
                    std::fflush(stderr);
                }
                continue;
            }
            if (!(pfd.revents & POLLIN)) continue;

            // 이제는 non-blocking이므로 여러 개 한꺼번에 빼낼 수도 있음
            for (;;) {
                ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
                if (n < 0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK) break; // 소진
                    if (errno==EINTR) continue;
                    break;
                }
                if (n == 0) break;
                if (static_cast<size_t>(n) < sizeof(MirrorHdr)) continue;

                // 구조체 안전 복사(정렬 이슈 회피)
                MirrorHdr mh;
                std::memcpy(&mh, buf.data(), sizeof(MirrorHdr));
                const uint8_t* payload = buf.data() + sizeof(MirrorHdr);

                if (mh.caplen == 0 || mh.caplen > 65535) continue;
                if (mh.pktlen == 0 || mh.pktlen < mh.caplen || mh.pktlen > 10*1024*1024) continue;
                if (sizeof(MirrorHdr) + mh.caplen > static_cast<size_t>(n)) continue;
                switch (mh.linktype){
                    case 1:   /* DLT_EN10MB */
                    case 113: /* DLT_LINUX_SLL */
                    case 101: /* DLT_RAW */
                        break;
                    default:
                        continue;
                }

                if (!first_seen) {
                    std::fprintf(stderr, "[mirror] first frame: dlt=%u cap=%u len=%u\n",
                                mh.linktype, mh.caplen, mh.pktlen);
                    std::fflush(stderr);
                    first_seen = true;
                }

                try{on_frame(mh, payload);}catch(...){};
            }
        }
    }
};
