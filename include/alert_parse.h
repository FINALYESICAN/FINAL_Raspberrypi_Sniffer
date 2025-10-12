#pragma once
#include <string>
#include <cstdint>
#include "alert_rx.h"   // AlertRecord 정의 사용

// UI 표시용 요약
struct AlertView {
    uint32_t ts_sec{}, ts_usec{};
    std::string action = "ALERT";   // alert_unixsock는 항상 ALERT
    std::string policy;             // rule msg를 정책명처럼 사용
    std::string src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;
};

// AlertRecord → AlertView 변환
// 반환값: true면 일부라도 파싱 성공(최소 시간/정책/가능하면 IP:PORT)
// IPv4/IPv6 + TCP/UDP만 포트 추출함.
bool build_alert_view(const AlertRecord& a, AlertView& out);
