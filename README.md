## 이 파일은 라즈베리파이 4B에서 libpcap을 사용하여 패킷을 잡고, UI에 올려보내기 위해 구현되었습니다.

## 빌드는 make를 통해 진행됩니다.

## 사용된 구조체는 아래에 정리할 예정입니다.

## 현재 구현상태
1. pcap_loop에 packet handler를 통해 PacketRecord에 L2~L4 + 페이로드 저장

## 진행되어야 하는 구현
1. Qt로 보내는 TCP server 구조 구현
