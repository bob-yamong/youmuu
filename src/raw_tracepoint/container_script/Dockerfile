# Ubuntu 20.04 이미지를 기반으로 함
FROM ubuntu:20.04

# 비대화형 모드 설정 (tzdata 등의 패키지 설치 시 프롬프트 방지)
ENV DEBIAN_FRONTEND=noninteractive

# 필요한 패키지 업데이트 및 설치
RUN apt-get update && apt-get install -y \
    bash \
    && rm -rf /var/lib/apt/lists/*

# 호스트의 run_sleep.sh 스크립트를 컨테이너로 복사
COPY run_sleep.sh /usr/local/bin/run_sleep.sh

# 스크립트에 실행 권한 부여
RUN chmod +x /usr/local/bin/run_sleep.sh

# 컨테이너 시작 시 run_sleep.sh 실행
CMD ["/usr/local/bin/run_sleep.sh"]

