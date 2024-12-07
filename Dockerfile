FROM ubuntu:22.04

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    g++\
    make\
    clang\
    llvm\
    gcc\
    libelf1\
    libelf-dev\
    zlib1g-dev\
    libcurl4-openssl-dev\
    libjson-c-dev\
    libyaml-dev\
    libyaml-cpp-dev\
    zlib1g-dev\
    build-essential \
    cmake \
    wget \
    pkg-config \
    nlohmann-json3-dev \
    librdkafka-dev \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/supervisor.d/
RUN mkdir -p /var/log/supervisor

COPY supervisord.conf /etc/supervisord.conf

# COPY youmuu/ /ebpf/
ADD . /ebpf 

# 애플리케이션 빌드
WORKDIR /ebpf/src/raw_tracepoint/
RUN make clean & make
WORKDIR /ebpf/src/tracepoint
RUN make
WORKDIR /ebpf/src/lsm
RUN make

WORKDIR /

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]