FROM ubuntu:22.04 AS builder

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
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/supervisor.d/
RUN mkdir -p /var/log/supervisor


# COPY youmuu/ /ebpf/
ADD . /ebpf 

# 애플리케이션 빌드
WORKDIR /ebpf/src/raw_tracepoint/
RUN make clean && make
WORKDIR /ebpf/src/tracepoint
RUN make
WORKDIR /ebpf/src/lsm
RUN make

WORKDIR /

FROM ubuntu:22.04 AS runner

RUN apt-get update && apt-get install -y \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /ebpf

COPY --from=builder /ebpf/src/raw_tracepoint/raw_tracepoint /ebpf/raw_tracepoint
COPY --from=builder /ebpf/src/tracepoint/tracepoint /ebpf/tracepoint
COPY --from=builder /ebpf/src/lsm/enforcement /ebpf/enforcement

ADD supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]