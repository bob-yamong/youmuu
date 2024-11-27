FROM ubuntu:22.04

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    # git\
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
    libpq-dev\
    libyaml-dev\
    libyaml-cpp-dev\
    zlib1g-dev\
    libpq-dev\
    build-essential \
    cmake \
    wget \
    pkg-config \
    nlohmann-json3-dev \
    librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*


# libpqxx 7.5.1 설치
RUN wget https://github.com/jtv/libpqxx/archive/refs/tags/7.5.1.tar.gz -O libpqxx-7.5.1.tar.gz \
    && tar -xzf libpqxx-7.5.1.tar.gz \
    && cd libpqxx-7.5.1 \
    && mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install \
    && cd ../.. \
    && rm -rf libpqxx-7.5.1 libpqxx-7.5.1.tar.gz \
    && ldconfig

# # make를 위한 git module 설치
# RUN git clone https://github.com/libbpf/bpftool.git /ebpf/bpftool
# RUN git clone https://github.com/libbpf/libbpf.git /ebpf/libbpf
# RUN git clone https://github.com/bob-yamong/youmuu/tree/main/vmlinux
# COPY ebpf/vmlinux /ebpf/vmlinux

# g++ 및 gcc 버전 출력
RUN g++ --version && gcc --version

# 애플리케이션 파일 복사
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

# 애플리케이션 실행
# CMD \
# CMD tail -f /dev/null

