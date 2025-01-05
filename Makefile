# Default target
all: build

# Build the project
build:
	make -C src

# Clean the project
clean:
	make -C src clean

# Install dependencies
install:
	sudo apt update && sudo apt-get install -y --no-install-recommends \
		g++ \
		make \
		clang \
		llvm \
		gcc \
		libelf1 \
		libelf-dev \
		zlib1g-dev \
		libcurl4-openssl-dev \
		libjson-c-dev \
		libyaml-dev \
		libyaml-cpp-dev \
		build-essential \
		cmake \
		wget \
		pkg-config \
		nlohmann-json3-dev \
		librdkafka-dev \
		supervisor \
		libpq-dev

# Clean up apt cache
clean_cache:
	sudo rm -rf /var/lib/apt/lists/*
