// kafkaProducer.cpp
#include "kafkaProducer.h"
#include <cstdio>
#include <cstring>

KafkaProducer::KafkaProducer(const std::string& brokers, const std::string& topic)
    : brokers_(brokers), topic_(topic), rk_(nullptr), rkt_(nullptr) {}

KafkaProducer::~KafkaProducer() {

    if (rkt_) {
        rd_kafka_topic_destroy(rkt_);
        rkt_ = nullptr;
    }

    if (rk_) {
        rd_kafka_flush(rk_, 10 * 1000); // 10초 대기
        rd_kafka_destroy(rk_);
        rk_ = nullptr;
    }

}

bool KafkaProducer::init() {
    char errstr[512];

    // Kafka 설정 생성
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    if (!conf) {
        fprintf(stderr, "Failed to create Kafka config\n");
        return false;
    }

    // Kafka 프로듀서 생성
    rk_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk_) {
        fprintf(stderr, "Failed to create Kafka producer: %s\n", errstr);
        rd_kafka_conf_destroy(conf);
        return false;
    }

    // 브로커 추가
    if (rd_kafka_brokers_add(rk_, brokers_.c_str()) == 0) {
        fprintf(stderr, "Failed to add brokers: %s\n", brokers_.c_str());
        rd_kafka_destroy(rk_);
        rk_ = nullptr;
        return false;
    }

    // 토픽 객체 생성 (재사용을 위해)
    rkt_ = rd_kafka_topic_new(rk_, topic_.c_str(), NULL);
    if (!rkt_) {
        fprintf(stderr, "Failed to create topic object: %s\n", rd_kafka_err2str(rd_kafka_last_error()));
        rd_kafka_destroy(rk_);
        rk_ = nullptr;
        return false;
    }

    return true;
}

bool KafkaProducer::send(const std::string& message) {
    if (!rkt_) {
        fprintf(stderr, "Kafka topic not initialized.\n");
        return false;
    }

    // 메시지 전송
    if (rd_kafka_produce(
            rkt_,
            RD_KAFKA_PARTITION_UA, // 사용 가능한 파티션에 자동 할당
            RD_KAFKA_MSG_F_COPY,   // 메시지 복사
            (void*)message.c_str(),
            message.size(),
            NULL, 0,
            NULL) == -1) {
        fprintf(stderr, "Failed to produce message: %s\n", rd_kafka_err2str(rd_kafka_last_error()));
        return false;
    }

    // 전송 완료 확인
    rd_kafka_poll(rk_, 0);
    return true;
}