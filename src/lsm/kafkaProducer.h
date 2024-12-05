// kafkaProducer.h
#pragma once
#include <string>
#include <librdkafka/rdkafka.h>

class KafkaProducer {
public:
    KafkaProducer(const std::string& brokers, const std::string& topic);
    ~KafkaProducer();

    bool init();
    bool send(const std::string& message);

private:
    std::string brokers_;
    std::string topic_;
    rd_kafka_t *rk_;
    rd_kafka_topic_t *rkt_; // 재사용할 토픽 객체
};