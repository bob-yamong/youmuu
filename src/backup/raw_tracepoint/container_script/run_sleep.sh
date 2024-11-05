#!/bin/bash

while true; do
    for i in {1..1000}; do
        sleep 1 &
    done
    wait
done
