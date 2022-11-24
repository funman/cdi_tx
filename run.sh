#!/bin/sh

set -e

export FI_LOG_LEVEL=10

(while :;do cat f;done)| exec ./tx 192.168.0.221 192.168.0.177:47593
