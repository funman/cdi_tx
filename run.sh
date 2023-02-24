#!/bin/sh

set -e

#export FI_LOG_LEVEL=10

(while :;do cat f;done)| exec ./tx 10.0.0.2 10.0.0.1:3002
