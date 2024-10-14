#!/bin/sh

cd /app
socat tcp-listen:9991,fork,reuseaddr exec:./chatbot 2>/dev/null
