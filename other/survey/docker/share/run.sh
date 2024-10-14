#!/bin/sh

cd /app
socat tcp-listen:9990,fork,reuseaddr exec:./survey 2>/dev/null
