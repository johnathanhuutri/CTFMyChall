#!/bin/sh

docker build . -t chatbot
docker run -d --restart unless-stopped -p 9991:9991 -it chatbot