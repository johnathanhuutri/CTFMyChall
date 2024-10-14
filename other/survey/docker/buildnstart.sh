#!/bin/sh

docker build . -t survey
docker run -d --restart unless-stopped -p 9990:9990 -it survey


