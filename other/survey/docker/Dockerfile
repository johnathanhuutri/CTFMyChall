FROM ubuntu:20.04

RUN apt update && apt install -y socat && apt clean && useradd user
RUN mkdir /app
ADD /share/ /app/
RUN chmod +x /app/* && chmod 444 /app/flag.txt

WORKDIR /app
USER user
CMD "/app/run.sh"

