FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get install -y socat
RUN apt-get clean
RUN useradd -m me

ADD share/flag.txt /home/me/flag.txt
ADD share/acceptance /home/me/acceptance
ADD share/run.sh /home/me/run.sh
ADD xinetd /etc/xinetd.d/acceptance

RUN chown -R me:me /home/me
RUN chmod 444 /home/me/flag.txt
RUN chmod +x /home/me/run.sh
RUN chmod +x /home/me/acceptance

USER me
WORKDIR /home/me

CMD ["/usr/sbin/xinetd", "-dontfork"]
