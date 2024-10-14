FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get clean
RUN useradd -m user

ADD share/flag.txt /home/user/flag.txt
ADD share/textsender /home/user/textsender
ADD share/libc-2.32.so /home/user/libc-2.32.so
ADD share/ld-2.32.so /home/user/ld-2.32.so
ADD share/run.sh /home/user/run.sh
ADD xinetd /etc/xinetd.d/user


RUN chown -R user:user /home/user
RUN chown root:root /home/user/flag.txt
RUN chown user:root /home/user/textsender
RUN chmod 444 /home/user/flag.txt
RUN chmod +x /home/user/run.sh
RUN chmod +x /home/user/textsender
RUN chmod +x /home/user/libc-2.32.so
RUN chmod +x /home/user/ld-2.32.so

USER user
WORKDIR /home/user

CMD ["/usr/sbin/xinetd", "-dontfork"]