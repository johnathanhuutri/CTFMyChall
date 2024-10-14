FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get install -y strace
RUN apt-get -y install libseccomp-dev
RUN apt-get clean
RUN useradd -m user

ADD share/flag.txt /home/user/flag.txt
ADD share/ld-2.31.so /home/user/ld-2.31.so
ADD share/libc-2.31.so /home/user/libc-2.31.so
ADD share/libseccomp.so.2.5.1 /home/user/libseccomp.so.2.5.1
ADD share/saveme /home/user/saveme
ADD share/run.sh /home/user/run.sh
ADD xinetd /etc/xinetd.d/user


RUN chown -R user:user /home/user
RUN chown root:root /home/user/flag.txt
RUN chown user:root /home/user/saveme
RUN chmod 444 /home/user/flag.txt
RUN chmod +x /home/user/saveme
RUN chmod +x /home/user/run.sh
RUN chmod +x /home/user/ld-2.31.so
RUN chmod +x /home/user/libc-2.31.so
RUN chmod +x /home/user/libseccomp.so.2.5.1

USER user
WORKDIR /home/user

CMD ["/usr/sbin/xinetd", "-dontfork"]