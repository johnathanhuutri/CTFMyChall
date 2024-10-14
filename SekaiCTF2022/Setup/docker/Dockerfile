FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y xinetd
# RUN apt-get install -y strace
RUN apt-get -y install libseccomp-dev
RUN apt-get clean
RUN useradd -m user

ADD files/glibc/libc-2.34.so /usr/lib/x86_64-linux-gnu/libc-2.34.so
ADD files/glibc/ld-2.34.so /usr/lib/x86_64-linux-gnu/ld-2.34.so
ADD files/glibc/libseccomp.so.2 /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.1
ADD files/home/ /home/user/
ADD xinetd /etc/xinetd.d/user

RUN chown -R user:user /home/user
RUN chown root:root /home/user/85c6ead8489c814ccc024c7054edf8e4.txt
RUN chown user:root /home/user/setup
RUN chmod 444 /home/user/85c6ead8489c814ccc024c7054edf8e4.txt
RUN chmod +x /usr/lib/x86_64-linux-gnu/libc-2.34.so
RUN chmod +x /usr/lib/x86_64-linux-gnu/ld-2.34.so
RUN chmod +x /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.1
RUN chmod +x /home/user/run.sh
RUN chmod +x /home/user/setup

USER user
WORKDIR /home/user

CMD ["/usr/sbin/xinetd", "-dontfork"]