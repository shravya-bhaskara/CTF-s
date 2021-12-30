FROM ubuntu:20.04
COPY deployment .
RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install gcc-multilib
EXPOSE 5005
CMD ./ynetd -p 5005 ./chall
