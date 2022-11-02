FROM ubuntu:22.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y socat
RUN apt-get install -y libssl-dev

WORKDIR /root

COPY ./s3 ./s3

RUN chmod +x ./s3

EXPOSE 8392


ENTRYPOINT socat -d TCP-LISTEN:8392,reuseaddr,fork EXEC:'timeout -k 5 30 /root/s3',pty,raw,stderr,echo=0
