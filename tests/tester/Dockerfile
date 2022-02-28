FROM ubuntu:latest

RUN apt update && \
    apt install -y netcat ldap-utils

COPY run_tests.sh /root

WORKDIR /root

CMD [ "sh", "run_tests.sh" ]