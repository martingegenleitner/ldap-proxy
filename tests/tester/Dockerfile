FROM ubuntu:20.04

RUN apt update && \
    apt install -y netcat ldap-utils freeradius-utils

COPY run_tests.sh /root

WORKDIR /root

CMD [ "sh", "run_tests.sh" ]