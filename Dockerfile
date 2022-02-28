# Dockerfile setup taken from https://testdriven.io/blog/docker-best-practices/

# Build stage for compiling assets
FROM python:3-slim as builder

WORKDIR /app

# Install required software for building python wheels
RUN apt-get update && \
    apt-get install -y build-essential libldap2-dev libsasl2-dev gcc

# Install dependencies
RUN pip install six && \
    pip wheel --wheel-dir /app/wheels ldaptor python-ldap py-radius



# final stage
FROM python:3-slim

# Default values for required environment variables
# Look at example-ad.env for descriptions
ENV LISTENING_PORT=8000
ENV UPSTREAM_LDAP_SERVER_HOST=ldap-backend
ENV UPSTREAM_LDAP_SERVER_PORT=389
ENV BIND_USER='CN=ldap proxy,CN=Users,DC=thales,DC=lab'
ENV BIND_PASSWORD='ProxyTest123!'
ENV LDAP_GROUP_MEMBER_ATTRIBUTE_NAME=memberOf
ENV MFA_USER_NAME_LDAP_ATTRIBUTE=cn
ENV MFA_USER_GROUP='CN=mfa-users,CN=Users,DC=thales,DC=lab'
ENV CHECK_RADIUS_BEFORE_LDAP=false
ENV RADIUS_SECRET=testing123
ENV RADIUS_HOST=radius-backend
ENV RADIUS_PORT=1812

WORKDIR /app

# The the pre-build python wheels from the build stage
COPY --from=builder /app/wheels /wheels

# Update system packages and install required libs
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y ldap-utils

# Install prebuild python wheels
RUN pip install --no-cache /wheels/*

# Copy the script into the app directory
COPY ldap_proxy.py /app

# Start the service
CMD [ "python", "ldap_proxy.py" ]