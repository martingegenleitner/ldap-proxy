# Taken from https://hub.docker.com/r/freeradius/freeradius-server
FROM freeradius/freeradius-server:latest
COPY raddb/ /etc/raddb/

# Enable ldap config by symlinking it
RUN cd /etc/raddb/mods-enabled && \
    ln -s ../mods-available/ldap ldap