# LDAP Proxy

Intercept ldap bind requests and responses for adding a radius authentication as second factor.

## Development

Initialize a virtual directory and install required packages using `pip`.
To use the `import ldap` follow the instructions at <https://www.python-ldap.org/en/python-ldap-3.3.0/installing.html#installing>.

```shell
git clone https://github.com/martingegenleitner/ldap-proxy
cd ldap-proxy
# initialize vEnv
python -m venv .venv
# Activate vEnv
./.venv/Scripts/activate(.bat)
# Install dependencies in vEnv
python -m pip install ldaptor
python -m pip install py-radius
python -m pip install python-ldap
```

ldapsearch -D "cn=mobpass,dc=example,dc=org" -w 'Testing123!,' -p 8000 -h 192.168.123.1 -b "dc=example,dc=org" -s sub "(objectclass=*)"

ldapsearch -D "cn=mobpass,dc=example,dc=org" -w 'Testing123!' -p 9389 -h 192.168.123.1 -b "dc=example,dc=org" -s sub "(objectclass=*)"
