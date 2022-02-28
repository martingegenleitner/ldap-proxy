#/bin/bash

echo "Waiting for services to start (5 sec) ..."
sleep 10s

# Check that the ldap-consumer, who is not a member of the mfa-user group, can read the LDAP-Directory without MFA
# Valid attempt
ldapsearch -D "cn=ldap-consumer,ou=people,dc=example,dc=org" -w 'ConsumerTest123!' -p 8000 -h ldap-proxy -b "ou=people,dc=example,dc=org" -s sub "(&(cn=user02)(memberOf=cn=mfa-users,ou=groups,dc=example,dc=org))" memberOf
if [ $? -eq 0 ]; then echo "------ TEST#1 succeeded ------"; else echo "------ TEST#1 failed ------"; fi
# Invalid LDAP-Password
ldapsearch -D "cn=ldap-consumer,ou=people,dc=example,dc=org" -w 'WrongLDAP123!' -p 8000 -h ldap-proxy -b "ou=people,dc=example,dc=org" -s sub "(&(cn=user02)(memberOf=cn=mfa-users,ou=groups,dc=example,dc=org))" memberOf
if [ $? -eq 49 ]; then echo "------ TEST#2 succeeded ------"; else echo "------ TEST#2 failed ------"; fi

# Check that a mfa-user must supply LDAP-Password and RADIUS-Password
# Valid attempt
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'User01Test123!,User01OTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 0 ]; then echo "------ TEST#3 succeeded ------"; else echo "------ TEST#3 failed ------"; fi
# Invalid attempt on RADIUS
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'User01Test123!,WrongOTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "------ TEST#4 succeeded ------"; else echo "------ TEST#4 failed ------"; fi
# Invalid attempt on LDAP
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'WrongLDAP123!,User01OTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "------ TEST#5 succeeded ------"; else echo "------ TEST#5 failed ------"; fi


# Check that non mfa-users cannot supply LDAP-Password and RADIUS-Password (LDAP-PW-Only)
# Valid attempt
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'User03Test123!' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 0 ]; then echo "------ TEST#6 succeeded ------"; else echo "------ TEST#6 failed ------"; fi
# Invalid attempt because of wrong LDAP-PW
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'WrongLDAP123!' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "------ TEST#7 succeeded ------"; else echo "------ TEST#7 failed ------"; fi
# Invalid attempt because of any RADIUS-PW
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'User03Test123!,nonexistingOTP' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "------ TEST#8 succeeded ------"; else echo "------ TEST#8 failed ------"; fi