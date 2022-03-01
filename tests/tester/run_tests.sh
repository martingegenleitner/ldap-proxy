#/bin/bash

echo "Waiting for services to start (5 sec) ..."
sleep 10s

# Check that the ldap-consumer, who is not a member of the mfa-user group, can read the LDAP-Directory without MFA
# Valid attempt
ldapsearch -D "cn=ldap-consumer,ou=people,dc=example,dc=org" -w 'ConsumerTest123!' -p 8000 -h ldap-proxy -b "ou=people,dc=example,dc=org" -s sub "(&(cn=user02)(memberOf=cn=mfa-users,ou=groups,dc=example,dc=org))" memberOf
if [ $? -eq 0 ]; then echo "\n------ LDAP_TEST#1 succeeded------\n"; else echo "\n------ LDAP_TEST#1 failed------\n"; fi
# Invalid LDAP-Password
ldapsearch -D "cn=ldap-consumer,ou=people,dc=example,dc=org" -w 'WrongLDAP123!' -p 8000 -h ldap-proxy -b "ou=people,dc=example,dc=org" -s sub "(&(cn=user02)(memberOf=cn=mfa-users,ou=groups,dc=example,dc=org))" memberOf
if [ $? -eq 49 ]; then echo "\n------ LDAP_TEST#2 succeeded------\n"; else echo "\n------ LDAP_TEST#2 failed------\n"; fi

# Check that a mfa-user must supply LDAP-Password and RADIUS-Password
# Valid attempt
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'User01Test123!,User01OTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 0 ]; then echo "\n------ LDAP_TEST#3 succeeded------\n"; else echo "\n------ LDAP_TEST#3 failed------\n"; fi
# Invalid attempt on RADIUS
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'User01Test123!,WrongOTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "\n------ LDAP_TEST#4 succeeded------\n"; else echo "\n------ LDAP_TEST#4 failed------\n"; fi
# Invalid attempt on LDAP
ldapsearch -D "cn=user01,ou=people,dc=example,dc=org" -w 'WrongLDAP123!,User01OTP' -p 8000 -h ldap-proxy -b "cn=user01,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "\n------ LDAP_TEST#5 succeeded------\n"; else echo "\n------ LDAP_TEST#5 failed------\n"; fi


# Check that non mfa-users cannot supply LDAP-Password and RADIUS-Password (LDAP-PW-Only)
# Valid attempt
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'User03Test123!' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 0 ]; then echo "\n------ LDAP_TEST#6 succeeded------\n"; else echo "\n------ LDAP_TEST#6 failed------\n"; fi
# Invalid attempt because of wrong LDAP-PW
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'WrongLDAP123!' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "\n------ LDAP_TEST#7 succeeded------\n"; else echo "\n------ LDAP_TEST#7 failed------\n"; fi
# Invalid attempt because of any RADIUS-PW
ldapsearch -D "cn=user03,ou=people,dc=example,dc=org" -w 'User03Test123!,nonexistingOTP' -p 8000 -h ldap-proxy -b "cn=user03,ou=people,dc=example,dc=org"
if [ $? -eq 49 ]; then echo "\n------ LDAP_TEST#8 succeeded------\n"; else echo "\n------ LDAP_TEST#8 failed------\n"; fi

# Check the RADIUS-Frontend of LDAP-Proxy
# Valid attempt of a MFA-user
radtest user01 'User01Test123!,User01OTP' radius-frontend:1812 10 testing123
if [ $? -eq 0 ]; then echo "\n------ RADIUS_TEST#1 succeeded------\n"; else echo "\n------ RADIUS_TEST#1 failed------\n"; fi
# Valid attempt of a non-MFA-user
radtest user03 'User03Test123!' radius-frontend:1812 10 testing123
if [ $? -eq 0 ]; then echo "\n------ RADIUS_TEST#2 succeeded------\n"; else echo "\n------ RADIUS_TEST#2 failed------\n"; fi
# Invalid attempt because of wrong LDAP-PW
radtest user01 'WrongTest123!,User01OTP' radius-frontend:1812 10 testing123
if [ $? -eq 1 ]; then echo "\n------ RADIUS_TEST#3 succeeded------\n"; else echo "\n------ RADIUS_TEST#3 failed------\n"; fi
# Invalid attempt because of wrong RADIUS-PW
radtest user01 'User01Test123!,WrongOTP' radius-frontend:1812 10 testing123
if [ $? -eq 1 ]; then echo "\n------ RADIUS_TEST#4 succeeded------\n"; else echo "\n------ RADIUS_TEST#4 failed------\n"; fi
# Invalid attempt because of wrong Username
radtest user09 'SomePassword123!,SomeOTP' radius-frontend:1812 10 testing123
if [ $? -eq 1 ]; then echo "\n------ RADIUS_TEST#5 succeeded------\n"; else echo "\n------ RADIUS_TEST#5 failed------\n"; fi
# Invalid attempt because non-mfa-user sends OTP
radtest user03 'User03Test123!,SomeOTP' radius-frontend:1812 10 testing123
if [ $? -eq 1 ]; then echo "\n------ RADIUS_TEST#6 succeeded------\n"; else echo "\n------ RADIUS_TEST#6 failed------\n"; fi