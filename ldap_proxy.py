#! /usr/bin/env python

# This script is taken from https://ldaptor.readthedocs.io/en/latest/cookbook/ldap-proxy.html

from ldaptor.protocols import pureldap
from ldaptor.protocols.pureldap import LDAPBindRequest
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from functools import partial
import sys
import os
import re
import radius
import ldap

class LoggingProxy(ProxyBase):

    # Cache for OTP retrieved from the original password
    otp = ""

    # Cache for queried userId, if 2FA is required (only query LDAP once in request-handling)
    user_id = ""

    def handleBeforeForwardRequest(self, request, controls, reply):

        # Only intercept Bind-Requests for MFA
        if not isinstance(request, LDAPBindRequest):
            return defer.succeed((request, controls))

        log.msg("Intercepted Request => " + repr(request))

        # Only perform MFA on users from a given group
        self.user_id = self.isMultiFactorAuthUser(request)
        if not self.user_id:
            return defer.succeed((request, controls))

        password, self.otp = self.splitPasswordAndOTP(request.auth)
        
        # Overwrite the to-be-sent-password with the password-part of the original value
        request.auth = password

        # Only perform MFA before LDAP, if it is configured
        #
        # Else forward the request with the updated password to the upstream LDAP
        # for primary authentication. Secondary auth will be processed during
        # handling of response of upstream LDAP
        if not os.getenv("CHECK_RADIUS_BEFORE_LDAP", 'False').lower() in ('true', '1', 't'):
            return defer.succeed((request, controls))


        if not self.secondFactorAuthentication(self.user_id, self.otp):
            # Find a way to direct respond to the client with an error message
            # https://github.com/twisted/ldaptor/blob/4bfe2897c8b9b510d647fb1c2a5b50c88d492ab1/ldaptor/protocols/ldap/proxybase.py
            return defer.succeed(None)

        return defer.succeed((request, controls))

    def handleProxiedResponse(self, response, request, controls):
        # Ignore all LDAP-Calls but Bind-Requests
        if not isinstance(request, LDAPBindRequest):
            return defer.succeed(response)

        # If LDAP-Authentication failed, forward the response directly (no 2FA)
        if response.resultCode != 0:
            return defer.succeed(response)

        # If the intercepted Bind-Request is from a non-MFA-User, continue
        if not self.user_id:
            return defer.succeed(response)

        # If RADIUS auth has been performed before LDAP, continue
        if os.getenv("CHECK_RADIUS_BEFORE_LDAP", 'False').lower() in ('true', '1', 't'):
            return defer.succeed(response)

        if not self.secondFactorAuthentication(self.user_id, self.otp):
            response.resultCode = 49
            response.errorMessage = b'Wrong OTP'
            return defer.succeed(response)

        return defer.succeed(response)

    def splitPasswordAndOTP(self, ldapPassword):
        password = ""
        otp = ""
        # Pattern description: search the last `,` and use it to split the input in two parts
        pattern = re.compile('^(.*)(,){1}(.*)$')
        # use .decode() to get the actual string from the byte array
        matches = pattern.match(ldapPassword.decode())

        if matches:
            password = matches.group(1)
            otp = matches.group(3)
        else:
            password = ldapPassword

        return password, otp

    # Mostly taken from https://github.com/python-ldap/python-ldap
    def isMultiFactorAuthUser(self, request):
        # Build query like (distinguishedName=CN=Test User,CN=Users,DC=thales,DC=lab)
        query = "({0}={1})".format(os.environ['LDAP_DN_ATTRIBUTE_NAME'], request.dn.decode())

        # Connect and bind to LDAP
        l = ldap.initialize("ldap://{0}:{1}".format(os.environ['UPSTREAM_LDAP_SERVER_HOST'], os.environ['UPSTREAM_LDAP_SERVER_PORT']))
        l.simple_bind_s(os.environ['BIND_USER'], os.environ['BIND_PASSWORD'])

        # Execute the query and filter for non empty results
        result = l.search_s(os.environ['BASE_DN'], ldap.SCOPE_SUBTREE, query)
        resultFiltered = list(filter(lambda x: x[0] != None, result))

        # Check if the user belongs to any group
        if os.environ['LDAP_GROUP_MEMBER_ATTRIBUTE_NAME'] not in resultFiltered[0][1]:
            return None
        # Check if the user is member of the MFA group and return the required auth username for RADIUS
        groupMemberships = resultFiltered[0][1][os.environ['LDAP_GROUP_MEMBER_ATTRIBUTE_NAME']]
        if os.environ['MFA_USER_GROUP'].encode() in groupMemberships:
            radiusUsername = resultFiltered[0][1][os.environ['MFA_USER_NAME_LDAP_ATTRIBUTE']][0]
            return radiusUsername.decode()
        else:
            return None

    def secondFactorAuthentication(self, user, otp):
        r = radius.RADIUS(
            os.environ['RADIUS_SECRET'],
            host=os.environ['RADIUS_HOST'],
            port=int(os.environ['RADIUS_PORT']),
            retries=3,
            timeout=30
        )
        return r.authenticate(user, otp)

def ldapBindRequestRepr(self):
    l=[]
    l.append('version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=***')
    if self.tag!=self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__+'('+', '.join(l)+')'

pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr

if __name__ == '__main__':
    """
    Demonstration LDAP proxy; listens on LISTENING_PORT and
    passes all requests to UPSTREAM_LDAP_SERVER_HOST:UPSTREAM_LDAP_SERVER_PORT.
    """
    log.startLogging(sys.stderr)
    log.msg('[ENV-Vars]')
    log.msg('Upstream-LDAP = ldap://{0}:{1}'.format(os.environ['UPSTREAM_LDAP_SERVER_HOST'], os.environ['UPSTREAM_LDAP_SERVER_PORT']))
    log.msg('Bind-User = {0}'.format(os.environ['BIND_USER']))
    log.msg('MFA-Group = {0}'.format(os.environ['MFA_USER_GROUP']))
    log.msg('Upstream-RADIUS = {0}:{1}'.format(os.environ['RADIUS_HOST'], os.environ['RADIUS_PORT']))
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'tcp:host={0}:port={1}'.format(os.environ['UPSTREAM_LDAP_SERVER_HOST'], os.environ['UPSTREAM_LDAP_SERVER_PORT'])
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(int(os.environ['LISTENING_PORT']), factory)
    reactor.run()