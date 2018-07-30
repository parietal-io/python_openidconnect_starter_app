from os import environ
from base64 import b64decode
import json
from django.http import JsonResponse, HttpResponseBadRequest
from django.utils.http import urlencode

from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse

from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic import rndstr

import requests


ISSUER = environ.get('OPENID_ISSUER', 'https://srv.qryp.to/op')
CLIENT_ID = environ.get('OPENID_CLIENT_ID', 'deauthorized')
CLIENT_SECRET = environ.get('OPENID_CLIENT_SECRET', '123')
SCOPES_SUPPORTED = ['openid', 'email', 'profile', 'address']
HOST = environ.get('OPENID_HOST', 'srv.qryp.to')
PORT = environ.get('OPENID_PORT', '443')
SCHEME = 'https'


client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
provider_info = client.provider_config(ISSUER)
auth_endpoint = provider_info['authorization_endpoint']
token_endpoint = provider_info['token_endpoint']
userinfo_endpoint = provider_info['userinfo_endpoint']

sessions = {}


def index(request):
    return render(request, 'index.html')


def auth(request):
    global sessions
    global auth_endpoint

    session_info = {}
    session_info['state'] = rndstr()
    session_info['nonce'] = rndstr()

    sessions[session_info['state']] = session_info

    redirect_uri = 'https://{}{}'.format(request.get_host(),
                                         reverse('openid_auth_callback'))
    params = {
        'response_type': 'code',
        'state': session_info['state'],
        'nonce': session_info['nonce'],
        'client_id': CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': SCOPES_SUPPORTED
    }

    return redirect(auth_endpoint + '?' + urlencode(params))


def auth_callback(request):
    '''
    '''
    global sessions
    global token_endpoint
    global userinfo_endpoint

    if request.method == 'GET':
        response = request.GET
    elif request.method == 'POST':
        response = request.POST

    if 'code' not in response or 'state' not in response:
        return HttpResponseBadRequest('Invalid request')

    if response['state'] not in sessions:
        return HttpResponseBadRequest('Invalid request')

    redirect_uri = 'https://{}{}'.format(request.get_host(),
                                         reverse('openid_auth_callback'))

    # GET ACCESS TOKEN
    params = {
        'grant_type': 'authorization_code',
        'code': response['code'],
        'redirect_uri': redirect_uri
    }

    access_token_response = requests.post(token_endpoint,
                                          auth=(CLIENT_ID, CLIENT_SECRET),
                                          params=params)

    return JsonResponse(dict(results=access_token_response.__dict__))

    if response.status_code != 200:
        return HttpResponseBadRequest('Invalid Access Token Response')

    credentials = response.json()

    return HTTPResgg

    # GET USER INFO - START
    response = requests.get(userinfo_endpoint, headers={
        'Authorization': 'Bearer %s' % access_token
    })

    if response.status_code != 200:
        raise errors.RequestError(provider.userinfo_endpoint, response.status_code)

    claims = response.json()

    # GET ID TOKEN
    # base64 decode

    # VERIFY ID TOKEN
    # base64 decode
    #params = {
    #    'grant_type': 'authorization_code',
    #    'code': response['code'],
    #    'redirect_uri': redirect_uri
    #}

    # get openid subject
    # --@openid_subject = @id_token.subject


def verify_id_token(self, token):
    log.debug('Verifying token %s' % token)
    header, claims, signature = token.split('.')
    header = b64decode(header)
    claims = b64decode(claims)

    if not signature:
        raise errors.InvalidIdToken()

    if header['alg'] not in ['HS256', 'RS256']:
        raise errors.UnsuppportedSigningMethod(header['alg'], ['HS256', 'RS256'])

    id_token = JWS().verify_compact(token, self.signing_keys)
    log.debug('Token verified, %s' % id_token)
    return json.loads(id_token)

def b64decode(token):
    token += ('=' * (len(token) % 4))
    decoded = b64decode(token)
    return json.loads(decoded)
