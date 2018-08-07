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

from jwkest.jwk import load_jwks_from_url
from jwkest.jwk import SYMKey
from jwkest.jws import JWS

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
jwks_uri = provider_info['jwks_uri']


def index(request):
    return render(request, 'index.html')


def auth(request):
    global auth_endpoint

    session_info = {}
    session_info['state'] = rndstr()
    session_info['nonce'] = rndstr()

    redirect_uri = 'https://{}{}'.format(request.get_host(),
                                         reverse('openid_auth_callback'))
    params = {
        'response_type': 'code',
        'state': session_info['state'],
        'nonce': session_info['nonce'],
        'client_id': CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': ' '.join(SCOPES_SUPPORTED)
    }

    auth_url = auth_endpoint + '?' + urlencode(params)

    return render(request, 'auth_iframe.html', {'auth_url': auth_url})


def auth_callback(request):
    '''
    '''
    global sessions
    global token_endpoint
    global userinfo_endpoint
    global provider_info

    response = request.GET

    if 'code' not in response or 'state' not in response:
        return HttpResponseBadRequest('Invalid request')

    redirect_uri = 'https://{}{}'.format(request.get_host(),
                                         reverse('openid_auth_callback'))

    # get access token
    params = {
        'grant_type': 'authorization_code',
        'code': response['code'],
        'redirect_uri': redirect_uri
    }

    access_token_response = requests.post(token_endpoint,
                                          auth=(CLIENT_ID, CLIENT_SECRET),
                                          data=params)

    if access_token_response.status_code != 200:
        return HttpResponseBadRequest('Invalid Access Token Response')

    access_json = access_token_response.json()
    access_token = access_json['access_token']
    id_token = access_json['id_token']

    # get userinfo token
    user_response = requests.get(userinfo_endpoint, headers={
        'Authorization': 'Bearer {}'.format(access_token)
    })

    if user_response.status_code != 200:
        return HttpResponseBadRequest('Invalid User Info Response')

    user_json = user_response.json()

    return JsonResponse(dict(userInfoResponse=user_json,
                             idTokenVerification=verify_id(id_token)))


def verify_id(token):
    global jwks_uri

    header, claims, signature = token.split('.')
    header = b64d(header)
    claims = b64d(claims)

    if not signature:
        raise ValueError('Invalid Token')

    if header['alg'] not in ['HS256', 'RS256']:
        raise ValueError('Unsupported signing method')

    if header['alg'] == 'RS256':
        signing_keys = load_jwks_from_url(jwks_uri)
    else:
        signing_keys = [SYMKey(key=str(CLIENT_SECRET))]

    id_token = JWS().verify_compact(token, signing_keys)
    id_token['header_info'] = header
    return id_token


def b64d(token):
    token += ('=' * (len(token) % 4))
    decoded = b64decode(token)
    return json.loads(decoded)
