from os import environ
from uuid import uuid4

from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse

from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from django.http import HttpResponse


ISSUER = environ.get('OPENID_ISSUER', 'https://srv.qryp.to/op')
IDENTIFIER = environ.get('OPENID_CLIENT_ID', 'deauthorized')
SECRET = environ.get('OPENID_CLIENT_SECRET', '123')
SCOPES_SUPPORTED = ['openid', 'email', 'profile', 'address']
HOST = environ.get('OPENID_HOST', 'srv.qryp.to')
PORT = environ.get('OPENID_PORT', '443')
SCHEME = 'https'


def index(request):
    return render(request, 'index.html')


def auth(request):
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    openid_config = client.provider_config(ISSUER)
    url = openid_config['authorization_endpoint']
    nonce = uuid4().hex
    redirect_uri = 'https://{}{}'.format(request.get_host(),
                                         reverse('openid_auth_callback'))
    url += "?response_type=code"
    url += "&state={}".format(nonce)
    url += "&nonce={}".format(nonce)
    url += "&client_id={}".format(IDENTIFIER)
    url += "&redirect_uri={}".format(redirect_uri)
    url += "&scope={}".format(' '.join(SCOPES_SUPPORTED))
    return redirect(url)


def auth_callback(request):
    '''
    '''
    # get response obj
    #  -- @response = params

    # set openid client redirect response obj
    #  -- client.redirect_uri = openid_auth_callback_url

    # set authorization_code based on response code
    #  -- client.authorization_code = params['code']

    #  get access token
    #  -- @access_token = client.access_token! client_au
    # th_method: client_auth_method

    # get user info
    #  -- @userinfo = @access_token.userinfo!

    # get id token by decoding it
    # -- @id_token = decode_id @access_token.id_token

    # verify id token using issuer, client_id, and nonce
    # --@id_token.verify!(
    # --  issuer: ENV['OPENID_ISSUER'],
    # --  client_id: ENV['OPENID_CLIENT_ID'],
    # --  nonce: stored_nonce
    # --)

    # get openid subject
    # --@openid_subject = @id_token.subject
    import json

    if request.method == 'GET':
        return HttpResponse(json.dumps(request.GET),
                            content_type='application/json')
    elif request.method == 'POST':
        return HttpResponse(json.dumps(request.POST),
                            content_type='application/json')
