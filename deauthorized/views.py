from os import environ
from uuid import uuid4

from django.shortcuts import render
from django.shortcuts import redirect

from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD


ISSUER = environ.get('OPENID_ISSUER', 'https://srv.qryp.to/op')
IDENTIFIER = environ.get('OPENID_CLIENT_ID', 'deauthorized')
SECRET = environ.get('OPENID_CLIENT_SECRET', '123')
SCOPES_SUPPORTED = ['openid', 'email', 'profile', 'address']
HOST = environ.get('OPENID_HOST', 'srv.qryp.to')
PORT = environ.get('OPENID_PORT', '443')
REDIRECT_URI = environ.get('OPENID_REDIRECT_URI', '')
SCHEME = 'https'


# Create your views here.
def index(request):
    # Render a page with a button which redirects to the issuer site
    return render(request, 'index.html')


def auth(request):
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    openid_config = client.provider_config(ISSUER)
    url = openid_config['authorization_endpoint']
    nonce = uuid4().hex
    url += "?response_type=code"
    url += "&state={}".format(nonce)
    url += "&nonce={}".format(nonce)
    url += "&client_id={}".format(IDENTIFIER)
    url += "&redirect_uri={}".format(REDIRECT_URI)
    url += "&scope={}".format(' '.join(SCOPES_SUPPORTED))
    return redirect(url)


def auth_callback(request):
    return render(request, 'auth_callback.html')
