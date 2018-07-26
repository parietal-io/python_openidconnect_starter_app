from django.conf.urls import url
from django.urls import path

from django.contrib import admin
admin.autodiscover()

import deauthorized.views

urlpatterns = [
    url(r'^$', deauthorized.views.index, name='index'),
    url(r'^auth', deauthorized.views.auth,
        name='auth'),
    url(r'^openid_auth_callback', deauthorized.views.auth_callback,
        name='openid_auth_callback'),
    path('admin/', admin.site.urls),
]
