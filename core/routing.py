from django.urls import re_path
from .consumers import NetworkConsumer

websocket_urlpatterns = [
    re_path(r'ws/network/$', NetworkConsumer.as_asgi()),
]