import os

# ✅ هذا يجب أن يكون أول شيء قبل أي import لـ Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

# ✅ يجب استدعاؤها قبل import أي models
django_asgi_app = get_asgi_application()

# ✅ الآن فقط يمكن استيراد routing الذي يستورد consumers الذي يستورد models
import core.routing

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(
            core.routing.websocket_urlpatterns
        )
    ),
})