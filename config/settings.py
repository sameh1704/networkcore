"""
Django settings for config project.
Compatible with Docker + Celery + Redis + Channels + Port History
"""

import os
from pathlib import Path
from celery.schedules import crontab

# ============================================================
# BASE DIRECTORY
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# SECURITY
# ============================================================
SECRET_KEY = 'django-insecure-x3cz^#vf3^bbvctumj4!9826oxvlf6u6-yx&+fwn+f5-=uay_+'

DEBUG = True

ALLOWED_HOSTS = ["*"]


# ============================================================
# APPLICATIONS
# ============================================================
INSTALLED_APPS = [
    # Django
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Realtime
    'daphne',
    'channels',

    # APIs
    'rest_framework',

    # Local
    'core',
]


# ============================================================
# MIDDLEWARE
# ============================================================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# ============================================================
# URLS & APPLICATION
# ============================================================
ROOT_URLCONF = 'config.urls'

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'


# ============================================================
# TEMPLATES
# ============================================================
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# ============================================================
# DATABASE (PostgreSQL - Docker)
# ============================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'nms',
        'USER': 'nms',
        'PASSWORD': 'nms123',
        'HOST': 'postgres',
        'PORT': 5432,
    }
}


# ============================================================
# CACHE (Redis in Docker, LocMem fallback locally)
# ============================================================
REDIS_CACHE_URL = os.getenv("REDIS_CACHE_URL", "redis://redis:6379/1")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_CACHE_URL,
        "TIMEOUT": 300,
        "KEY_PREFIX": "nms",
    }
}


# ============================================================
# CHANNELS (WebSocket via Redis)
# ============================================================
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("redis", 6379)],
        },
    },
}


# ============================================================
# CELERY (FIXED FOR DOCKER)
# ============================================================
CELERY_BROKER_URL = 'redis://redis:6379/0'
CELERY_RESULT_BACKEND = 'redis://redis:6379/0'

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

CELERY_TIMEZONE = 'Africa/Cairo'
CELERY_ENABLE_UTC = True

CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60


# ════════════════════════════════════════════════════════════
#  PORT HISTORY SETTINGS (إدارة مساحة التخزين)
# ════════════════════════════════════════════════════════════

# ── إعدادات الاحتفاظ بالبيانات ─────────────────────────────
# قلّل هذه القيم إذا كان القرص يمتلئ بسرعة

# آخر 6 ساعات: لقطة كل 5 دقائق (تفصيل كامل)
PORT_HISTORY_FULL_HOURS    = getattr(locals(), 'PORT_HISTORY_FULL_HOURS', 6)

# 6 ساعات → 24 ساعة: لقطة كل 30 دقيقة (تخفيف)
PORT_HISTORY_MEDIUM_HOURS  = getattr(locals(), 'PORT_HISTORY_MEDIUM_HOURS', 24)

# 24 ساعة → 7 أيام: لقطة كل ساعة
PORT_HISTORY_LOW_DAYS      = getattr(locals(), 'PORT_HISTORY_LOW_DAYS', 7)

# الأحداث تُحفظ 30 يوماً
PORT_HISTORY_EVENTS_DAYS   = getattr(locals(), 'PORT_HISTORY_EVENTS_DAYS', 30)

# ── حدود القرص (Disk thresholds) ───────────────────────────
# عند 85% امتلاء → تنظيف طارئ
PORT_HISTORY_DISK_EMERGENCY = getattr(locals(), 'PORT_HISTORY_DISK_EMERGENCY', 85)

# عند 90% امتلاء → إيقاف جمع اللقطات الجديدة
PORT_HISTORY_DISK_PAUSE     = getattr(locals(), 'PORT_HISTORY_DISK_PAUSE', 90)


# ════════════════════════════════════════════════════════════
#  CELERY BEAT SCHEDULE (جدولة المهام)
# ════════════════════════════════════════════════════════════

CELERY_BEAT_SCHEDULE = {

    # ── جمع بيانات المنافذ (Port History) ──────────────────
    # كل 5 دقائق: جمع لقطات لكل السويتشات
    'collect-all-port-snapshots': {
        'task': 'core.tasks.task_collect_all_snapshots',
        'schedule': crontab(minute='*/5'),
    },

    # ── التنظيف الذكي للمساحة (الأهم لمنع امتلاء القرص) ────
    # كل ساعة: تنظيف خفيف
    'smart-cleanup-port-history': {
        'task': 'core.tasks.cleanup_port_history_task',
        'schedule': crontab(minute=0),  # بداية كل ساعة
    },

    # كل يوم الساعة 3 صباحاً: تنظيف عميق
    'deep-cleanup-port-history': {
        'task': 'core.tasks.cleanup_port_history_task',
        'schedule': crontab(hour=3, minute=0),
    },

    # ── مراقبة صحة القرص ───────────────────────────────────
    # كل 30 دقيقة: تقرير عن حالة المساحة
    'disk-health-report': {
        'task': 'core.tasks.disk_health_report',
        'schedule': crontab(minute='*/30'),
    },

    # ── تنظيف قديم (احتياطي) ────────────────────────────────
    # يومياً الساعة 3 صباحاً (ظل للتوافق مع الإعداد القديم)
    'cleanup-old-history': {
        'task': 'core.tasks.cleanup_port_history_task',
        'schedule': crontab(hour=3, minute=0),
    },

    # ── بث الشبكة عبر WebSocket ─────────────────────────────
    # كل 10 ثواني
    'broadcast-network': {
        'task': 'core.tasks.broadcast_network',
        'schedule': 10.0,
    },
}


# ============================================================
# REST FRAMEWORK
# ============================================================
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ]
}


# ============================================================
# INTERNATIONALIZATION
# ============================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Cairo'

USE_I18N = True
USE_TZ = True


# ============================================================
# STATIC FILES
# ============================================================
STATIC_URL = '/static/'

STATIC_ROOT = BASE_DIR / "staticfiles"

STATICFILES_DIRS = [
    BASE_DIR / "static"
]


# ============================================================
# DEFAULT PRIMARY KEY
# ============================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ============================================================
# AUTHENTICATION REDIRECTION
# ============================================================
# صفحة تسجيل الدخول (للمستخدمين غير المسجلين)
LOGIN_URL = 'login'

# التوجيه بعد تسجيل الدخول
LOGIN_REDIRECT_URL = 'dashboard'

# التوجيه بعد تسجيل الخروج
LOGOUT_REDIRECT_URL = 'login'
