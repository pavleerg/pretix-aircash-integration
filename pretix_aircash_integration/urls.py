from django.urls import path
from . import views

# Event-scoped URLs (Pretix will prepend /<organizer>/<event>/)
event_patterns = [
    path("aircash/return/", views.return_ok, name="aircash_return"),
    path("aircash/cancel/", views.return_cancel, name="aircash_cancel"),
    path("aircash/webhook/", views.webhook, name="aircash_webhook"),
]
