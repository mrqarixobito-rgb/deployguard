from django.urls import path

from . import views

app_name = "panel"
urlpatterns = [
    path("", views.overview, name="overview"),
    path("approvals/", views.approvals, name="approvals"),
    path("users/", views.users, name="users"),
    path("users/<int:pk>/", views.user_detail, name="user"),
    path("users/<int:pk>/status/", views.set_status, name="status"),
    path("users/<int:pk>/reset-mfa/", views.reset_mfa, name="reset_mfa"),
    path("prompts/", views.prompts, name="prompts"),
    path("links/", views.links, name="links"),
    path("database/", views.database, name="database"),
    path("settings/", views.ai_settings, name="settings"),
]
