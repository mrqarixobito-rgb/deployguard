from django.urls import path

from . import views

app_name = "scans"
urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("scans/new/", views.new_scan, name="new"),
    path("scans/<int:pk>/", views.detail, name="detail"),
    path("scans/<int:pk>/rescan/", views.rescan, name="rescan"),
    path("scans/<int:pk>/report.pdf", views.report_pdf, name="report"),
    path("findings/<int:pk>/explain/", views.explain, name="explain"),
]
