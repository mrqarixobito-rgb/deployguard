from django.contrib import admin

from .models import AIPrompt, Finding, Scan, Website

admin.site.register(Website)
admin.site.register(Scan)
admin.site.register(Finding)
admin.site.register(AIPrompt)
