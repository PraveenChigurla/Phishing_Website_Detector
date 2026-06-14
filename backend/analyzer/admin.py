from django.contrib import admin
from .models import ScanHistory, DomainPolicy

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('url', 'verdict', 'final_score', 'scanned_at')
    list_filter = ('verdict', 'scanned_at')
    search_fields = ('url', 'verdict')
    readonly_fields = ('scanned_at',)
    ordering = ('-scanned_at',)

@admin.register(DomainPolicy)
class DomainPolicyAdmin(admin.ModelAdmin):
    list_display = ('domain', 'policy', 'reason', 'updated_at')
    list_filter = ('policy', 'updated_at')
    search_fields = ('domain', 'reason')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('domain',)
