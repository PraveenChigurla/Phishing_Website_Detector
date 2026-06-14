from django.urls import path
from .views import (
    AnalyzeURLView, 
    ScanHistoryListView, 
    PolicyConfigView,
    urlscan_proxy,
    ipquality_proxy
)

urlpatterns = [
    path('analyze', AnalyzeURLView.as_view(), name='analyze_url'),
    path('history', ScanHistoryListView.as_view(), name='scan_history'),
    path('policy', PolicyConfigView.as_view(), name='domain_policy'),
    
    # Compatibility and Direct Scan API endpoints
    path('urlscan', urlscan_proxy, name='urlscan_proxy'),
    path('ipquality', ipquality_proxy, name='ipquality_proxy'),
]
