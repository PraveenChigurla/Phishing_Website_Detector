from rest_framework import serializers
from .models import ScanHistory, DomainPolicy

class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = '__all__'


class DomainPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = DomainPolicy
        fields = '__all__'
