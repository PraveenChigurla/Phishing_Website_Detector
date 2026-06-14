from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from .models import ScanHistory, DomainPolicy
from .serializers import ScanHistorySerializer, DomainPolicySerializer
from .services import (
    analyze_url_service, 
    scan_with_urlscan, 
    scan_with_ipqualityscore
)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class AnalyzeURLView(APIView):
    def post(self, request):
        url = request.data.get("url")
        if not url:
            return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            result = analyze_url_service(url)
            return Response(result, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanHistoryListView(APIView):
    def get(self, request):
        history = ScanHistory.objects.all()
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(history, request)
        if page is not None:
            serializer = ScanHistorySerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = ScanHistorySerializer(history, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PolicyConfigView(APIView):
    def get(self, request):
        policies = DomainPolicy.objects.all()
        serializer = DomainPolicySerializer(policies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = DomainPolicySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ------------------ Compatibility Proxies ------------------ #

@api_view(['POST'])
def urlscan_proxy(request):
    url = request.data.get("url")
    if not url:
        return Response({"error": "URL is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    result = scan_with_urlscan(url)
    if result["success"]:
        return Response({"success": True, "message": result["message"]})
    return Response({"success": False, "message": result["message"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def ipquality_proxy(request):
    url = request.query_params.get("url")
    if not url:
        return Response({"error": "Missing URL parameter"}, status=status.HTTP_400_BAD_REQUEST)
        
    result = scan_with_ipqualityscore(url)
    if result["success"]:
        # Match format expected by IPQualityScore frontend service
        # (needs res.data.result and res.data.success = true)
        risk_score = 75 if result["status"] == "phishing" else 10
        return Response({
            "success": True, 
            "result": {
                "risk_score": risk_score, 
                "suspicious": result["status"] == "phishing",
                "message": result["message"]
            }
        })
    return Response({"success": False, "message": result["message"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
