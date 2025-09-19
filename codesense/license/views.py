# scanner/api/license_views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from .services.license_manager import LicenseManager
from .services.license_sync import LicenseSyncService

class LicenseStatusView(APIView):
    def get(self, request, client_id):
        status = LicenseManager.get_status(client_id)
        return Response(status)

class LicenseCheckLimitView(APIView):
    def post(self, request, client_id):
        usage = request.data
        result = LicenseManager.check_limit(client_id, usage)
        return Response(result)

class LicenseSyncView(APIView):
    def post(self, request, client_id):
        result = LicenseSyncService.fetch_from_central(client_id)
        return Response(result)