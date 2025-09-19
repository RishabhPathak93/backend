# scanner/tasks/license_sync_task.py
from ..services.license_sync import LicenseSyncService

def sync_license_job(client_id: str):
    """
    Periodic job to sync license data from central server.
    """
    result = LicenseSyncService.fetch_from_central(client_id)
    if not result["success"]:
        print(f"[SYNC ERROR] {result['error']}")
    else:
        print(f"[SYNC OK] License synced for {client_id}")
