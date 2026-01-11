#!/usr/bin/env python3
"""
Cat Genie API Client

Makes authenticated requests to the Cat Genie API.
"""

import requests
import json
from catgenie_api import generate_request_headers

# API Base URL
BASE_URL = "https://iot.petnovations.com"

# JWT token captured from the app via Frida
JWT_TOKEN = ""

class CatGenieClient:
    def __init__(self, jwt_token: str = None, base_url: str = BASE_URL):
        self.base_url = base_url
        self.jwt_token = jwt_token
        self.session = requests.Session()

    def _make_request(
        self,
        method: str,
        path: str,
        body: dict = None,
        params: dict = None,
        require_auth: bool = True
    ) -> requests.Response:
        """Make an authenticated request to the API."""

        # Generate signature headers
        headers = generate_request_headers(path, method, body, params)

        # Add standard headers
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        headers["Accept-Language"] = "en-US"

        # Add JWT if available and required
        if require_auth and self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        url = f"{self.base_url}/{path}"

        print(f"\n{'='*60}")
        print(f"Request: {method} {url}")
        print(f"Headers:")
        for k, v in headers.items():
            if k == "Authorization":
                print(f"  {k}: Bearer <token>")
            else:
                print(f"  {k}: {v}")

        if body:
            print(f"Body: {json.dumps(body)}")

        response = self.session.request(
            method=method,
            url=url,
            headers=headers,
            json=body,
            params=params
        )

        print(f"\nResponse: {response.status_code}")
        try:
            print(f"Body: {json.dumps(response.json(), indent=2)}")
        except:
            print(f"Body: {response.text[:500]}")

        return response

    def get(self, path: str, params: dict = None, require_auth: bool = True):
        return self._make_request("GET", path, params=params, require_auth=require_auth)

    def post(self, path: str, body: dict = None, require_auth: bool = True):
        return self._make_request("POST", path, body=body, require_auth=require_auth)

    # API Methods - discovered from Frida hooks
    def get_devices(self):
        """Get list of devices."""
        return self.get("device/device/v2", params={"useFleetIndexAndGetRealConnectivity": "true"})

    def get_notifications(self):
        """Get user notifications including firmware updates."""
        return self.get("notification/v1/push/user")

    def get_all_notifications(self):
        """Get all notifications for the user."""
        return self.get("notification/v1/notification/user")

    def get_pet_statistics(self, start_time: str = None):
        """Get pet usage statistics."""
        params = {}
        if start_time:
            params["startTime"] = start_time
        return self.get("device/history/account/pet/statistics", params=params)

    def get_account(self):
        """Get account info."""
        return self.get("ums/v1/users/account")

    def get_firmware_notifications(self):
        """Get firmware update notifications."""
        return self.get("notification/v1/notification/user")

    def get_device_update(self, manufacturer_id: str):
        """Get device update/firmware info."""
        return self.get(f"device/update/{manufacturer_id}")

    def get_update_versions(self):
        """Get available firmware versions."""
        return self.get("device/update/versions/comments")

    def get_push_notifications_by_type(self, notification_type: str = "FW_UPDATE"):
        """Get notifications by type (e.g., FW_UPDATE)."""
        return self.get(f"notification/v1/push/forUserByType/{notification_type}")

    def get_device_thing(self, manufacturer_id: str):
        """Get device thing info."""
        return self.get(f"device/v1/thing/{manufacturer_id}")

    def get_mainboard(self, manufacturer_id: str):
        """Get mainboard info."""
        return self.get(f"device/mainBoard/{manufacturer_id}")

    def get_push_notifications(self):
        """Get push notifications."""
        return self.get("notification/v1/push/user")

    def get_firmware_comments(self, version: str):
        """Get firmware release notes/comments."""
        return self.get("device/update/versions/comments", params={"name": version})


def test_without_auth():
    """Test API responses without authentication."""
    print("\n" + "="*60)
    print("Testing API without authentication")
    print("="*60)

    client = CatGenieClient()

    # Try various endpoints without auth
    endpoints = [
        ("GET", "facade/v1/mobile-user/version"),
        ("GET", "facade/v1/health"),
        ("GET", "facade/v1/app/config"),
    ]

    for method, path in endpoints:
        try:
            if method == "GET":
                client.get(path, require_auth=False)
        except Exception as e:
            print(f"Error: {e}")


def test_with_auth():
    """Test API with authentication."""
    print("\n" + "="*60)
    print("Testing API with authentication")
    print("="*60)

    client = CatGenieClient(jwt_token=JWT_TOKEN)

    # Get devices
    print("\n--- Getting devices ---")
    try:
        response = client.get_devices()
        if response.status_code == 200:
            data = response.json()
            things = data.get("thingList", [])
            print(f"\nFound {len(things)} devices:")
            for d in things:
                print(f"  {d['manufacturerId']}: {d['name']} - FW: {d['fwVersion']}")
    except Exception as e:
        print(f"Error: {e}")

    # Test possible firmware endpoints
    manufacturer_id = ""  # The connected device

    print(f"\n--- Getting device update info for {manufacturer_id} ---")
    try:
        response = client.get_device_update(manufacturer_id)
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- Getting update versions ---")
    try:
        response = client.get_update_versions()
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- Getting FW_UPDATE notifications ---")
    try:
        response = client.get_push_notifications_by_type("FW_UPDATE")
    except Exception as e:
        print(f"Error: {e}")

    print(f"\n--- Getting mainboard for {manufacturer_id} ---")
    try:
        response = client.get_mainboard(manufacturer_id)
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- Getting push notifications ---")
    try:
        response = client.get_push_notifications()
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- Getting firmware comments for 8.7.203R ---")
    try:
        response = client.get_firmware_comments("8.7.203R")
    except Exception as e:
        print(f"Error: {e}")


def main():
    """Main entry point."""
    print("Cat Genie API Client")
    print("="*60)

    if JWT_TOKEN:
        test_with_auth()
    else:
        print("No JWT token configured. Run Frida capture first.")
        test_without_auth()


if __name__ == "__main__":
    main()
