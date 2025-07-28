import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_access_token(base_url, login, password):
    data = {
        "grant_type": "password",
        "username": login,
        "password": password
    }

    try:
        r = requests.post(
            f"{base_url}/oauth/token",
            verify=False,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Referer": base_url
            },
            json=data,
            timeout=10
        )
        if r.status_code == 404:
            print(f"❌ /oauth/token not found on {base_url}")
            return None
        token = r.json().get("access_token")
        if not token:
            print("❌ Authentication failed (no token returned)")
        return token
    except Exception as e:
        print(f"❌ Exception during authentication: {e}")
        return None