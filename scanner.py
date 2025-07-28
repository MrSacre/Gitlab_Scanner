import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_public_repos(base_url):
    repos = []
    page = 1
    try:
        while True:
            response = requests.get(
                f"{base_url}/api/v4/projects",
                headers={},
                verify=False,
                params={'page': page}
            )
            if response.status_code != 200:
                print(f"❌ Request failed on {base_url} (status code {response.status_code})")
                break
            data = response.json()
            if not data:
                break
            repos.extend(data)
            page += 1
    except Exception as e:
        repos = []
    return repos

def scan_public_repos(url_arg, silent=True):
    all_repos = []
    urls = get_urls_from_arg(url_arg)
    for url in urls:
        print(f"🔍 Scanning public projects: {url}")
        repos = get_public_repos(url)
        all_repos.extend(repos)
    if not silent:
        for repo in all_repos:
            print(f"[PUBLIC] {repo.get('web_url')}")
    return all_repos

def get_internal_repos(base_url, headers):
    repos = []
    page = 1
    while True:
        response = requests.get(
            f"{base_url}/api/v4/projects",
            headers=headers,
            verify=False,
            params={'page': page}
        )
        if response.status_code != 200:
            print(f"❌ Error {response.status_code} on {base_url}")
            break
        data = response.json()
        if not data:
            break
        repos.extend(data)
        page += 1
    return repos

def scan_internal_repos(token_or_user, password, url_arg, silent=True):
    from auth import get_access_token
    
    urls = get_urls_from_arg(url_arg)
    all_repos = []

    for base_url in urls:
        print(f"🔐 Scanning with authentication: {base_url}")

        if password is None:
            headers = {'Private-Token': token_or_user}
        else:
            access_token = get_access_token(base_url, token_or_user, password)
            if not access_token:
                print(f"❌ Failed to retrieve access token for {base_url}")
                continue
            headers = {"Authorization": f"Bearer {access_token}"}

        repos = get_internal_repos(base_url, headers)
        all_repos.extend(repos)

    def sort_key(repo):
        order = {'public': 0, 'internal': 1, 'private': 2}
        return order.get(repo.get('visibility', 'unknown'), 3)

    all_repos.sort(key=sort_key)
    
    if not silent:
        for repo in all_repos:
            visibility = repo.get("visibility", "unknown").upper()
            print(f"[{visibility}] {repo.get('web_url')}")
    return all_repos

def get_urls_from_arg(url_arg):
    if os.path.isfile(url_arg):
        with open(url_arg, 'r') as f:
            urls = [normalize_url(line.strip()) for line in f if line.strip()]
            return urls
    else:
        return [normalize_url(url_arg)]

def normalize_url(url):
    return url.rstrip('/')