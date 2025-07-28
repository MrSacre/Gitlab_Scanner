import os
import json
import subprocess
import time
import shutil
import stat
import requests
import urllib3
from auth import get_access_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clean_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path, onerror=remove_readonly)

def get_last_commit(base_url, repo_id, visibility, token=None, login=None, password=None):
    if visibility == 'public':
        headers = {}
    else:
        if token:
            headers = {'Private-Token': token}
        else:
            access_token = get_access_token(base_url, login, password)
            headers = {"Authorization": f"Bearer {access_token}"}
    
    commits_url = f"{base_url}/api/v4/projects/{repo_id}/repository/commits"
    r = requests.get(commits_url, headers=headers, verify=False)
    
    if r.status_code == 200 and r.json() != []:
        latest_commit = r.json()[0].get('id')
        return latest_commit
    return None

def extract_base_url(url):
    tmp = url.split('/')
    return tmp[0] + '//' + tmp[2]

def update_aggregated_results(repo_url, leak_data):
    aggregated_json_path = "aggregated_leaks.json"
    if os.path.exists(aggregated_json_path):
        with open(aggregated_json_path, "r", encoding="utf-8") as f:
            try:
                aggregated = json.load(f)
            except json.JSONDecodeError:
                aggregated = []
    else:
        aggregated = []
    
    aggregated = [entry for entry in aggregated if entry["repo"] != repo_url]
    
    aggregated.append({
        "repo": repo_url,
        "leaks": leak_data
    })

    with open(aggregated_json_path, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2, ensure_ascii=False)

def check_leak_in_repo(repo, last_commit, auth_mode='public', token=None, login=None, password=None):
    res_json = {
        "web_url": repo.get('web_url'),
        "id": repo.get('id'),
        "last_commit": last_commit,
        "visibility": repo.get("visibility", "public"),
        "leak": None
    }
    
    url = repo.get('http_url_to_repo')
    destination = os.path.abspath("repo_clone_temp")
    print(f"📥 Cloning {url}...")
    
    if auth_mode == 'internal':
        if token:
            url = url.replace('://', '://audit:' + token + '@')
        else:
            url = url.replace('://', '://' + login + ':' + password + '@')
    
    try:
        result = subprocess.run(["git", "-c", "credential.helper=", "clone", url, destination], 
                              check=True, capture_output=True)
        time.sleep(1)
    except subprocess.CalledProcessError as e:
        if os.path.isdir(os.path.join(destination, ".git")):
            print(f"✅ Clone successful (despite possible warning): {url}")
        else:
            print(f"❌ Incomplete clone: {repo.get('web_url')}")
            return 1
    
    timestamp = int(time.time())
    json_output = os.path.join('.', f"{repo.get('path')}_{timestamp}_output.json")
    
    print(f"🕵️ Running Gitleaks analysis...")
    try:
        res = subprocess.run(["gitleaks", "detect", '-s', destination, '-c', 'customrule.toml', 
                            '-v', '-r', f"{repo.get('path')}_{timestamp}_output.json"], 
                           check=True, capture_output=True)
        os.remove(f"{repo.get('path')}_{timestamp}_output.json")
        res_json['leak'] = False
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print("🔍 Gitleaks detected leaks (exit code 1)")
            res_json['leak'] = True
            with open(json_output, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    valid_leaks = []
                    for leak in data:
                        secret = leak.get("Secret", "UNKNOWN")
                        match = leak.get("Match", "UNKNOWN")
                        if secret == "UNKNOWN" or match == "UNKNOWN":
                            print(f"❌ Error parsing JSON: {json_output}")
                            continue
                        else:
                            valid_leaks.append(leak)
                    if valid_leaks:
                        update_aggregated_results(repo.get('web_url'), valid_leaks)
                except json.JSONDecodeError as e:
                    print(f"❌ Error parsing JSON: {e}")
                    return 1
        else:
            print(f"❌ Critical error in gitleaks")
            return 1
    finally:
        if os.path.exists(json_output):
            try:
                os.remove(json_output)
            except Exception as cleanup_error:
                print(f"⚠️ Unable to delete {json_output}: {cleanup_error}")
    
    try:
        clean_dir(destination)
    except Exception as e:
        print(f"❌ Error during cleanup.")
    
    return res_json