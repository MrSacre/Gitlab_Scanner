import json
import os

class ScanDatabase:
    def __init__(self, db_file="scanner_state.json"):
        self.db_file = db_file
        self.index = {}
        self.load_database()
    
    def load_database(self):
        try:
            with open(self.db_file, "r") as f:
                db_repos = json.load(f)
        except Exception as e:
            db_repos = []
        
        self.index = {item['web_url']: item for item in db_repos}
    
    def save_database(self):
        data_list = list(self.index.values())
        with open(self.db_file, "w") as f:
            json.dump(data_list, f, indent=2)
    
    def get_repo_state(self, repo_url):
        return self.index.get(repo_url)
    
    def update_repo_state(self, repo_url, state):
        self.index[repo_url] = state
        self.save_database()
    
    def should_scan_repo(self, repo, last_commit, rescan=False):
        existing_state = self.get_repo_state(repo.get('web_url'))
        
        if existing_state is None:
            return True
        
        if existing_state.get('leak') != False and rescan:
            return True
        
        if existing_state.get('last_commit') != last_commit:
            return True
        
        return False