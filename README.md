# GitLab Repository Scanner

A tool for scanning GitLab repositories and detecting secrets/leaks using Gitleaks.

## Features

- Scan public GitLab repositories
- Scan private/internal GitLab repositories with authentication
- Detect secrets and leaks using Gitleaks
- Persistent state management to avoid rescanning unchanged repositories
- Support for both token-based and username/password authentication

## Prerequisites

- Python 3.6+
- Git
- [Gitleaks](https://github.com/gitleaks/gitleaks) installed and available in PATH
- A `customrule.toml` file for Gitleaks configuration

## Installation

1. Clone this repository
2. Ensure Gitleaks is installed and accessible in your PATH
3. Create a `customrule.toml` file with your Gitleaks rules CF : [Default rule file](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) 

## Usage

### Scan Public Repositories

List all public repositories:
```bash
python main.py scan public -U https://gitlab.example.com
```

Scan public repositories for leaks:
```bash
python main.py leaks public -U https://gitlab.example.com
```

### Scan Internal/Private Repositories

Using a token:
```bash
python main.py scan internal -U https://gitlab.example.com -t YOUR_TOKEN
python main.py leaks internal -U https://gitlab.example.com -t YOUR_TOKEN
```

Using username/password:
```bash
python main.py scan internal -U https://gitlab.example.com -u username -p password
python main.py leaks internal -U https://gitlab.example.com -u username -p password
```

### Scan specific Repositories

Using a token:
```bash
python main.py leaks list -l .\url.txt -t YOUR_TOKEN
python main.py leaks list -l .\url.txt -t YOUR_TOKEN
```

Using username/password:
```bash
python main.py leaks list -l .\url.txt -u username -p password
python main.py leaks list -l .\url.txt -u username -p password
```

### Using URL Lists

You can provide a file containing multiple GitLab URLs:
```bash
python main.py leaks public -U urls.txt
```

### Force Rescan

To force rescanning of repositories even if no changes detected:
```bash
python main.py leaks public -U https://gitlab.example.com --rescan true
```

## Output Files

- `scanner_state.json`: Maintains the state of scanned repositories

```json
  {
    "repo_path": "https://gitlab.example.com/secretrepo",
    "id": 1337,
    "last_commit": "d88912cd8f40c78318de551527103c5788ee7fb0",
    "leak": false
  },...
```


- `aggregated_leaks.json`: Contains all detected leaks across repositories

```json
{
    "repo": "https://gitlab.example.com/secretrepo",
    "leaks": [
      {
        "RuleID": "gitlab-pat",
        "Description": "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
        "StartLine": 238,
        "EndLine": 238,
        "StartColumn": 24,
        "EndColumn": 49,
        "Match": "xxxxxxxxx",
        "Secret": "xxxxxxxxxxxxxx",
        "File": "leaked_file.json",
        "SymlinkFile": "",
        "Commit": "d88912cd8f40c78318de551527103c5788ee7fb0",
        "Entropy": 4.132944,
        "Author": "vilain",
        "Email": "leaker.vilain@gmail.com",
        "Date": "1970-01-01T00:00:00Z",
        "Message": "Commit done by vilain",
        "Tags": [],
        "Fingerprint": ""
      },
      {
        Snip....
      }
    ]
  },....
```


- Temporary JSON files are created during Gitleaks analysis and cleaned up automatically

## File Structure

- `main.py`: CLI interface and main application logic
- `scanner.py`: Repository scanning functionality
- `auth.py`: Authentication handling
- `leak_detector.py`: Leak detection using Gitleaks
- `database.py`: State management for scanned repositories