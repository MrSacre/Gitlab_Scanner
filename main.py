#!/usr/bin/env python3
import argparse
import sys
from scanner import scan_public_repos, scan_internal_repos
from leak_detector import check_leak_in_repo, get_last_commit, extract_base_url
from database import ScanDatabase

def configure_auth(args):
    if args.token:
        return {
            'mode': 'internal',
            'token': args.token,
            'login': 'oauth2',
            'password': None
        }
    elif args.user and args.password:
        return {
            'mode': 'internal',
            'token': None,
            'login': args.user,
            'password': args.password
        }
    else:
        return {'mode': 'public'}

def validate_internal_auth(args):
    has_token = args.token is not None
    has_login = args.user is not None and args.password is not None
    if not has_token and not has_login:
        print("❌ You must provide either --token or --user + --password for this mode.")
        sys.exit(1)

def scan_repo_list(repos, rescan, auth_config):
    db = ScanDatabase()
    count = 1
    
    for repo in repos:
        base_url = extract_base_url(repo.get('web_url'))
        last_commit = get_last_commit(
            base_url, 
            repo.get('id'), 
            repo.get("visibility", "public"),
            auth_config.get('token'),
            auth_config.get('login'),
            auth_config.get('password')
        )
        
        if db.should_scan_repo(repo, last_commit, rescan):
            result = check_leak_in_repo(
                repo, 
                last_commit, 
                auth_config.get('mode', 'public'),
                auth_config.get('token'),
                auth_config.get('login'),
                auth_config.get('password')
            )
            if isinstance(result, dict):
                db.update_repo_state(repo.get('web_url'), result)
            print(f"✅ {count}/{len(repos)} Scanned {repo.get('web_url')}")
        else:
            print(f"✅ {count}/{len(repos)} Skipped {repo.get('web_url')}")
        count += 1

def main():
    parser = argparse.ArgumentParser(description="GitLab Repository Scanner and Leak Detector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_url_argument(subparser):
        subparser.add_argument("-U", "--url", required=True, 
                             help="GitLab URL or file containing a list of URLs")

    scan_parser = subparsers.add_parser("scan", help="Scan GitLab repositories")
    scan_subparsers = scan_parser.add_subparsers(dest="mode", required=True)

    scan_public = scan_subparsers.add_parser("public", help="Scan public repositories")
    add_common_url_argument(scan_public)

    scan_internal = scan_subparsers.add_parser("internal", help="Scan repositories requiring authentication")
    add_common_url_argument(scan_internal)
    scan_internal.add_argument("-t", "--token", help="Access token")
    scan_internal.add_argument("-u", "--user", help="Username")
    scan_internal.add_argument("-p", "--password", help="Password")

    leaks_parser = subparsers.add_parser("leaks", help="Scan GitLab repositories for secrets")
    leaks_subparsers = leaks_parser.add_subparsers(dest="mode", required=True)

    leaks_public = leaks_subparsers.add_parser("public", help="Leak scan on public repositories")
    leaks_public.add_argument("--rescan", choices=["true", "false"], default="false", 
                            help="Force rescan even if leak was found and nothing changed")
    add_common_url_argument(leaks_public)

    leaks_internal = leaks_subparsers.add_parser("internal", help="Leak scan on internal repositories")
    add_common_url_argument(leaks_internal)
    leaks_internal.add_argument("--rescan", choices=["true", "false"], default="false", 
                              help="Force rescan even if leak was found and nothing changed")
    leaks_internal.add_argument("-t", "--token", help="Access token")
    leaks_internal.add_argument("-u", "--user", help="Username")
    leaks_internal.add_argument("-p", "--password", help="Password")

    args = parser.parse_args()
    auth_config = configure_auth(args) if hasattr(args, 'token') else {'mode': 'public'}
    
    if args.command == "scan":
        if args.mode == "public":
            scan_public_repos(args.url, False)
        elif args.mode == "internal":
            validate_internal_auth(args)
            if args.token:
                scan_internal_repos(args.token, None, args.url, False)
            else:
                scan_internal_repos(args.user, args.password, args.url, False)
    
    elif args.command == "leaks":
        rescan_enabled = args.rescan.lower() == "true"
        if args.mode == "public":
            repos = scan_public_repos(args.url)
            scan_repo_list(repos, rescan_enabled, {'mode': 'public'})
        elif args.mode == "internal":
            validate_internal_auth(args)
            auth_config = configure_auth(args)
            if args.token:
                repos = scan_internal_repos(args.token, None, args.url)
            else:
                repos = scan_internal_repos(args.user, args.password, args.url)
            scan_repo_list(repos, rescan_enabled, auth_config)

if __name__ == "__main__":
    main()