#!/usr/bin/env python3

import argparse
import os
from utils import prompt_rmdir_warning, rmdir, mkdir, rmfile
from github import Github
import re
from cmd import run_command
import shutil
import random
import time
from tqdm import tqdm
from pprint import pprint

def create_or_empty_folder(folder):
    if os.path.isdir(folder):
        prompt_rmdir_warning(folder)
        rmdir(folder)
        
    mkdir(folder)
    
    
def list_issues(owner, repo, github):
    issues = github.get("/repos/{}/{}/issues?state=open&labels=verified&per_page=100".format(owner, repo))
    
    body = {}
    
    for i in issues:
        body[i['number']] = i['body']
    
    return body


def get_comments(owner, repo, issue_id, github):
    r = github.get("/repos/{}/{}/issues/{}/comments".format(owner, repo, issue_id))
    
    comments = []
    
    for comment in r:
        comments.append(comment['body'])
    
    return comments
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='download and decrypt all verified submissions')
    
    parser.add_argument("-u", "--user", metavar="string", required=True,
                        help="specify the GitHub user")
    
    parser.add_argument("-t", "--token", metavar="APITOKEN", required=True,
                        help="specify the GitHub API token")
                    
    parser.add_argument("-o", "--owner", metavar="string", required=True,
                        help="specify the repo owner")
                    
    parser.add_argument("-r", "--repo", metavar="string", required=True,
                        help="specify the GitHub Repo")
                    
    parser.add_argument("-d", "--destination", metavar="string", required=False, default=None,
                        help="specify the GitHub Repo")
                    
    args = parser.parse_args()
    
    destination = args.destination
    
    if destination is None:
        destination = args.repo
    
    create_or_empty_folder(destination)
    
    github = Github(args.user, args.token)
    
    issues = list_issues(args.owner, args.repo, github)
    
    for issue_id, body in tqdm(issues.items()):
        comments = get_comments(args.owner, args.repo, issue_id, github)
        
        matches = re.match(r"My NetID is (\w+), and my pub key id is (\w+)", comments[0])
        net_id = matches.group(1)
        key_id = matches.group(2)
        
        net_id_folder = "{}/{}".format(destination, net_id)
        
        if not os.path.isdir(net_id_folder):
            mkdir(net_id_folder)
            
        issue_folder = "{}/{}/".format(net_id_folder, issue_id)
        
        create_or_empty_folder(issue_folder)
        
        with open(issue_folder + "answer.zip.pgp", "w") as f:
            f.write(body)
            
        with open(issue_folder + "pub_key.asc", "w") as f:
            f.write(comments[1])
            
        run_command("gpg --import pub_key.asc", issue_folder)
        
        run_command("gpg -o answer.zip answer.zip.pgp", issue_folder)
        
        run_command("unzip answer.zip -d ./", issue_folder)
        
        rmfile(issue_folder + "answer.zip")
        
        shutil.make_archive("{}/{}".format(net_id_folder, issue_id), "zip", issue_folder)
        
        # GitHub has a limitation for how many requests we can make per minute
        time.sleep(random.randint(1, 3))
    