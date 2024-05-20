#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
AngryFuzz3r is a collection of tools for pentesting to gather information about the targets based on Fuzzedb https://github.com/fuzzdb-project/fuzzdb
This tool fuzzes and finds some pages on the server.
"""
__author__ = "Iheb Ben Salem (S0ld1er)"
__copyright__ = "Copyright 2017, Bugs_Bunny Team | Pentesting Tools"
__version__ = "0.5"
__email__ = "ihebbensalem.dev@gmail.com"
__status__ = "Development"
__codename__ = 'urlfuzzer'
__source__ = "https://github.com/ihebski/angryFuzzer"
__info__ = "URL Fuzzing"

import re
import requests
import sys
import os
import argparse
from urllib.parse import urlparse
import time

wordlists = {
    "dict": "fuzzdb/discovery/predictable-filepaths/dicc.txt",
    "wp": "fuzzdb/discovery/predictable-filepaths/cms/wordpress.txt",
    "dp": "fuzzdb/discovery/predictable-filepaths/cms/drupal_plugins.txt",
    "jm": "fuzzdb/discovery/predictable-filepaths/cms/joomla_plugins.txt",
}

class Colors:
    BLUE = '\033[94m'
    LIGHTRED = '\033[91m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    RED = '\033[91m'

def banner():
    print(Colors.BLUE + "   _____                               ___________                    ________        ")
    print(Colors.LIGHTRED + "  /  _  \   ____    ___________ ___.__.\_   _____/_ __________________\_____  \______ ")
    print(" /  /_\  \ /    \  / ___\_  __ <   |  | |    __)|  |  \___   /\___   /  _(__  <_  __ \"")
    print("/    |    \   |  \/ /_/  >  | \/\___  | |     \ |  |  //    /  /    /  /       \  | \/")
    print("\____|__  /___|  /\___  /|__|   / ____| \___  / |____//_____ \/_____ \/______  /__|   ")
    print(Colors.BLUE + "        \/     \//_____/        \/          \/              \/      \/       \/       \n")
    print(Colors.CYAN + "============>" + __source__)
    print(Colors.BLUE + "===========================================> by Sold1er \n" + Colors.RESET)

def parse_arguments():
    parser = argparse.ArgumentParser(description="[*] Discover hidden files and directories")
    parser.add_argument('-q', '--quiet', action="store_true", help="Silent mode, only report")
    parser.add_argument('-u', '--url', type=str, required=True, help="URL of the Target")
    parser.add_argument('-c', '--cms', type=str, choices=["wp", "dp", "jm"], help="Scan CMS ==> wp, dp, jm")
    parser.add_argument('-w', '--wordlist', type=str, help="Custom wordlist")
    return parser.parse_args()

def report(results):
    """Final Results of the Valid URLs with status code = 200 OK"""
    print(Colors.WHITE + "=== Report ====")
    for url in results:
        print(Colors.MAGENTA + "[+] -[200] -" + url)

def fuzz(url, cms_type, custom_wordlist):
    """All the logic of the application goes here."""
    results = []
    if cms_type:
        wordlist_path = wordlists[cms_type]
    elif custom_wordlist:
        wordlist_path = custom_wordlist
    else:
        wordlist_path = wordlists["dict"]
    
    try:
        with open(wordlist_path, "r") as f:
            words = [w.strip() for w in f.readlines()]

        for path in words:
            if not path.startswith('/'):
                path = '/' + path
            if not path.endswith('/'):
                path += '/'
            
            full_path = url + path
            try:
                r = requests.get(full_path)
                code = r.status_code
                if code == 200:
                    print(Colors.GREEN + f"[+] [{time.strftime('%H:%M:%S')}] - [{code}] - [{path}] -> {full_path}")
                    results.append(full_path)
                elif code == 301:
                    print(Colors.YELLOW + f"[+] [{time.strftime('%H:%M:%S')}] - [{code}] - [{path}] -> {full_path}")
                else:
                    print(Colors.LIGHTRED + f"[+] [{time.strftime('%H:%M:%S')}] - [{code}] - [{path}] -> {full_path}")
            except requests.RequestException as e:
                print(Colors.RED + f"[!] Request error: {e}")

        report(results)
    except Exception as e:
        print(Colors.RED + f"[!] Error: {e}")

def main():
    args = parse_arguments()
    banner()

    o = urlparse(args.url)
    if o.scheme not in ['http', 'https']:
        print(Colors.RED + "[!] Please check your URL scheme (http:// or https://)")
        sys.exit(0)

    if args.wordlist and not os.path.isfile(args.wordlist):
        print(Colors.RED + "[!] Please check your custom wordlist path")
        sys.exit(0)

    fuzz(args.url, args.cms, args.wordlist)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting... :)")
        sys.exit(0)
