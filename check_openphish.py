import requests
import os
import queue
import logging
import threading
import argparse
import doh
import re
import requests
import socket
import urllib3
import ipdb
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util import connection

_orig_create_connection = connection.create_connection
def patched_create_connection(address, *args, **kwargs):
    global use_doh
    if use_doh:
        # Translate host to ip in url
        rhost = "1.2.3.4"
        res = doh.query(address[0])
        if res is not None:
            for r in res:
                if is_ip(r):
                    rhost = r
                    break
        return _orig_create_connection((rhost, address[1]), *args, **kwargs)        
    else:
        return _orig_create_connection((address[0], address[1]), *args, **kwargs)


# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Globals
sam_url = "3.125.105.122"
blocked_set = []
allowed_set = []
ne_set = []
rdir = ''
num_threads = 0
redirect_addr = ''
list_limit = 0
use_doh = False
no_dns = False
no_ip = False
debug_buglist = []  # DEBUG

def is_ip(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)

def get_openphish():
    res = requests.get("https://openphish.com/feed.txt")
    res_text = res.text
    url_list = res_text.split("\n")
    url_set = set([])
    for url in url_list:
            if url.strip() != '':
                url_set.add(url)
    return url_set

def get_alienvault():
    URL = 'https://reputation.alienvault.com/reputation.generic'
    response = requests.get(url=URL)

    lines = response.text.split('\n')
    ip_set = set([])

    for l in lines:
        l = l.strip()
        if (l is not '') and (l[0] is not "#"):
            ip_set.add(l.split(' ')[0])
    return ip_set

def _debug_get_is_phishy(host):
    try:
        res = requests.get("https://reputation.demo.sam.securingsam.io/reputation/query/{}".format(host))
    except:
        return True
    rep = res.json()["reputation"]
    if rep < 40:
        return True
    else:
        return False

def print_set(myset):
    if len(myset) == 0:
        print("(empty)")
    else:
        for url in myset:
            print(url)

def print_dns_summary():
    print("\n\n========== DNS REPUTATION SUMMARY ==========\n")
    print("[+] BLOCKED: ({0})".format(len(blocked_set)))
    print_set(blocked_set)

    print("\n[+] NOT BLOCKED: ({0})".format(len(allowed_set)))
    print_set(allowed_set)

    # print("\n[+] BUGS (Blocked But High Rep): ({0})".format(len(debug_buglist)))   #DEBUG
    # print_set(debug_buglist)
    # print("")

def print_ip_summary():
    print("\n\n========== IP REPUTATION SUMMARY ==========\n")
    print("[+] BLOCKED: ({0})".format(len(blocked_set)))
    print_set(blocked_set)

    print("\n[+] NOT BLOCKED: ({0})".format(len(allowed_set)))
    print_set(allowed_set)
    print("")

def my_get(url, host):
    s = requests.Session()
    return s.get(url, verify=False, timeout=5, headers={"Host": host}, stream=True)

def my_get_doh(url, host):
    connection.create_connection = patched_create_connection  
    conn = urllib3.connection_from_url(url)
    return conn.request('GET', url, headers={"HOST": host}, timeout=2.5, retries=2)

def get_parser():
    parser = argparse.ArgumentParser()
    version = "1.0.0"
    parser.add_argument('--version', '-v', action='version', version=version)
    parser.add_argument('--redirect-addr', '-r', help='Address of the BLOCKED warning site. Default is SAM\'s', default=sam_url)
    parser.add_argument('--num-threads', '-t', help='Number of running threads. Default is 2', default=2, type=int)
    parser.add_argument('--list-limit', '-l', help='URL list max size. Default is O (no limit)', default=0, type=int)
    parser.add_argument('--use-doh', '-d', action='store_true', help='Enable DOH for resolving site. This will test the blocking software\'s ability to protect users using DNS over TLS', default=False)
    parser.add_argument('--no-dns', '-xn', action='store_true', help='Disable DNS reputation test', default=False)
    parser.add_argument('--no-ip', '-xi', action='store_true', help='Disable IP reputation test', default=False)
    
    return parser

def reset_sets():
    global blocked_set
    global allowed_set
    global ne_set

    blocked_set = []
    allowed_set = []
    ne_set = []

class RepCheck(threading.Thread):
 
    def __init__(self, q):
        threading.Thread.__init__(self)
        self.q = q
 
    def run(self):
        while not self.q.empty():
            # gets the url from the queue
            url = self.q.get()
 
            # download the file
            self.download_file(url)

            # send a signal to the queue that the job is done
            self.q.task_done()
 
    def download_file(self, url):
        host = url.split('/')[2]

        if use_doh:
            orig_url = url

            # decide state - Expected RST            
            try:
                res = my_get_doh(url, host)
            except urllib3.exceptions.MaxRetryError as e:
                if type(e.reason) is urllib3.exceptions.ProtocolError:
                    print("[+] Blocked:     {0}".format(orig_url))
                    blocked_set.append(orig_url)
                if type(e.reason) is urllib3.exceptions.ConnectTimeoutError:
                    print("[!] Not Exists:  {0}".format(orig_url))
                    # ne_set.append(orig_url)
                    blocked_set.append(orig_url) 
                return
            except (urllib3.exceptions.HostChangedError,
                    urllib3.exceptions.BodyNotHttplibCompatible,
                    urllib3.exceptions.DecodeError,
                    urllib3.exceptions.HeaderParsingError,
                    urllib3.exceptions.IncompleteRead,
                    urllib3.exceptions.InvalidHeader,
                    urllib3.exceptions.LocationParseError,
                    urllib3.exceptions.LocationValueError,
                    urllib3.exceptions.ResponseError,
                    urllib3.exceptions.SubjectAltNameWarning):
                print("[+] Not Blocked: {0}".format(orig_url))
                allowed_set.append(orig_url)
                return
                        
            print("[+] Not Blocked: {0}".format(orig_url))
            allowed_set.append(orig_url)
                
              
        else:
            # decide state - Expected 302 Redirect
            try:
                res = my_get(url, host)
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL):
                print("[!] Not Exists:  {0}".format(url))
                # ne_set.append(url)
                blocked_set.append(url)
                return
            except (requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects):
                print("[+] Not Blocked: {0}".format(url))
                allowed_set.append(url)
                return
            except (requests.exceptions.BaseHTTPError,
                    requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ContentDecodingError,
                    requests.exceptions.FileModeWarning,
                    requests.exceptions.InvalidHeader,
                    requests.exceptions.InvalidSchema):
                print("[+] Not Blocked: {0}".format(url))
                allowed_set.append(url)
                return
            


            try:
                ip = res.raw._fp.fp.raw._sock.getpeername()[0]
            except AttributeError:

                ip = res.raw._fp.fp.raw._sock.socket.getpeername()[0]

            if  ip == redirect_addr:
                print("[+] Blocked:     {0}".format(url))
                blocked_set.append(url)
                # if not _debug_get_is_phishy(host): # DEBUG
                #     print("--> BUG!!! " + url)
                #     debug_buglist.append(url)
            else:
                print("[+] Not Blocked: {0}".format(url))
                allowed_set.append(url)


class CommCheck(threading.Thread):
    """Threaded Comm Checker"""
 
    def __init__(self, q):
        threading.Thread.__init__(self)
        self.q = q
 
    def run(self):
        while not self.q.empty():
            # gets the url from the queue
            ip = self.q.get()
 
            # download the file
            self.check_ip(ip)

            # send a signal to the queue that the job is done
            self.q.task_done()

    def check_ip(self, ip):
        global blocked_set
        global allowed_set
        allowed_80 = True
        allowed_443 = True

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        try:
            s.connect((ip, 80))
        except socket.timeout:
            allowed_80 = False
        s.close()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((ip, 443))
        except socket.timeout:
            allowed_443 = False
        
        s.close()

        if allowed_80 or allowed_443:
            allowed_set.append(ip)
            print("[+] Not Blocked: {0}".format(ip))
        else:
            blocked_set.append(ip)
            print("[+] Blocked:     {0}".format(ip))


def main(args=None):
    parser = get_parser()
    args = parser.parse_args(args)

    global num_threads
    global redirect_addr
    global list_limit
    global use_doh
    global no_dns
    global no_ip

    num_threads = args.num_threads
    redirect_addr = args.redirect_addr
    list_limit = args.list_limit
    use_doh = args.use_doh
    no_dns = args.no_dns
    no_ip = args.no_ip

    if not no_dns:
        url_set = set(list(get_openphish()))

        url_q = queue.Queue()
        if list_limit:    
            for i, url in enumerate(url_set):
                if i == list_limit:
                    break
                url_q.put(url)
        else:
            for url in url_set:
                url_q.put(url)

        print("[!] Starting DNS reputation test")
        
        if use_doh:
            print("[!] using DNS over TLS...")
        else:
            print("[!] using regular DNS...")

        for i in range(num_threads):
            t = RepCheck(url_q)
            t.setDaemon(True)
            t.start()
            
        # wait for the queue to finish
        url_q.join()
        print_dns_summary()

    if not no_ip:
        reset_sets()

        ip_set = set(list(get_alienvault()))

        ip_q = queue.Queue()

        if list_limit:    
            for i, ip in enumerate(ip_set):
                if i == list_limit:
                    break
                ip_q.put(ip)
        else:
            for ip in ip_set:
                ip_q.put(ip)

        print("[!] Starting IP reputation test")

        for i in range(num_threads):
            t = CommCheck(ip_q)
            t.setDaemon(True)
            t.start()
            
        # wait for the queue to finish
        ip_q.join()

        print_ip_summary()

    print("\nFINISHED TESTS")

if __name__ == '__main__':
    main()