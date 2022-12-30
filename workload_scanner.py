# Make a python function to parse the grype.json output

import json
import subprocess
import time
import os
import re
import argparse
from multiprocessing import Process
import wget
import shutil
import csv
import requests
import platform

parser = argparse.ArgumentParser()
parser.add_argument("-surface_scan", help="Run surface scan only")
parser.add_argument("-deep_scan",help="Run deep scan only")
parser.add_argument("-eod_scan",help="Run both surface and deep scan")
parser.add_argument("-all_scan",help="Run both surface and deep scan")

args = parser.parse_args()

surface_scan = None
if args.surface_scan != None:
    surface_scan = args.surface_scan

deep_scan = None
if args.deep_scan != None:
    deep_scan = args.deep_scan

eod_scan = None
if args.eod_scan != None:
    eod_scan = args.eod_scan

all_scan = None
if args.all_scan != None:
    all_scan = args.all_scan

check_os_version = ["/etc/os-release"]
#check_os_version = {"/etc/redhat-release", "/etc/lsb-release", "/etc/debian_version", "/etc/os-release", "/etc/centos-release", "/etc/SuSE-release"}
change_package_type = {"go-module":"GO", "java-archive": "Java", "deb":"Debian"}
report_grype = []
reject_sev = ["Unknown", "Negligible"]
findings = []
final_data = []
data_report_eod = {}
info = []
parsed_data = {}


def run_grype():
    print("[+] Running deep scan")
    dir_name = "dir:{0}".format(os.environ["folder_name"])
    start = time.time()
    subprocess.run(["grype", dir_name, "-o", "json", "--file", "/tmp/grype.json"])
    print("Time taken for scan: {} seconds".format(round(time.time()-start, 3)))

# Make a python function to  check if the grype.json file exists

def check_file():
    try:
        with open("/tmp/grype.json") as f:
           return "[+] File exists"
    except FileNotFoundError:
        return "[-] File does not exist"

def grype_parse(grype_json):
    with open(grype_json) as f:
        data = json.load(f)
    return data


def change_grype_date(data):

    for i in data["matches"]:
        cve = i["vulnerability"]["id"]
        if "GHSA" not in cve:
            data_to_add = {}
            discription = ""
            severity = ""
            package = ""
            location = []
            data_source = ""
            urls_poc = []
            type_of_package = ""
            version = ""
            if "dataSource" in i["vulnerability"]:
                data_source += i["vulnerability"]["dataSource"]
            if "urls" in i["vulnerability"]:
                for u in i["vulnerability"]["urls"]:
                    urls_poc.append(u)
                
            if "description" in i["vulnerability"]:
                discription += i["vulnerability"]["description"]
            if "severity" in i["vulnerability"]:
                if i["vulnerability"]["severity"] in reject_sev:
                    continue
                else:
                    severity += i["vulnerability"]["severity"]
            if "name" in i["artifact"]:
                package += i["artifact"]["name"]
            if "version" in i["artifact"]:
                version += i["artifact"]["version"]
            if "type" in i["artifact"]:
                if i["artifact"]["type"] in change_package_type:
                    type_of_package += change_package_type[i["artifact"]["type"]]
                else:
                    type_of_package += i["artifact"]["type"]
            if "locations" in i["artifact"]:
                for l in i["artifact"]["locations"]:
                    location.append(l["path"])
            type_platform = ""
            if "language" in i["artifact"]:
                type_of_raw = i["artifact"]["language"]
                if type_of_raw == "":
                    type_platform += "Operating System"
                else:
                    type_platform += "Installed Application"
            data_to_add["cve"] = cve
            data_to_add["data_source"] = data_source
            data_to_add["urls"] = urls_poc
            data_to_add["description"] = discription
            data_to_add["severity"] = severity
            data_to_add["package"] = package
            data_to_add["version"] = version
            data_to_add["type_of_package"] = type_of_package
            data_to_add["location"] = location
            data_to_add["type"] = type_platform
            report_grype.append(data_to_add)

def save_report_grype():
    with open(os.environ["report_file_deep"], 'w', encoding='utf-8') as f:
     json.dump(report_grype, f, ensure_ascii=False, indent=4)
    print("[+] Report saved to {0}".format(os.environ["report_file_deep"]))

def appendToVulns(line):
    line = line.encode("ascii", "ignore")
    line = line.decode()
    with open("cve.csv", "a") as afh:
        afh.write(line)

def download_cve_csv():
    url = "https://cve.mitre.org/data/downloads/allitems.csv"
    filename = wget.download(url)
    print("\n[+] Downloaded CVE CSV file as: " + filename)
    with open(filename, "r", encoding="Latin-1") as rfh:
        csvread = csv.reader(rfh)
        for line in csvread:
            cvenum = line[0]
            desc = line[2]
            line = cvenum + ";" + desc + "\n"
            appendToVulns(line)



def git_clone():
    repo_url = "https://github.com/scipag/vulscan.git"
    repo_name = "scipag_vulscan"
    new_cve_file = "cve.csv"
    subprocess.run(["git", "clone", repo_url, repo_name])
    shutil.copy(new_cve_file, repo_name + "/cve.csv")

def link_pwd():
    os.symlink("scipag_vulscan", "/usr/share/nmap/scripts/vulscan")

def update_cve_db():
    print("[+] Making things ready for surface scan")
    if os.path.exists("cve.csv"):
        os.remove("cve.csv")
    if os.path.exists("scipag_vulscan"):
        shutil.rmtree("scipag_vulscan")
    if os.path.exists("allitems.csv"):
        os.remove("allitems.csv")
    else:
        download_cve_csv()
        git_clone()


def surface_runner():
    print("[+] Running surface scan")
    target = os.environ["target_ip"]
    cmd = "nmap -sV --script=vulscan/vulscan.nse {} -Pn".format(target)
    response = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = response.stdout.read().decode('utf-8')
    port_matcher = re.compile(r'\d+/tcp')
    ports = port_matcher.findall(output)

    ## find all cves between detected ports from nmap output
    
    total_ports = len(ports)
    ## now iterate through each line of the output and stop when we reach the next port
    for i in range(total_ports):
        port = ports[i]
        cves = []
        if i < total_ports - 1:
            next_port = ports[i+1]
        else:
            next_port = None
        output_after_port = output.split(port)[1]
        ## print first line in output after port
        nmap_service_detail_line = output_after_port.split('\n')[0]
        ## let's explode by 2 spaces
        nmap_service_detail_line = nmap_service_detail_line.split('  ')
        ## now remove all elements that are empty
        nmap_service_detail_line = [x for x in nmap_service_detail_line if x]
        ## strip blank spaces from left and right
        nmap_service_detail_line = [x.strip() for x in nmap_service_detail_line]
        ## if array has 1 element, then it's strip by space to 2 elements and another elment with empty string
        if len(nmap_service_detail_line) == 1:
            nmap_service_detail_line = nmap_service_detail_line[0].split(' ')
            nmap_service_detail_line = [x for x in nmap_service_detail_line if x]
            nmap_service_detail_line = [x.strip() for x in nmap_service_detail_line]
            nmap_service_detail_line.append('')

        port_status = re.search(r'open|closed', output_after_port).group(0)
        print("[+] Parsing surface scan output")
        for line in output_after_port.splitlines():
            if next_port and next_port in line:
                break
            cve = re.search(r"(|\[)CVE-?\d+-?\d+", line)
            if cve:
                cves.append(cve.group().strip('[]'))
        try:
            findings.append({
                "port": port,
                "status": nmap_service_detail_line[0],
                "service": nmap_service_detail_line[1],
                "version": nmap_service_detail_line[2],
                "cves": cves,
            })
        except IndexError:
            findings.append({
                "port": port,
                "status": nmap_service_detail_line[0],
                "service": nmap_service_detail_line[1],
                "version": '',
                "cves": cves,
            })

def save_report_nmap():
    with open(os.environ["report_file_surface"], 'w', encoding='utf-8') as f:
     json.dump(findings, f, ensure_ascii=False, indent=4) 
    print("[+] Report saved to {0}".format(os.environ["report_file_surface"]))

def deep_scan_handler():
    run_grype()
    result_check = check_file()
    if result_check ==  "[+] File exists":
        start = time.time()
        data = grype_parse("/tmp/grype.json")
        print("[+] Scan completed. Generating report")
        change_grype_date(data)
        save_report_grype()
        print("Time taken for parsing  scan: {} seconds".format(round(time.time()-start, 3)))
    else:
        print("[-] Scan failed. No report generated")

def surface_scan_handler():
    update_cve_db()
    if os.path.exists("/usr/share/nmap/scripts/vulscan"):
        surface_runner()
        save_report_nmap()
    else:
        print("[-] Scan failed surface scan. As vulscan is not installed")

def end_of_life_check(product):
    url = "https://endoflife.date/api/{product}.json"
    req = requests.get(url.format(product=product))
    if req.status_code == 200:
      data = req.json()
      if data:
        return data
    
def eod(data):
  lines = data.strip().split("\n")
  
  for line in lines:
    try:
      data = line.split("=")
      key = data[0]
      value = data[1]
      value = value.strip("\"")
      parsed_data[key] = value
    except IndexError:
      pass
  if "ID" in parsed_data:
    eod_data = end_of_life_check(parsed_data["ID"])     
    for i in eod_data:
      try:
        if i["latest"] == parsed_data["VERSION_ID"] or i["cycle"] == parsed_data["VERSION_ID"] :
          result = parsed_data["NAME"] + " " + parsed_data["VERSION_ID"] + " " + i["eol"]
          data_report_eod["Operating System"] = parsed_data["NAME"]
          data_report_eod["Version"] = parsed_data["VERSION_ID"]
          data_report_eod["End Of Life"] = i["eol"]
          final_data.append(data_report_eod)
          info.append(result)
      except KeyError:
        pass

def save_eod_result():
  with open(os.environ["report_file_eod"], "w") as f:
    f.write(json.dumps(final_data))
    print("[+] Report saved to {0}".format(os.environ["report_file_eod"]))

def eod_scan_handler():
    print("[+] Starting End of Life check")
    for i in check_os_version:
        if os.path.exists(i):
            with open(i, "r") as file:
                content = file.read()
                eod(content)
                save_eod_result()
        else:
            print("[-] File {0} not found".format(i))
            print("[-] Scan End of Life check failed")

if __name__=="__main__":
    os_name = platform.system()
    if os_name == "Linux":
        if deep_scan == "true":
            start = time.time()
            deep_scan_handler()
            print("Time taken deep scan: {} seconds".format(round(time.time()-start, 3)))
        if surface_scan == "true":
            start = time.time()
            surface_scan_handler()
            print("Time taken surface scan: {} seconds".format(round(time.time()-start, 3)))
        if all_scan == "true":
            start = time.time()
            process1 =  Process(target=surface_scan_handler)
            process2 = Process(target=deep_scan_handler)
            process3 = Process(target=eod_scan_handler)
            process1.start()
            process2.start()
            process3.start()
            process1.join()
            process2.join()
            process3.join()
            print("Time taken for workload scan: {} seconds".format(round(time.time()-start, 3)))
        if eod_scan == "true":
            start = time.time()
            eod_scan_handler()
            print("Time taken for end of life scan: {} seconds".format(round(time.time()-start, 3)))
    else:
        print("[-] This workload script only works on Linux for now")
