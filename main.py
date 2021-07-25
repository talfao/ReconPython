import argparse
import os
import time
import re


folder = "/home/user/BugBounty/"
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest="filename",help="File of domains")
    parser.add_argument("-d", "--domain", dest="domain", help="One domain")
    parser.add_argument("-s", "--subs-enumeration", dest="subs", help="\n Write: \n -s all = for (subfinder,amass,assetfinder) \n -s amass = for (amass)\n -s fast = for (assetfinder and subfinder) ")
    parser.add_argument("-p", "--phrase", dest="mode", help="For tools: -p all = all phrases, \n -p enum = subdomain enumeration, \n -p alive = httprobe, \n -p wayback = waybackurls, \n -p scan = port scanning, \n -p takeover = subdomain takeover, \n -p spidering = gospider. \n -p domains (enum,alive,takeover)")
    options = parser.parse_args()
    return options
def prepare_workspace(url):
    print("Preparing workspace...Creating folders")
    path_main = folder + url
    path_recon = path_main + "/recon"
    path_httprobe = path_recon + "/httprobe"
    path_wayback = path_recon + "/wayback"
    path_wayback_params = path_wayback + "/params"
    path_wayback_extent = path_wayback + "/extent"
    path_scans = path_recon + "/scans"
    path_takeovers = path_recon + "/potential_takeovers"

    try:
        os.mkdir(path_main)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_recon)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_httprobe)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_wayback)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_wayback_extent)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_wayback_params)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_scans)
    except OSError as error:
        print(error)
    try:
        os.mkdir(path_takeovers)
    except OSError as error:
        print(error)

def scan_for_subdomains(url,subs):
    output_subdomains = folder + url +"/recon/allDomains.txt"
    subfinder = "subfinder -d " + url +" >> "+ output_subdomains
    assetfinder = "assetfinder " + url + " >> " + output_subdomains
    amass = "amass enum -d " + url + " >> " + output_subdomains
    subs = subs.lower()
    if (subs == "all"):
        print("Subfinder is running for "+ url)
        os.system(subfinder)
        time.sleep(60)
        print("Assetfinder is running for " + url)
        os.system(assetfinder)
        time.sleep(60)
        print("Amass is running for " + url)
        os.system(amass)
        time.sleep(60)
    elif(subs == "amass"):
        print("Amass is running for " + url)
        os.system(amass)
        time.sleep(60)
    elif (subs == "fast"):
        print("Subfinder is running for " + url)
        os.system(subfinder)
        time.sleep(60)
        print("Assetfinder is running for " + url)
        os.system(assetfinder)
        time.sleep(60)
    else:
        print("Bad argument was set, use -h for help")
    #print("Sorting them:")
def scan_for_subdomain_takeover(url):
    print("Checking for potential subdomain takeovers")
    subjack = "subjack -w "+folder+"/"+url+"/recon/allDomains.txt -t 100 -timeout 30 -ssl -c /root/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o "+ folder +"/"+url+"/recon/potential_takeovers/potential_takeovers.txt"
    os.system(subjack)
def check_for_alive_subs(url):
    print("Scanning for alive subdomains...")
    path_to_all = folder + url +"/recon/allDomains.txt"
    path_to_with = folder + url +"/recon/httprobe/with_https.txt"
    path_alive = folder + url + "/recon/httprobe/alive.txt"
    httprobe_with_http = "cat "+path_to_all+" | sort -u | httprobe -s -p https:443 >> "+ path_to_with
    os.system(httprobe_with_http)
    httprobe_alive = "cat "+path_to_with+" | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> " + path_alive
    os.system(httprobe_alive)
def wayback(url):
    print("Scraping wayback data....")
    wayback_output_path = folder+url+"/recon/wayback/wayback_output.txt"
    wayback_output_extent_path =folder+url+"/recon/wayback/extent/extenstions.txt"
    wayback_output_params_path = folder+url+"/recon/wayback/params/params.txt"
    wayback = "cat "+ folder + url + "/recon/allDomains.txt | waybackurls >> " + wayback_output_path
    os.system(wayback)
    wayback_output = open(wayback_output_path, "r")
    params = open(wayback_output_params_path, "w")
    extent = open(wayback_output_extent_path,"w")
    for line in wayback_output:
            parameter = re.search("(\?|\&)([^=]+)\=([^&]+)",line)
            ext = re.search("(\...)$",line)
            if parameter:
                params.write(line)
            if ext:
                extent.write(line)


    wayback_output.close()
    params.close()
    extent.close()


def portScan():
    pass
def spidering():
    pass










def main():
    options = get_arguments()
    mode = options.mode
    mode = mode.lower()
    if options.filename:
        domains = open("domains.txt", "r")
        for domain in domains:
            domain=domain.strip()
            prepare_workspace(domain)
            if mode == "all":
                scan_for_subdomains(domain, options.subs)
                scan_for_subdomain_takeover(domain)
                check_for_alive_subs(domain)
                wayback(domain)
            elif mode == "enum":
                scan_for_subdomains(domain, options.subs)
            elif mode == "domains":
                scan_for_subdomains(domain, options.subs)
                scan_for_subdomain_takeover(domain)
                check_for_alive_subs(domain)
            elif mode == "takeover":
                scan_for_subdomain_takeover(domain)
            elif mode == "alive":
                check_for_alive_subs(domain)
            elif mode == "wayback":
                wayback(domain)
        domains.close()
    if options.domain:
        domain = options.domain
        prepare_workspace(domain)
        if mode == "all":
            scan_for_subdomains(domain, options.subs)
            scan_for_subdomain_takeover(domain)
            check_for_alive_subs(domain)
            wayback(domain)
        elif mode == "enum":
            scan_for_subdomains(domain, options.subs)
        elif mode == "domains":
            scan_for_subdomains(domain, options.subs)
            scan_for_subdomain_takeover(domain)
            check_for_alive_subs(domain)
        elif mode == "takeover":
            scan_for_subdomain_takeover(domain)
        elif mode == "alive":
            check_for_alive_subs(domain)
        elif mode == "wayback":
            wayback(domain)




main()








#domains.close()

