#!/usr/bin/env python
#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX

from OTXv2 import OTXv2
import otx_search
import open_file
import hashlib, json, re, time, argparse, os

class FileHandler():
    def read(self, input):
        with open(input, "r") as file_input:
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", file_input.read())
        return ips
    
    def report(self, alerts):
        unixtime = int(time.time())
        filename = "report-" + str(unixtime) + ".json"
        with open(filename, "w") as jfile:
            json.dump(alerts, jfile, indent = 4)
        return filename 


def main():
    # Read arguments
    parser = argparse.ArgumentParser(description='OTX CLI IP Bulk Search')
    parser.add_argument('-input', help='Input File', required=False)
    args = vars(parser.parse_args())

    if args['input']:
        input = args['input']
    else:
        input = "input.txt"


    # Load IP file and use some regex magic to find all ips
    fh = FileHandler()
    ips = fh.read(input)

    # Your API key
    API_KEY = ''
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(API_KEY, server=OTX_SERVER)

    report = {}
    for ip in ips:
        alerts = otx_search.ip(otx, ip)
        report[ip] = alerts
    
    filename = fh.report(report)

    # Opens the file in default program
    open_file.subprocess_opener(filename)


if __name__ == "__main__":
    main()


