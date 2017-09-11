from datetime import timedelta, datetime

import os
import dateutil.parser
import requests
import json
from cve import CVE

class SecurityAPI(object):
    def __init__(self,
                 cve_path=os.path.dirname(os.path.realpath(__file__))+"/cves"):

        self.cve_path = cve_path
        self.cve_list = []
        self.new_cves = False
        if not os.path.isdir(self.cve_path):
            os.mkdir(self.cve_path)
        self.load_cves()

    def refresh(self,
                 baseurl):
        print "Updating CVE's from API."
        self.baseurl = baseurl
        cves_from_api = self.get_data('cve.json',['per_page=20000'])
        for cve in cves_from_api:
            cve_file_path = self.cve_path + "/" + cve['CVE'] + '.json'
            if not os.path.isfile(cve_file_path):
                new_cve = CVE(cve['CVE'], self.cve_path)
                self.cve_list.append(new_cve)
        print "Finished updating CVE's from API."


    def get_data(self, query_type, params=[]):
        url = self.baseurl + '/' + query_type
        if len(params) > 0:
            url += '?'
            for param in params:
                url += param
                url += '&'
        r = requests.get(url)

        if r.status_code != 200:
            print('ERROR: Invalid request; returned {} for the following '
                  'query:\n{}'.format(r.status_code, url))
            sys.exit(1)

        if not r.json():
            print('No data returned with the following query:')
            print(url)
            sys.exit(0)

        return r.json()

    def load_cves(self):

        self.cve_file_name_list = [f for f in os.listdir(self.cve_path) if os.path.isfile(os.path.join(self.cve_path, f)) and os.path.join(self.cve_path, f).endswith(".json")]
        for cve_file_name in self.cve_file_name_list:
            cve_id = cve_file_name.replace(".json", "")
            new_cve = CVE(cve_id, self.cve_path, cve_file_name)
            new_cve.read()
            self.cve_list.append(new_cve)
