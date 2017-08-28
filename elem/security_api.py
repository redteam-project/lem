from datetime import timedelta, datetime

import os
import dateutil.parser
import requests
import json

class SecurityAPI(object):
    def __init__(self,
                 baseurl,
                 cve_path=os.path.dirname(os.path.realpath(__file__))+"/cves"):
        self.baseurl = baseurl
        self.cve_path = cve_path
        self.cve_list = []
        if not os.path.isdir(self.cve_path):
            os.mkdir(self.cve_path)

        self.load_cves()
        since_date = self.get_recent_cve_date()
        yesterday = datetime.now().replace(hour=00,
                                           minute=00,
                                           second=00,
                                           microsecond=00) - timedelta(1)
        # If our existing CVE data is older than yesterday, get new data
        if since_date != yesterday:
            print "Security API data is more than a day old.  Querying for new data."
            self.cvedata = self.get_data('cve.json',
                                         ['per_page=50000',
                                          'after=' + str(since_date)])

            for cve in self.cvedata:
                cve = self.get_data('cve/' + cve['CVE'] + '.json')
                self.write_cve(cve)
                self.cve_list.append(cve)

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

    def write_cve(self, cve_json):

        cve_file_name = self.cve_path + '/' + cve_json['name'] + '.json'
        with open(cve_file_name, 'w') as cve_file:
            json.dump(cve_json, cve_file)

    def load_cves(self):

        cve_file_name_list = [f for f in os.listdir(self.cve_path) if os.path.isfile(os.path.join(self.cve_path, f))]
        for cve_file_name in cve_file_name_list:
            with open(self.cve_path + '/' + cve_file_name, 'r') as cve_file:
                self.cve_list.append(json.load(cve_file))

    def get_recent_cve_date(self):
        recent_date = dateutil.parser.parse('2010-11-10T00:00:00')
        for cve in self.cve_list:
            new_date = dateutil.parser.parse(cve['public_date'])
            if new_date > recent_date:
                recent_date = new_date
        return recent_date
