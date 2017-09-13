from datetime import timedelta, datetime

import os
import dateutil.parser
import requests
import json
import logging


class SecurityAPI(object):
    def __init__(self, baseurl):
        self.baseurl = baseurl
        self.cve_list = []
        self.logger = logging.getLogger('elem')

    def refresh(self):
        self.logger.info("Updating CVE's from API.")
        cves_from_api = self.get_data('cve.json',['per_page=20000'])
        for cve in cves_from_api:
            self.cve_list.append(cve['CVE'])
        self.logger.info("Finished updating CVE's from API.")

    def get_data(self, query_type, params=[]):
        url = self.baseurl + '/' + query_type
        if len(params) > 0:
            url += '?'
            for param in params:
                url += param
                url += '&'
        r = requests.get(url)

        if r.status_code != 200:
            self.logger.error('ERROR: Invalid request; returned {} for the following '
                  'query:\n{}'.format(r.status_code, url))
            sys.exit(1)

        if not r.json():
            self.logger.warn('No data returned with the following query: %s' % url)
            sys.exit(0)

        return r.json()

    def load_cves(self):

        self.cve_file_name_list = [f for f in os.listdir(self.cve_path) if os.path.isfile(os.path.join(self.cve_path, f)) and os.path.join(self.cve_path, f).endswith(".json")]
        for cve_file_name in self.cve_file_name_list:
            cve_id = cve_file_name.replace(".json", "")
            new_cve = CVE(cve_id, self.cve_path, cve_file_name)
            new_cve.read()
            self.cve_list.append(new_cve)

    def exploits_dict(self, edbid_to_find=None):
        result = {}
        for cve in self.cve_list:
            result[cve.id] = cve
        return result
