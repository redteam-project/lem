from datetime import timedelta, datetime

import os
import dateutil.parser
import requests
import json
import logging


class SecurityAPI(object):
    def __init__(self, baseurl, sslverify=True):
        self.baseurl = baseurl
        self.cve_list = []
        self.logger = logging.getLogger('elem')
        self.console_logger = logging.getLogger('console')
        self.sslverify = sslverify

    def refresh(self):
        self.console_logger.info("Obtain list of CVE's from API.")
        cves_from_api = self.get_data('cve.json', ['per_page=20000'])
        for cve in cves_from_api:
            self.cve_list.append(cve['CVE'])
        self.console_logger.info("Finished obtaining list CVE's from API.")

    def get_data(self, query_type, params=[]):
        url = self.baseurl + '/' + query_type
        if len(params) > 0:
            url += '?'
            for param in params:
                url += param
                url += '&'
        r = requests.get(url, verify=self.sslverify)

        if r.status_code != 200:
            self.logger.error('ERROR: Invalid request; returned {} for the '
                              'following query:\n{}'.format(r.status_code,
                                                            url))
            sys.exit(1)

        if not r.json():
            self.logger.warn('No data returned with the following '
                             'query: %s' % url)
            sys.exit(0)

        return r.json()
