#!/usr/bin/python

from exploit_database import ExploitDatabase
from exploit_manager import ExploitManager
from security_api import SecurityAPI

import sys
import subprocess
import re
import log
import shutil
import os


class Elem(object):
    def __init__(self, args):
        self.args = args
        self.logger = log.setup_custom_logger('elem')
        self.console_logger = log.setup_console_logger('console')

        self.exploitdb = ExploitDatabase(self.args.exploitdb,
                                         self.args.exploitdbrepo)
        self.exploit_manager = ExploitManager(self.args.exploits,
                                              self.args.exploitsrepo)

    def run(self):

        if hasattr(self.args, 'refresh'):
            self.refresh(self.args.securityapi, self.args.sslverify)
        elif hasattr(self.args, 'list'):
            self.list_exploits(self.args.edbid,
                               self.args.cveid)
        elif hasattr(self.args, 'score'):
            self.score_exploit(self.args.edbid,
                               self.args.version,
                               self.args.kind,
                               self.args.value)
        elif hasattr(self.args, 'assess'):
            self.assess()
        elif hasattr(self.args, 'copy'):
            self.copy(self.args.edbid, self.args.destination)
        elif hasattr(self.args, 'patch'):
            self.patch(self.args.edbid)

    def refresh(self,
                security_api_url,
                sslverify):

        self.exploitdb.refresh_exploitdb_repository()
        self.exploitdb.refresh_exploits_with_cves()
        self.exploit_manager.refresh_exploits_repository()
        self.exploit_manager.load_exploit_info()
        # We will reconcile information from the exploit database with the
        # existing exploit data.
        for edbid in self.exploitdb.exploits.keys():
            # Add an exploit if it doesn't exist
            if edbid not in self.exploit_manager.exploits.keys():
                self.exploit_manager.exploits[edbid] = dict(filename='',
                                                            cves=dict())
                self.exploit_manager.write(edbid)

            # Update the file name if necessary
            if self.exploit_manager.exploits[edbid]['filename'] != \
                    self.exploitdb.exploits[edbid]['filename']:
                self.exploit_manager.exploits[edbid]['filename'] = \
                    self.exploitdb.exploits[edbid]['filename']
                self.exploit_manager.write(edbid)


            # Ensure that all CVE's detected from exploit-db are present in
            # curation information.
            for cveid in self.exploitdb.exploits[edbid]['cves']:
                if cveid not in \
                        self.exploit_manager.exploits[edbid]['cves'].keys():
                    self.exploit_manager.exploits[edbid]['cves'][cveid] = \
                        dict()
                    self.exploit_manager.write(edbid)
        # Next, query the security API
        securityapi = SecurityAPI(security_api_url, sslverify)
        securityapi.refresh()

        # Indicate whether a CVE was found in the security API or not
        for cve in securityapi.cve_list:
            for edbid in self.exploit_manager.exploits.keys():
                if cve in self.exploit_manager.exploits[edbid]['cves'].keys():
                    self.exploit_manager.exploits[edbid]['cves'][cve]['rhapi'] = True
                    self.exploit_manager.write(edbid)

    def list_exploits(self, edbid_to_find=None, cveid_to_find=None):
        results = []
        try:
            self.exploit_manager.load_exploit_info()
        except OSError:
            self.console_logger.error("\nNo exploit information loaded.  "
                                      "Please try: elem refresh\n")
            sys.exit(1)

        if edbid_to_find:
            if self.exploit_manager.affects_el(edbid_to_find):
                results += self.exploit_manager.get_exploit_strings(edbid_to_find)
            else:
                self.console_logger.warn("Exploit ID %s does not appear "
                                         "to affect enterprise Linux." %
                                         edbid_to_find)
                sys.exit(0)

        if cveid_to_find:
            exploit_ids = self.exploit_manager.exploits_by_cve(cveid_to_find)
            for edbid in exploit_ids:
                results += self.exploit_manager.get_exploit_strings(edbid)
            if len(exploit_ids) == 0:
                self.console_logger.warn("There do not appear to be any "
                                         "exploits that affect CVE %s."
                                         % cveid_to_find)


        if not edbid_to_find and not cveid_to_find:
            for edbid in self.exploit_manager.exploits.keys():
                if self.exploit_manager.affects_el(edbid):
                    results += self.exploit_manager.get_exploit_strings(edbid)


        for line in results:
            self.console_logger.info(line)

        if len(results) == 0:
            self.console_logger.warn("There do not appear to be any "
                                     "exploit information available.  Please"
                                     " try: elem refresh")

    def score_exploit(self,
                      edbid,
                      version,
                      score_kind,
                      score):
        try:
            self.exploit_manager.load_exploit_info()
        except OSError:
            self.console_logger.error("\nNo exploit information loaded.  "
                                      "Please try: elem refresh\n")
            sys.exit(1)
        self.exploit_manager.score(edbid, version, score_kind, score)
        self.exploit_manager.write(edbid)

    def assess(self):
        assessed_cves = []
        lines = []
        error_lines = []
        try:
            command = ["yum", "updateinfo", "list", "cves"]
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            lines = out.split('\n')
            error_lines = err.split('\n')
        except OSError:
            self.logger.error("\'assess\' may only be "
                              "run on an Enterprise Linux host.")
            sys.exit(1)
        pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})')
        for line in lines:
            result = re.findall(pattern, line)
            if result and result[0] not in assessed_cves:
                assessed_cves.append(result[0])

        for cveid in assessed_cves:
            edbids = self.exploit_manager.exploits_by_cve(cveid)
            for edbid in edbids:
                strings = self.exploit_manager.get_exploit_strings(edbid)
                for string in strings:
                    self.console_logger.info(string)

    def copy(self, edbid, destination):
        self.exploitdb.refresh_exploits_with_cves()
        self.console_logger.info("Copying from %s to %s." %
                                (self.exploit_manager.exploits[edbid]['filename'],
                                 destination))
        shutil.copy(self.exploit_manager.exploits[edbid]['filename'],
                    destination)

    def patch(self, edbid):
        self.exploitdb.refresh_exploits_with_cves()
        lines = []
        error_lines = []
        cves_to_patch = ','.join(self.exploitdb.exploits[edbid]['cves'])

        try:
            self.console_logger.info("Patching system for EDB ID %s with "
                                     "CVE(s) %s." % (edbid, cves_to_patch))
            command = ["yum", "update", "-y", "--cve", cves_to_patch]
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            self.console_logger.info("Patching Completed.  A system restart" +
                                     "may be necessary.")
        except OSError:
            self.logger.error("\'assess\' may only be "
                              "run on an Enterprise Linux host.")
