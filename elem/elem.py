#!/usr/bin/python


from exploit_database import ExploitDatabase
from security_api import SecurityAPI
from cve import CVE

import sys
import subprocess
import re
import log

class Elem(object):
    def __init__(self, args):
        self.args = args
        self.logger = log.setup_custom_logger('elem')
        self.console_logger = log.setup_console_logger('console')

    def run(self):

        if hasattr(self.args, 'refresh'):
            self.refresh(self.args.securityapi,
                         self.args.api,
                         self.args.exploitdb,
                         self.args.exploits)
        elif hasattr(self.args, 'list'):
            self.list_exploits(self.args.edbid,
                               self.args.exploitdb,
                               self.args.exploits)
        elif hasattr(self.args, 'score'):
            self.score_exploit(self.args.edbid,
                               self.args.version,
                               self.args.kind,
                               self.args.value)
        elif hasattr(self.args, 'assess'):
            self.assess(self.args.csv)

    def refresh(self,
                security_api_url,
                exploitdb_path='',
                exploit_path=''):
        exploitdb = ExploitDatabase(exploitdb_path, exploit_path)
        exploitdb.refresh_exploits_with_cves()

        securityapi = SecurityAPI(security_api_url)
        securityapi.refresh()

        for cve in securityapi.cve_list:
            for edbid in exploitdb.exploits.keys():
                if cve in exploitdb.exploits[edbid]['cves'].keys():
                    exploitdb.exploits[edbid]['cves'][cve]['rhapi'] = True
                    exploitdb.write(edbid)

    def list_exploits(self,
                      edbid=None,
                      exploitdb_path='',
                      exploit_path=''):

        exploitdb = ExploitDatabase(exploitdb_path, exploit_path)
        affected_count = 0
        unaffected_count = 0

        for edbid in exploitdb.exploits.keys():
            if exploitdb.affects_el(edbid):
                self.console_logger.info(edbid + "," + exploitdb.exploits[edbid]['filename'])

    def score_exploit(self, edbid, version, kind, score):
        securityapi = SecurityAPI()
        cve_list = securityapi.cve_list
        for cve in cve_list:
            if cve.affected_by_exploit(edbid):
                cve.score_exploit(edbid, version, kind, score)
                cve.write()

    def assess(self, csv=False):
        assessed_cves = []
        lines = []
        securityapi = SecurityAPI()
        try:
            try:
                lines = subprocess.check_output(["yum","updateinfo","list","cves"]).split('\n')
            except AttributeError:
                p = subprocess.Popen(["yum","updateinfo","list","cves"], stdout=subprocess.PIPE)
                out, err = p.communicate()
                lines = out.split('\n')
        except OSError:
            self.logger.error("\'assess\' may only be run on an Enterprise Linux host.")
            sys.exit(1)
        pattern = re.compile('\s(.*CVE-\d{4}-\d{4,})' )
        for line in lines:
            result = re.findall(pattern, line)
            if result and result[0] not in assessed_cves:
                assessed_cves.append(result[0])

        potential_exploits = securityapi.exploits_dict()
        for cve_id in assessed_cves:
            if cve_id in potential_exploits.keys():
                if not csv:
                    logger.info(dict(potential_exploits[cve_id]))
                else:
                    logger.info(str(potential_exploits[cve_id]))
