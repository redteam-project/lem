import json
import logging
from git import Repo
from git.repo import fun
from git_manager import GitManager
import os
import subprocess

class ExploitManager(GitManager):
    def __init__(self, exploit_path,
                       exploits_repo,
                       subfolder='/exploits'):

        super(ExploitManager, self).__init__(exploit_path,
                                             exploits_repo,
                                             'elem-curation')

        self.exploits = dict()
        self.exploit_path = self.content_path
        if subfolder is not '':
            self.exploit_path += os.path.sep
            self.exploit_path += subfolder


    def load_exploit_info(self):
        self.exploit_file_names = [f for f in os.listdir(self.exploit_path)
                                   if os.path.isfile(os.path.join(self.exploit_path, f)) and
                                   os.path.join(os.path.join(self.exploit_path, f)).endswith(".json")]

        for exploit_file_name in self.exploit_file_names:
            self.read(os.path.join(self.exploit_path, exploit_file_name))

    def write(self, edbid):
        file_name = self.exploit_path + \
                    os.path.sep + \
                    edbid + '.json'
        with open(file_name, 'w') as exploit_file:
            json.dump(self.exploits[edbid], exploit_file)

    def read(self, file_name):
        with open(file_name, 'r') as exploit_file:
            root = os.path.splitext(file_name)[0]
            edbid = root.replace(self.exploit_path + '/', "")
            self.exploits[edbid] = json.load(exploit_file)

    def affects_el(self, edbid):
        try:
            for cveid in self.exploits[edbid]['cves'].keys():
                if 'windows' in self.exploits[edbid]['filename']:
                    return False
                if self.exploits[edbid]['cves'][cveid]['rhapi']:
                    return True
        except KeyError:
            pass
        return False

    def exploits_by_cve(self, cveid):
        edbids = []

        for edbid in self.exploits.keys():
            if cveid in self.exploits[edbid]['cves'] and \
                    'windows' not in self.exploits[edbid]['filename']:
                edbids.append(edbid)

        return edbids

    def add_cpe(self, edbid, cpe):
        if 'cpes' not in self.exploits[edbid].keys():
            self.exploits[edbid]['cpes'] = dict()

        if cpe not in self.exploits[edbid]['cpes'].keys():
            self.exploits[edbid]['cpes'][cpe] = dict()

    def score(self, edbid, cpe, score_kind, score):
        self.add_cpe(edbid, cpe)

        if 'scores' not in self.exploits[edbid]['cpes'][cpe].keys():
            self.exploits[edbid]['cpes'][cpe]['scores'] = dict()

        if score_kind not in \
                self.exploits[edbid]['cpes'][cpe]['scores'].keys():
            self.exploits[edbid]['cpes'][cpe]['scores'][score_kind] = dict()

        self.exploits[edbid]['cpes'][cpe]['scores'][score_kind] = score

    def set_stage_info(self, edbid, cpe, stage_info, kind=''):
        self.add_cpe(edbid, cpe)

        self.exploits[edbid]['cpes'][cpe]['staging'] = stage_info

    def add_packages(self, edbid, cpe, packages):
        self.add_cpe(edbid, cpe)

        if 'packages' not in self.exploits[edbid]['cpes'][cpe].keys():
            self.exploits[edbid]['cpes'][cpe]['packages'] = []

        if isinstance(packages, str):
            self.exploits[edbid]['cpes'][cpe]['packages'].append(packages)
        elif isinstance(packages, list):
            self.exploits[edbid]['cpes'][cpe]['packages'] = self.exploits[edbid]['cpes'][cpe]['packages'] + packages

        self.exploits[edbid]['cpes'][cpe]['packages'] = \
            list(set(self.exploits[edbid]['cpes'][cpe]['packages']))

    def add_services(self, edbid, cpe, services):
        self.add_cpe(edbid, cpe)

        if 'services' not in self.exploits[edbid]['cpes'][cpe].keys():
            self.exploits[edbid]['cpes'][cpe]['services'] = []

        if isinstance(services, str):
            self.exploits[edbid]['cpes'][cpe]['services'].append(services)
        elif isinstance(services, list):
            self.exploits[edbid]['cpes'][cpe]['services'] = self.exploits[edbid]['cpes'][cpe]['services'] + services

        self.exploits[edbid]['cpes'][cpe]['services'] = \
            list(set(self.exploits[edbid]['cpes'][cpe]['services']))

    def set_selinux(self, edbid, cpe, selinux):
        self.add_cpe(edbid, cpe)

        if 'services' not in self.exploits[edbid]['cpes'][cpe].keys():
            self.exploits[edbid]['cpes'][cpe]['selinux'] = selinux


    def stage(self, edbid, destination):
        if 'staging' not in self.exploits[edbid]:
            return False, "No staging information available."

        try:
            command = self.exploits[edbid]['staging'].split(' ')
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 cwd=destination)
            out, err = p.communicate()
            lines = out.split('\n')
            error_lines = err.split('\n')
        except OSError:
            self.logger.error("Command %s cannot be run on this host." %
                              self.exploits[edbid]['staging'])
            sys.exit(1)
        if p.returncode != 0:
            return False, ','.join(error_lines)
        return True, lines

    def get_exploit_strings(self, edbid):
        strings = []
        if 'cpes' not in self.exploits[edbid].keys():
            for cve in self.exploits[edbid]['cves']:
                string = edbid
                string += ","
                string += cve
                strings.append(string)
        else:
            for cpe in self.exploits[edbid]['cpes'].keys():
                for kind in self.exploits[edbid]['cpes'][cpe]['scores'].keys():
                    for cve in self.exploits[edbid]['cves']:
                        string = edbid
                        string += ","
                        string += cve
                        string += ","
                        string += cpe
                        string += ","
                        string += kind
                        string += ','
                        string += self.exploits[edbid]['cpes'][cpe]['scores'][kind]
                        strings.append(string)

        return strings
