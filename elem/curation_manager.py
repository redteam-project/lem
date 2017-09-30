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

    def score(self, edbid, version, score_kind, score):
        if 'scores' not in self.exploits[edbid].keys():
            self.exploits[edbid]['scores'] = dict()

        if version not in self.exploits[edbid]['scores'].keys():
            self.exploits[edbid]['scores'][version] = dict()

        if score_kind not in \
                self.exploits[edbid]['scores'][version].keys():
            self.exploits[edbid]['scores'][version][score_kind] = dict()

        self.exploits[edbid]['scores'][version][score_kind] = score

    def set_stage_info(self, edbid, stage_info):
        self.exploits[edbid]['staging'] = stage_info

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
        if 'scores' not in self.exploits[edbid].keys():
            for cve in self.exploits[edbid]['cves']:
                string = edbid
                string += ","
                string += self.exploits[edbid]['filename']
                string += ","
                if 'staging' in self.exploits[edbid].keys():
                    string += self.exploits[edbid]['staging']
                    string += ","
                string += cve
                strings.append(string)
        else:
            for ver in self.exploits[edbid]['scores'].keys():
                for kind in self.exploits[edbid]['scores'][ver].keys():
                    for cve in self.exploits[edbid]['cves']:
                        string = edbid
                        string += ","
                        string += self.exploits[edbid]['filename']
                        string += ","
                        if 'staging' in self.exploits[edbid].keys():
                            string += self.exploits[edbid]['staging']
                            string += ","
                        string += cve
                        string += ","
                        string += ver
                        string += ","
                        string += kind
                        string += ','
                        string += self.exploits[edbid]['scores'][ver][kind]
                        strings.append(string)

        return strings
