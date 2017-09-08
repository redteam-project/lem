import os
import json

class Curator(object):
    def __init__(self,
                 curator_file_name=os.path.dirname(os.path.realpath(__file__))+"/curator.json"):
        self.curator_file_name = curator_file_name
        self.curated_exploits = {}
        try:
            with open(self.curator_file_name, 'r') as curator_file:
                self.curated_exploits = json.load(curator_file)
        except IOError:
            pass

    def add_exploit(self, cve_id, exploit_entries):
        if cve_id not in self.curated_exploits.keys():
            self.curated_exploits[cve_id] = {}

        for edb_id in exploit_entries.keys():
            if edb_id not in self.curated_exploits[cve_id].keys():
                self.curated_exploits[cve_id][edb_id] = \
                    dict(filename=exploit_entries[edb_id]['filename'],
                         confidence=dict(unknown=['']),
                         notes='empty')

    def write(self):
        with open(self.curator_file_name, 'w') as curator_file:
            self.curated_exploits = json.dump(self.curated_exploits,
                                              curator_file)

    def cves_by_exploit_id(self, edbid_to_find):
        pruned_list = dict((cveid, dict((edbid, exploit) for edbid, exploit in exploit_entries.iteritems() if edbid_to_find == int(edbid))) for cveid, exploit_entries in self.curated_exploits.iteritems())

        final_list = dict((cveid, exploits) for cveid, exploits in pruned_list.iteritems() if len(exploits) > 0)

        return final_list
