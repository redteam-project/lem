import json

class CVEDefinitionFormatError(Exception):
    def __init__(self, definition):
        print str(definition)
        print "Cannot parse CVE definition.  Must be a dictionary or valid JSON string"

class CVE(object):
    def __init__(self, cve_id, cve_path, cve_file_name=None):
        self.id = cve_id
        self.cve_path = cve_path
        self.cve_file_name = cve_file_name
        self.exploits = {}

    def json(self):
        return json.dumps(self.exploits, indent=4, sort_keys=True)

    def add_exploit(self, edbid, filename=''):
        if edbid not in self.exploits.keys():
            print "Adding exploit %s to cve %s" % (edbid, self.id)
            self.exploits[edbid] = dict(filename=filename)

    def read(self):
        file_name = self.cve_path + '/' + self.cve_file_name
        with open(file_name, 'r') as cve_file:
            self.exploits = json.load(cve_file)

    def write(self):
        if not self.cve_file_name:
            self.cve_file_name = self.id + ".json"
        file_name = self.cve_path + '/' + self.cve_file_name
        with open(file_name, 'w') as cve_file:
            cve_file.write(self.json())

    def affected_by_exploit(self, edbid_to_find):
        if str(edbid_to_find) in self.exploits.keys():
            return True
        return False

    def exploits_dict(self, edbid_to_find=None):
        result = {}

        if edbid_to_find:
            result[self.id] = dict((edbid, exploit) for edbid, exploit in self.exploits.iteritems() if int(edbid) == int(edbid_to_find))
        else:
            result[self.id] = dict((edbid, exploit)
                            for edbid, exploit in self.exploits.iteritems())

        return result

    def score_exploit(self, edbid_to_find, version, s=None, t=None, r=None, i=None, d=None, e=None):
        if version not in self.exploits[str(edbid_to_find)].keys():
            self.exploits[str(edbid_to_find)][version] = dict(s=0,
                                                              t=0,
                                                              r=0,
                                                              i=0,
                                                              d=0,
                                                              e=0)
        if s:
            self.exploits[str(edbid_to_find)][version]['s'] = s
        if t:
            self.exploits[str(edbid_to_find)][version]['t'] = t
        if r:
            self.exploits[str(edbid_to_find)][version]['r'] = r
        if i:
            self.exploits[str(edbid_to_find)][version]['i'] = i
        if d:
            self.exploits[str(edbid_to_find)][version]['d'] = d
        if e:
            self.exploits[str(edbid_to_find)][version]['e'] = e
