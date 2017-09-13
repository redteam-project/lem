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
            self.exploits[edbid] = dict(filename=filename, scores=dict())

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

    def __iter__(self):

        result = {}
        result[self.id] = dict((edbid, exploit)
                        for edbid, exploit in self.exploits.iteritems())
        return result.iteritems()

    def score_exploit(self, edbid_to_find, version, kind, score):
        if 'scores' not in self.exploits[str(edbid_to_find)].keys():
            self.exploits[str(edbid_to_find)]['scores'] = dict()

        if version not in self.exploits[str(edbid_to_find)]['scores'].keys():
            self.exploits[str(edbid_to_find)]['scores'][version] = dict()

        if kind not in self.exploits[str(edbid_to_find)]['scores'][version].keys():
            self.exploits[str(edbid_to_find)]['scores'][version][kind] = dict()

        self.exploits[str(edbid_to_find)]['scores'][version][kind] = score

    def __str__(self):
        string = ""
        for edbid in self.exploits.keys():
            string += self.id
            string += ','
            string += edbid
            string += ','
            string += self.exploits[edbid]['filename']
            string += '\n'

        return string[:len(string)-1]
