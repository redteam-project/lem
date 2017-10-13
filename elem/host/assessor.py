import subprocess
import re

class Assessor(object):
    def __init__(self):
        self.cves = []
    def assess(self):
        pass

class YumAssessor(Assessor):
    def __init__(self):
        super(YumAssessor, self).__init__()

    def assess(self):
        lines = []
        error_lines = []
        
        command = ["yum", "updateinfo", "list", "cves"]
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()

        if p.returncode != 0:
            raise OSError((p.returncode, err))

        lines = out.split('\n')

        pattern = re.compile(r'\s(.*CVE-\d{4}-\d{4,})')
        for line in lines:
            result = re.findall(pattern, line)
            if result and result[0] not in self.cves:
                self.cves.append(result[0])

        self.cves = list(set(self.cves))

class RpmAssessor(Assessor):
    def __init__(self):
        super(RpmAssessor, self).__init__()