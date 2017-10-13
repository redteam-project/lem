import subprocess

class Patcher(object):
    def __init__(self, cves):
        self.cves = ",".join(cves).encode('utf-8')
    
    def patch(self):
        lines = []
        error_lines = []
        print self.cves
        command = ["yum", "update", '-y', "--cves", self.cves]
        print command
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        


        if p.returncode != 0:
            print err
            raise OSError((p.returncode, err))

        lines = out.split('\n')
        print lines
