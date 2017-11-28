import subprocess
import re
from cpe import CPE

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
        
class Rpm(object):
    target_hw_re = re.compile(r'(i386|i486|i586|i686|athlon|geode|pentium3|pentium4|x86_64|amd64|ia64|alpha|alphaev5|alphaev56|alphapca56|alphaev6|alphaev67|sparcsparcv8|sparcv9|sparc64|sparc64v|sun4|sun4csun4d|sun4m|sun4u|armv3l|armv4b|armv4larmv5tel|armv5tejl|armv6l|armv7l|mips|mipselppc|ppciseries|ppcpseries|ppc64|ppc8260|ppc8560|ppc32dy4|m68k|m68kmint|atarist|atariste|ataritt|falcon|atariclone|milan|hades|Sgi|rs6000|i370|s390x|s390|noarch)')
    target_sw_re = re.compile(r'(el\d)')
    version_re = re.compile(r'-(\d.+)-')
    update_re = re.compile(r'-(\d+).\D')
    # TODO: This needs fixing
    name_re = re.compile(r'^([0-9a-zA-Z-]+)(?=-\d)')

    def __init__(self, rpm):
        self.rpm = rpm

    def target_hw(self):
        hardware = Rpm.target_hw_re.findall(self.rpm)
        if hardware:
            return hardware[0]
        return ""

    def target_sw(self):
        software = Rpm.target_sw_re.findall(self.rpm)
        if software:
            return software[0]
        return ""

    def version(self):
        version = Rpm.version_re.findall(self.rpm)
        if version:
            return version[0]
        return ""

    def update(self):
        update = Rpm.update_re.findall(self.rpm)
        if update:
            return update[0]
        return ""

    def name(self):
        name = Rpm.name_re.findall(self.rpm)
        if name:
            return name[0]
        return ""

    def cpe(self):
        cpe_string = ['cpe']
        cpe_string.append('2.3')
        cpe_string.append('a')
        cpe_string.append('*')
        cpe_string.append(self.name())
        cpe_string.append(self.version())
        cpe_fs = ":".join(cpe_string) + ":*:*:*:*:*:*:*"
        return CPE(cpe_fs, CPE.VERSION_2_3)




