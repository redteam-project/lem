import subprocess
import re
from cpe import CPE
import platform

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
    def __init__(self, vuln_data):
        super(RpmAssessor, self).__init__()
        self.installed_packages = dict()
        self.vuln_data = vuln_data

    def _get_rpms(self):
        lines = []
        error_lines = []
        
        command = ["rpm", "-qa"]
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()

        if p.returncode != 0:
            raise OSError((p.returncode, err))

        lines = out.split('\n')

        for line in lines:
            rpm = Rpm(line)
            self.installed_packages[rpm.name()] = rpm

    def assess(self):
        self._get_rpms()
        for cve, definition in self.vuln_data.iteritems():
            for rpm in definition['affected_packages']:
                if rpm.name() in self.installed_packages.keys():
                    if self.installed_packages[rpm.name()].version_less_than(rpm):
                        self.cves.append(cve)      

        self.cves = list(set(self.cves))


class Rpm(object):
    target_hw_re = re.compile(r'(i386|i486|i586|i686|athlon|geode|pentium3|pentium4|x86_64|amd64|ia64|alpha|alphaev5|alphaev56|alphapca56|alphaev6|alphaev67|sparcsparcv8|sparcv9|sparc64|sparc64v|sun4|sun4csun4d|sun4m|sun4u|armv3l|armv4b|armv4larmv5tel|armv5tejl|armv6l|armv7l|mips|mipselppc|ppciseries|ppcpseries|ppc64|ppc8260|ppc8560|ppc32dy4|m68k|m68kmint|atarist|atariste|ataritt|falcon|atariclone|milan|hades|Sgi|rs6000|i370|s390x|s390|noarch)')
    target_sw_re = re.compile(r'(el\d)|(fc\d)')
    version_re = re.compile(r'-(\d.+)-')
    update_re = re.compile(r'-(\d+).\D')
    name_re = re.compile(r'^((\w+)(-[a-zA-Z0-9]*)*)(?=-\d)')

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

    def major(self):
        version = Rpm.version_re.findall(self.rpm)
        if version:
            return version[0].split('.')[0]
        return ""

    def minor(self):
        version = Rpm.version_re.findall(self.rpm)
        if version:
            try:
                return version[0].split('.')[1]
            except IndexError:
                pass
        return ""

    def micro(self):
        version = Rpm.version_re.findall(self.rpm)
        if version:
            try:
                return version[0].split('.')[2]
            except IndexError:
                pass
        return ""

    def update(self):
        update = Rpm.update_re.findall(self.rpm)
        if update:
            return update[0]
        return ""

    def name(self):
        match = Rpm.name_re.search(self.rpm)
        if match:
            return match.group(0)
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

    def version_less_than(self, other_rpm):
        if not isinstance(other_rpm, Rpm):
            return False
        if self.name() == other_rpm.name():
        # and \
        #     self.target_hw() == other_rpm.target_hw() and \
        #     self.target_sw() == other_rpm.target_sw():
            if self.major() < other_rpm.major():
                return True
            elif self.major() == other_rpm.major() and self.minor() < other_rpm.minor():
                return True
            elif self.major() == other_rpm.major() and self.minor() == other_rpm.minor() and self.micro() < other_rpm.micro():
                return True
            elif self.major() == other_rpm.major() and self.minor() == other_rpm.minor() and self.micro() == other_rpm.micro() and self.update() < other_rpm.update():
                return True
        return False

    def version_greater_than(self, other_rpm):
        if not isinstance(other_rpm, Rpm):
            return False
        if self.name() == other_rpm.name() and \
            self.target_hw() == other_rpm.target_hw() and \
            self.target_sw() == other_rpm.target_sw():
            if self.major() > other_rpm.major():
                return True
            elif self.major() == other_rpm.major() and self.minor() > other_rpm.minor():
                return True
            elif self.major() == other_rpm.major() and self.minor() == other_rpm.minor() and self.micro() > other_rpm.micro():
                return True
            elif self.major() == other_rpm.major() and self.minor() == other_rpm.minor() and self.micro() == other_rpm.micro() and self.update() > other_rpm.update():
                return True
        return False

    # def __eq__(self, other_rpm):
    #     pass
    
    # def __ne__(self, other_rpm):
    #     pass

    # def __lt__(self, other_rpm):
    #     pass

    # def __gt__(self, other_rpm):
    #     pass

    # def __le__(self, other_rpm):
    #     pass
    
    # def __ge__(self, other_rpm):
    #     pass



