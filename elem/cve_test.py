from ConfigParser import SafeConfigParser
from vulnerability import VulnerabilityManager

if __name__ == "__main__":

    vm = VulnerabilityManager()
    parser = SafeConfigParser()
    parser.read('config/elem.conf')
    for section in parser.sections():
        if section.startswith("nvd:"):
            section_name = section.split(':')[1]
            vm.add_reader(name=section_name, file_location=parser.get(section, 'file'))
    cve_list, _ = vm.list_cves()

    for cveid, vendors in cve_list.iteritems():
        print cveid + "," + ",".join(vendors)