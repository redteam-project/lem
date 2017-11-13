import os
import log
import sys
from vulnerability import VulnerabilityManager
from host import YumAssessor
from host import RpmAssessor
from host import Patcher
from score import ScoreManager
from exploit import CurationManager

from . import ElemConfiguration

class Elem(object):
    def __init__(self, args):
        self.args = args
        self.elem_conf = ElemConfiguration()
        self.config = self.elem_conf.read_config()

        self.logger = log.setup_custom_logger('elem')
        self.console_logger = log.setup_console_logger('console')
        self.vuln_manager = None
        self.score_manager = None

    def configure_vulnerability_sources(self):
        self.vuln_manager = VulnerabilityManager()

        for section in self.config.sections():
            section_pieces = section.split(":")
            if section_pieces[0].startswith('securityapi'):
                self.vuln_manager.add_api_source(section_pieces[1],
                                                 self.config.get(section, 'location'),
                                                 not self.args.notlsverify,
                                                 os.path.join(self.elem_conf.path, self.config.get(section, 'cache_path')))

            elif section_pieces[0].startswith('nvd'):
                self.vuln_manager.add_nvd_source(section_pieces[1],
                                                 self.config.get(section, 'location'),
                                                 not self.args.notlsverify,
                                                 os.path.joing(self.elem_conf.path, self.config.get(section, 'cache_path')))

    def configure_score_managers(self):
        self.score_manager = ScoreManager()
        for section in self.config.sections():
            section_pieces = section.split(":")
            if section_pieces[0].startswith('score'):
                self.score_manager.add_score(section_pieces[1],
                                             self.config.get(section, 'pattern'),
                                             self.config.get(section, 'example') or None)

    def run(self):
        if self.args.which == 'cve':
            self.process_cve()
        elif self.args.which == 'host':
            self.process_host()
        elif self.args.which == 'score':
            self.process_score()
        elif self.args.which == 'exploit':
            self.process_exploit()

    def process_cve(self):
        self.configure_vulnerability_sources()
        for name, source in self.vuln_manager.readers.iteritems():
            if self.args.names and name in self.args.names:
                pass

    def process_host(self):
        try:
            if self.args.sub_which == 'assess':
                self.process_assess()
            if self.args.sub_which == 'patch':
                self.process_patch()
        except OSError as oserror:
            if oserror.errno == 2:
                self.console_logger.error("\nUnable to execute %s.  The patch or assess subcommands may only "
                                          "be run on an enterprise Linux host.", self.args.sub_which)
            elif oserror.errno == 1:
                self.console_logger.error("\nUnable to execute %s.  Please ensure you have the permissions to do so.", self.args.sub_which)
            else:
                raise OSError(oserror.args)

    def process_assess(self):
        curation_manager = CurationManager(self.args.curation)
        if self.args.type == 'yum':
            assessor = YumAssessor()
        elif self.args.type == 'rpm':
            assessor = RpmAssessor()
            assessor.assess()
        self.console_logger.info(curation_manager.csv(cves=assessor.cves,
                                                    source=self.args.source,
                                                    score_kind=self.args.kind,
                                                    score_regex=self.args.score,
                                                    eid=self.args.id))
    def process_patch(self):
        if self.args.sub_sub_which == 'exploits':
            curation_manager = CurationManager(self.args.curation)
            cves = curation_manager.cves_from_exploits(self.args.source, self.args.ids)
            Patcher.patch(cves)
        elif self.args.sub_sub_which == 'all':
            Patcher.patch()


    def process_score(self):
        self.configure_score_managers()
        if 'list' in self.args.sub_which:
            self.console_logger.info(str(self.score_manager))

    def process_exploit(self):
        curation_manager = CurationManager(self.args.curation)
        if 'reconcile' in self.args.sub_which:
            curation_manager.add_source(self.args.source_name, self.args.source)
            curation_manager.update_exploits(source_name=self.args.source_name,
                                             all_exploits=self.args.all)

        elif 'list' in self.args.sub_which:
            self.console_logger.info(curation_manager.csv(source=self.args.source,
                                                          cves=self.args.cves,
                                                          cpes=self.args.cpes,
                                                          score_kind=self.args.kind,
                                                          eid=self.args.id,
                                                          score_regex=self.args.score))

        elif 'score' in self.args.sub_which:
            self.configure_score_managers()
            if not self.args.kind in self.score_manager.scores.keys():
                self.console_logger.error("Score kind {0} is not valid.  Please check {1}".format(self.args.kind, self.elem_conf.path))
                sys.exit(1)
            if not self.score_manager.is_valid(self.args.kind, self.args.value):
                self.console_logger.error("Score value {0} is not valid.  Please check {1}".format(self.args.value, self.elem_conf.path))
                sys.exit(1)

            curation_manager.score(eid=self.args.id, 
                                   source=self.args.source, 
                                   cpe=self.args.cpe, 
                                   kind=self.args.kind, 
                                   value=self.args.value)

        elif 'configure' in self.args.sub_which:
            if not self.args.command and not self.args.packages and not self.args.services and not self.args.selinux:
                self.console_logger.error("At least one of the following must"
                                        "be specified for staging: command, "
                                        "packages, services, selinux")
                sys.exit(1)

            curation_manager.set_stage(eid=self.args.id, 
                                       source=self.args.source, 
                                       cpe=self.args.cpe,
                                       command=self.args.command,
                                       selinux=self.args.selinux,
                                       packages=self.args.packages,
                                       services=self.args.services,
                                       filename=self.args.filename)

        elif 'copy' in self.args.sub_which:
            curation_manager.copy(eid=self.args.id, 
                                  source=self.args.source, 
                                  cpe=self.args.cpe,
                                  destination=self.args.destination,
                                  stage=self.args.stage)
