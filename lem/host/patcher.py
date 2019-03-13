import subprocess
import logging
class Patcher(object):
    #def __init__(self, cves):
    #    self.
    @classmethod
    def patch(cls, cves=None):
        #logger = logging.getLogger('elem')
        if cves is not None:
            cves = ",".join(cves).encode('utf-8')
            command = ["yum", "update", '-y', "--cves", cves]
        else:
            command = ["yum", "update", '-y', "--security"]

        #logger.debug("Patching with command %s", command)

        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        #if err:
        #    logger.error("\n".join(err.split('\n')))
        if p.returncode != 0:
            raise OSError(p.returncode, err)

        #logger.debug("Patch Successful: %s", out)

