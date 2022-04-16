import re
# import os
# import shutil
# import sys
# import tempfile

from bdscan import classComponent
# from bdscan import utils


class GoLangComponent(classComponent.Component):
    def __init__(self, compid, name, version, ns):
        super().__init__(compid, name, version, ns)
        self.pm = 'golang'
        self.pms = ['golang']
        self.name = self.name.replace('%2F', '/')
        self.compid = self.compid.replace('%2F', '/')

    def get_http_name(self):
        bdio_name = "http:" + re.sub(":", "/", self.compid.replace('/', '%2F'))  # , 1

        return bdio_name

    @staticmethod
    def normalise_dep(dep):
        print(f"dep={dep}")
        #
        # Replace / with :
        # return dep.replace('/', ':').replace('http:', '')
        dep = dep.replace('http:', '').replace(':', '|').replace('/', '|')
        # Check format matches 'npmjs:component/version'
        slash = dep.split('|')
        if len(slash) == 3:
            return f"{slash[0]}:{slash[1]}:{slash[2]}"
        return ''

    def prepare_upgrade(self, index):
        print(f"BD-Scan-Action: WARNING: Package manager {self.pm} does not support upgrades")
        return False

    def do_upgrade_dependency(self):
        print(f"BD-Scan-Action: WARNING: Package manager {self.pm} does not support direct dependency upgrades "
              f"for indirect vulnerabilities")
        return None

    def get_projfile_linenum(self, filename):
        if not filename.endswith('requirements.txt') and not filename.endswith('Pipfile') and \
                not filename.endswith('Pipfile.lock'):
            return -1
        namestring = f'"{self.name.lower()}":'
        try:
            with open(filename, 'r') as f:
                for (i, line) in enumerate(f):
                    if namestring in line.lower():
                        return i
        except Exception as e:
            return -1
        return -1

    @staticmethod
    def supports_direct_upgrades():
        return False
