# import re
# import os
# import shutil
# import sys
# import tempfile

from bdscan import classComponent
# from bdscan import utils


class ConanComponent(classComponent.Component):
    def __init__(self, compid, name, version, ns):
        super().__init__(compid, name, version, ns)
        self.pm = 'conan'
        self.pms = ['conan']
        self.version = self.version.replace("@_", "")   # Clean up the version, as it is initially parsed outside
                                                        # of this class

    def parse_compid(self, compid):
        comp_ns = compid.split(':')[0]
        comp_name_and_version = compid.split(':')[1]  # libiconv/1.16@_/_#05310dd310959552336b136c594ac562
        comp_name = comp_name_and_version.split('/')[0]  # libiconv
        comp_version_and_hash = comp_name_and_version.split('/', 1)[1]  # 1.16@_/_#05310dd310959552336b136c594ac562
        comp_version = comp_version_and_hash.split('@')[0]  # 1.16
        # comp_extra = comp_name_and_version.split('@')[1]  # _/_#05310dd310959552336b136c594ac562

        return comp_ns, comp_name, comp_version

    def parse_component_id(self):
        comp_ns = self.compid.split(':')[0]
        comp_name_and_version = self.compid.split(':')[1]  # libiconv/1.16@_/_#05310dd310959552336b136c594ac562
        comp_name = comp_name_and_version.split('/')[0]  # libiconv
        comp_version_and_hash = comp_name_and_version.split('/', 1)[1]  # 1.16@_/_#05310dd310959552336b136c594ac562
        comp_version = comp_version_and_hash.split('@')[0]  # 1.16
        comp_extra = comp_name_and_version.split('@')[1]  # _/_#05310dd310959552336b136c594ac562

        return comp_ns, comp_name, comp_version, comp_extra

    def get_http_name(self):
        comp_ns, comp_name, comp_version, comp_extra = self.parse_component_id()
        # http:conan/folly/2020.08.10.00@_/_#b1cadac6d4ce906933dc25583108f437
        # http:conan/folly/2020.08.10.00%40_%2F_%23b1cadac6d4ce906933dc25583108f437
        bdio_name = f"http:{comp_ns}/{comp_name}/{comp_version}%40{comp_extra.replace('/', '%2F').replace('#', '%23')}"

        return bdio_name

    @staticmethod
    def normalise_dep(dep):
        if dep.find('http:') == 0:
            dep = dep.replace('http:', '')
        return dep.replace('/', ':', 1).replace('%40', '@').replace('%2F', '/').replace('%23', '#')

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
