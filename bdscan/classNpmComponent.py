import re
import os
import shutil
import tempfile

from bdscan import classComponent
from bdscan import utils


class NpmComponent(classComponent.Component):
    def __init__(self, compid, name, version, ns):
        super().__init__(compid, name, version, ns)
        self.pm = 'npm'
        self.pms = ['npm']

    def get_http_name(self):
        bdio_name = f"http:" + re.sub(":", "/", self.compid, 1)
        return bdio_name

    @staticmethod
    def normalise_dep(dep):
        #
        # Replace / with :
        # return dep.replace('/', ':').replace('http:', '')
        dep = dep.replace('http:', '').replace(':', '|').replace('/', '|')
        # Check format matches 'npmjs:component/version'
        slash = dep.split('|')
        if len(slash) == 3:
            return f"{slash[0]}:{slash[1]}/{slash[2]}"
        return ''

    def prepare_upgrade(self, index):
        if shutil.which("npm") is None:
            print('BD-Scan-Action: ERROR: Unable to find npm executable to install packages - unable to test upgrades')
            return

        cmd = f"npm install {self.name}@{self.potentialupgrades[index]} --package-lock-only >/dev/null 2>&1"
        # cmd = f"npm install {comp}@{upgrade_version} --package-lock-only"
        # print(cmd)
        ret = os.system(cmd)

        if ret == 0:
            return True
        return False

    def do_upgrade_dependency(self):
        # Key will be actual name, value will be local filename

        files_to_patch = dict()
        # dirname = tempfile.TemporaryDirectory()
        tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + self.name + "-" + self.version)
        origdir = os.getcwd()

        for package_file in self.projfiles:
            if os.path.isabs(package_file):
                package_file = utils.remove_cwd_from_filename(package_file)

            # Change into sub-folder for packagefile
            subtempdir = os.path.dirname(package_file)
            os.chdir(tempdirname)
            if len(subtempdir) > 0:
                os.makedirs(subtempdir, exist_ok=True)
                os.chdir(subtempdir)
            shutil.copy2(os.path.join(origdir, package_file), os.path.join(tempdirname, package_file))

            # print(f'DEBUG: upgrade_npm_dependency() - working in folder {os.getcwd()}')

            cmd = f"npm install {self.name}@{self.goodupgrade} --package-lock-only >/dev/null 2>&1"
            print(f"BD-Scan-Action: INFO: Executing NPM to update component: {cmd}")
            err = os.system(cmd)
            if err > 0:
                print(f"BD-Scan-Action: ERROR: Error {err} executing NPM command")
                os.chdir(origdir)
                tempdirname.cleanup()
                return None

            os.chdir(origdir)
            # Keep files so we can commit them!
            # shutil.rmtree(dirname)

            files_to_patch["package.json"] = os.path.join(tempdirname, "package.json")
            files_to_patch["package-lock.json"] = os.path.join(tempdirname, "package-lock.json")

        return files_to_patch

    def get_projfile_linenum(self, filename):
        if not filename.endswith('package.json') and not filename.endswith('package_lock.json'):
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
        return True
