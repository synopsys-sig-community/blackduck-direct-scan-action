import re
import os
import semver
from operator import itemgetter

from bdscan import utils, globals


class Component:
    md_comp_vulns_hdr = \
        "\n| Direct Dependency | Affected Component | Vulnerability | Score |  Policy Violated | Description |\n" \
        "| --- | --- | --- | --- | --- | --- |\n"

    def __init__(self, compid, name, version, ns):
        self.ns = ns
        self.pm = ns
        self.pms = [ns]
        self.org = ''  # Used in Maven
        self.name = name
        self.version = version
        self.compid = compid
        self.inbaseline = False
        self.projfiles = []
        self.projfilelines = []
        self.compdata = []
        self.versions = []
        self.upgradeguidance = []
        self.potentialupgrades = []
        self.goodupgrade = ''
        self.origins = {}
        self.children = []
        self.vulns = {}
        self.childvulns = {}
        self.maxvulnscore = 0
        self.maxchildvulnscore = 0
        self.vulnsummary = []
        self.goodfutureversions = []
        self.lic_violations = {}
        self.child_lic_violations = {}

    def set_data(self, fieldname, data):
        if fieldname == 'compdata':
            self.compdata = data
        elif fieldname == 'versions':
            self.versions = data
        elif fieldname == 'upgradeguidance':
            self.upgradeguidance = data
        elif fieldname == 'goodupgrade':
            self.goodupgrade = data
        elif fieldname == 'inbaseline':
            self.inbaseline = True
        elif fieldname == 'projfiles':
            if data in self.projfiles:
                return False
            self.projfiles.append(data)
        elif fieldname == 'projfilelines':
            self.projfilelines.append(data)
        elif fieldname == 'children':
            self.children = data
        elif fieldname == 'maxvulnscore':
            self.maxvulnscore = data
        elif fieldname == 'maxchildvulnscore':
            self.maxchildvulnscore = data
        elif fieldname == 'vulnsummary':
            self.vulnsummary.append(data)
        elif fieldname == 'goodfutureversions':
            self.goodfutureversions.append(data)
        return True

    def add_vuln(self, vulnid, data):
        self.vulns[vulnid] = data

    def add_child_vuln(self, vulnid, data):
        self.childvulns[vulnid] = data

    def add_lic_violation(self, licid, data):
        self.lic_violations[licid] = data

    def add_child_lic_violation(self, licid, data):
        self.child_lic_violations[licid] = data

    def set_origins(self, ver, data):
        self.origins[ver] = data

    def get_num_vulns(self):
        return len(self.vulns.keys()) + len(self.childvulns.keys())

    def check_ver_origin(self, ver):
        if len(self.origins) > 0 and ver in self.origins.keys():
            for over in self.origins[ver]:
                if 'originName' in over and 'originId' in over and over['originName'] == self.ns:
                    # 'org.springframework:spring-aop:3.2.10.RELEASE'
                    a_over = re.split('[:/]', over['originId'])
                    if a_over[0] == self.name and a_over[1] == self.version:
                        return True
        return False

    def find_upgrade_versions(self, upgrade_major):
        v_curr = self.get_version_semver(self.version)
        if v_curr is None:
            return

        future_vers = []
        for ver, url in self.goodfutureversions[::]:
            v_ver = self.check_version_is_release(ver)
            if v_ver is None:
                continue

            if self.check_ver_origin(ver):
                future_vers.append([ver, url])

        #
        # Find the initial upgrade (either latest in current version major range or guidance_short)
        if len(self.upgradeguidance) > 0:
            v_guidance_short = self.check_version_is_release(self.upgradeguidance[0])
            v_guidance_long = self.check_version_is_release(self.upgradeguidance[1])
        else:
            v_guidance_short = None
            v_guidance_long = None

        foundvers = []
        if v_guidance_short is None:
            # Find final version in current major range
            verstring, guidance_major_last = Component.find_next_ver(
                self, future_vers, v_curr.major, v_curr.minor, v_curr.patch)
        else:
            if len(self.upgradeguidance) > 0:
                verstring = self.upgradeguidance[0]
            else:
                verstring = None
            guidance_major_last = v_guidance_short.major + 1
        if verstring != '':
            foundvers.append(verstring)

        if v_guidance_long is None:
            # Find final minor version in next major range
            verstring, guidance_major_last = Component.find_next_ver(
                self, future_vers, guidance_major_last, -1, -1)
        else:
            verstring = self.upgradeguidance[1]
            guidance_major_last = v_guidance_long.major
        if verstring != '' and upgrade_major and verstring not in foundvers:
            foundvers.append(verstring)

        if upgrade_major:
            while len(foundvers) <= 4:
                verstring, guidance_major_last = Component.find_next_ver(
                    self, future_vers, guidance_major_last + 1, -1, -1)
                if verstring == '':
                    break
                foundvers.append(verstring)

        self.potentialupgrades = foundvers

    def prepare_upgrade(self, index):
        return

    def md_table(self):
        # md_comp_vulns_table = self.md_comp_vulns_hdr[:]
        md_comp_vulns_table = []
        for vulnid in self.vulns.keys():
            md_comp_vulns_table.append(self.vulns[vulnid])
        for vulnid in self.childvulns.keys():
            # sep = " | "
            md_comp_vulns_table.append(self.childvulns[vulnid])

        # sort the table here
        md_comp_vulns_table = sorted(md_comp_vulns_table, key=itemgetter(3), reverse=True)

        sep = ' | '
        md_table_string = ''
        for row in md_comp_vulns_table:
            md_table_string += '| ' + sep.join(row) + ' |\n'

        md_table_string = self.md_comp_vulns_hdr + md_table_string
        return md_table_string

    def md_lic_table(self):
        md_comp_lic_table = []
        for licid in self.lic_violations.keys():
            md_comp_lic_table.append(self.lic_violations[licid])
        for licid in self.child_lic_violations.keys():
            md_comp_lic_table.append(self.child_lic_violations[licid])

        # sort the table here
        # TODO
        # md_comp_lic_table = sorted(md_comp_lic_table, key=itemgetter(3), reverse=True)

        sep = ' | '
        md_table_string = ''
        for row in md_comp_lic_table:
            md_table_string += '| ' + sep.join(row) + ' |\n'

        # Do not prepend header, unlike vulnerabilities this will all be summarized
        return md_table_string

    def shorttext(self):
        if len(self.vulns) > 0 and len(self.childvulns) > 0:
            shorttext = f"The direct dependency '{self.name}/{self.version}' has {len(self.vulns)} vulnerabilities " \
                        f"(max score {self.maxvulnscore}) and {len(self.childvulns)} vulnerabilities in child " \
                        f"dependencies (max score {self.maxchildvulnscore}) reported by security policy violations."
        elif len(self.vulns) > 0 and len(self.childvulns) == 0:
            shorttext = f"The direct dependency {self.name}/{self.version} has {len(self.vulns)} vulnerabilities " \
                        f"(max score {self.maxvulnscore})  reported by security policy violations."
        elif len(self.childvulns) > 0:
            shorttext = f"The direct dependency {self.name}/{self.version} has {len(self.childvulns.keys())} " \
                        f"vulnerabilities in child dependencies (max score {self.maxchildvulnscore})  reported " \
                        f"by security policy violations."
        else:
            shorttext = ''
        if shorttext != '' and self.goodupgrade != '':
            shorttext += f" Upgrade to version '{self.goodupgrade}' to address the reported security policy violations."

        return shorttext

    def longtext(self):
        shorttext = self.shorttext()
        # md_comp_vulns_table = self.md_table()
        if len(self.vulns) > 0 and len(self.childvulns) > 0:
            longtext = f"{shorttext}\n\nList of direct vulnerabilities:\n{','.join(self.vulns.keys())}\n\n" \
                       f"List of indirect vulnerabilities:\n{','.join(self.childvulns.keys())} "
        elif len(self.vulns) > 0 and len(self.childvulns) == 0:
            longtext = f"{shorttext}\n\nList of direct vulnerabilities:\n{','.join(self.vulns.keys())}"
        elif len(self.childvulns) > 0:
            longtext = f"{shorttext}\n\nList of indirect vulnerabilities:\n{','.join(self.childvulns.keys())}"
        else:
            longtext = ''
        return longtext

    def longtext_md(self):
        shorttext = self.shorttext()
        md_table = self.md_table()
        longtext_md = shorttext + "\n\n" + md_table
        return longtext_md

    def get_projfile(self, projstring, allpoms):
        import urllib.parse
        arr = projstring.split('/')
        if len(arr) < 4:
            return ''

        projfile = urllib.parse.unquote(arr[3])
        if os.path.isfile(projfile):
            print(f'BD-Scan-Action: INFO: Found project file {projfile}')
            return utils.remove_cwd_from_filename(projfile)

    def get_projfile_linenum(self, filename):
        try:
            with open(filename, 'r') as f:
                for (i, line) in enumerate(f):
                    if self.name.lower() in line.lower():
                        return i
        except Exception as e:
            return -1
        return -1

    # def get_package_file(self):
    #     for package_file in self.projfiles:
    #         line = self.get_projfile_linenum(package_file)
    #         if line > 0:
    #             globals.printdebug(f"DEBUG: '{self.name}': PKG file'{package_file}' Line {line}")
    #             return utils.remove_cwd_from_filename(package_file), line
    #     return "Unknown", 0

    def md_summary_table_row(self):
        # | Direct Dependency | Total Vulns | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns
        # | Max Indirect Vuln Severity | Upgrade to |",
        # if self.inbaseline:
        #     changed = 'No'
        # else:
        #     changed = 'Yes'
        upg = self.goodupgrade
        if self.goodupgrade == '':
            if globals.args.upgrade_major:
                upg = 'No Upgrade Available'
            else:
                upg = 'No Minor Upgrade Available'

        table = [
            f"{self.name}/{self.version}",
            f"{len(self.vulns.keys()) + len(self.childvulns.keys())}",
            f"{len(self.vulns.keys())}",
            f"{self.maxvulnscore}",
            f"{len(self.childvulns.keys())}",
            f"{self.maxchildvulnscore}",
            f"{upg}",
            # changed,
        ]
        return table

    def do_upgrade_dependency(self):
        print(f'BD-Scan-Action: WARNING: Unable to upgrade component {self.name}/{self.version} - unsupported package '
              f'manager')
        return

    @staticmethod
    def finalise_upgrade():
        return

    @staticmethod
    def parse_compid(compid):
        arr = re.split('[:/]', compid)
        if len(arr) == 3:
            return arr[0], arr[1], arr[2]
        else:
            return '', '', ''

    @staticmethod
    def get_version_semver(ver):
        # extract numeric semver
        #
        # 1. remove leading text
        # 2. remove trailing segment with text
        if ver == '':
            return None

        tempver = re.sub('[A-Za-z_-]+\d*$', '', ver.lower())
        tempver = re.sub('^\D+', '', tempver)
        tempver = re.sub('[_-]+', '.', tempver)

        arr = tempver.split('.')
        if len(arr) == 3:
            newver = tempver
        elif len(arr) > 3:
            newver = '.'.join(arr[0:3])
        elif len(arr) == 2:
            newver = '.'.join(arr[0:2]) + '.0'
        elif len(arr) == 1:
            if arr[0].isnumeric():
                if int(arr[0]) > 999:
                    return None
            newver = f'{arr[0]}.0.0'
        else:
            return None

        try:
            retsemver = semver.VersionInfo.parse(newver)
        except Exception as e:
            return None

        return retsemver

    @staticmethod
    def check_version_is_release(ver):
        #
        # 0. Check for trailing string for pre-releases
        # 1. Replace separator chars
        # 2. Check number of segments
        # 3. Normalise to 3 segments
        tempsemver = Component.get_version_semver(ver)

        match = re.search('alpha|beta|milestone|rc|cr|dev|nightly|snap|pre|talend|redhat|sonatype|osgi|brew|[_-]m\d$',
                          ver.lower())
        if match is not None:
            return None

        return tempsemver

    def is_goodfutureversion(self, futurever):
        curr_semver = self.get_version_semver(self.version)
        future_semver = self.check_version_is_release(futurever)
        shortguidance_semver = self.get_version_semver(self.upgradeguidance[0])
        # longguidance_semver = self.check_version_is_release(self.longguidance[0])

        if future_semver is None or curr_semver is None:
            return False
        if future_semver.major < curr_semver.major:
            return False
        elif future_semver.major == curr_semver.major:
            if future_semver.minor < curr_semver.minor:
                return False
            elif future_semver.minor == curr_semver.minor and future_semver.patch <= curr_semver.patch:
                return False
        if shortguidance_semver is not None:
            if future_semver.major < shortguidance_semver.major:
                return False
            elif future_semver.major == shortguidance_semver.major:
                if future_semver.minor < shortguidance_semver.minor:
                    return False
                elif future_semver.minor == shortguidance_semver.minor and \
                        future_semver.patch < shortguidance_semver.patch:
                    return False

        return True

    @staticmethod
    def find_next_ver(comp, verslist, major, minor, patch):
        foundver = ''
        found_rels = [1000, -1, -1]

        for ver, url in verslist:
            v_ver = comp.check_version_is_release(ver)
            if v_ver is None:
                continue
            if major < v_ver.major < found_rels[0]:
                found_rels = [v_ver.major, v_ver.minor, v_ver.patch]
                foundver = ver
            elif v_ver.major == major:
                if v_ver.minor > found_rels[1] and v_ver.minor > minor:
                    found_rels = [major, v_ver.minor, v_ver.patch]
                    foundver = ver
                elif v_ver.minor == found_rels[1] and v_ver.patch > found_rels[2] and v_ver.patch > patch:
                    found_rels = [major, v_ver.minor, v_ver.patch]
                    foundver = ver

        return foundver, found_rels[0]
