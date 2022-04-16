import re
import os
# import shutil
import tempfile
import hashlib
# import sys
import json
from operator import itemgetter

from bdscan import classComponent, classNugetComponent, classNpmComponent, classMavenComponent, classPyPiComponent, \
    classConanComponent, classCargoComponent, classHexComponent, classGoLangComponent, classCondaComponent, \
    classDartComponent
from bdscan import utils, globals


class ComponentList:
    md_directdeps_header = \
        f"\nSynopsys Black Duck has reported security policy violations. The summary table shows the list of direct " \
        f"dependencies with violations, including counts of vulnerabilities within the dependency and within its " \
        f"child (transitive) dependencies.\n\n" \
        f"## SUMMARY: Direct Dependencies with security Policy Violations:\n\n" \
        f"| Direct Dependency | Total Vulns | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns | " \
        f"Max Indirect Vuln Severity | Upgrade to |\n| --- | --- | --- | --- | --- | --- | --- |\n"

    md_comp_lic_hdr = \
        "\n## SUMMARY License violations:\n\n" \
        "| Direct Dependency | Affected Component | License | Policy Violated |\n" \
        "| --- | --- | --- | --- |\n"

    def __init__(self):
        self.compids = []
        self.components = []

    def add(self, compid):
        if compid in self.compids:
            return self.components[self.compids.index(compid)]

        globals.printdebug(f"DEBUG: add(compid={compid})")

        arr = re.split('[/:]', compid)

        ns = arr[0]
        if ns == 'npmjs':
            component = classNpmComponent.NpmComponent(compid, arr[1], arr[2], ns)
        elif ns == 'nuget':
            component = classNugetComponent.NugetComponent(compid, arr[1], arr[2], ns)
        elif ns == 'maven':
            component = classMavenComponent.MavenComponent(compid, arr[1], arr[2], arr[3], ns)
        elif ns == 'pypi':
            component = classPyPiComponent.PyPiComponent(compid, arr[1], arr[2], ns)
        elif ns == 'conan':
            component = classConanComponent.ConanComponent(compid, arr[1], arr[2], ns)
        elif ns == 'crates':
            component = classCargoComponent.CargoComponent(compid, arr[1], arr[2], ns)
        elif ns == 'hex':
            component = classHexComponent.HexComponent(compid, arr[1], arr[2], ns)
        elif ns == 'golang':
            component = classGoLangComponent.GoLangComponent(compid, arr[1], arr[2], ns)
        elif ns == 'anaconda':
            component = classCondaComponent.CondaComponent(compid, arr[1], arr[2], ns)
        elif ns == 'dart':
            component = classDartComponent.DartComponent(compid, arr[1], arr[2], ns)
        else:
            # component = classComponent.Component(compid, arr[1], arr[2], ns)
            raise ValueError(f'Unsupported package manager {ns}')
        self.components.append(component)
        self.compids.append(component.compid)

        return component

    def set_data_in_comp(self, compid, fieldname, data):
        if compid in self.compids:
            index = self.compids.index(compid)
            comp = self.components[index]
            return comp.set_data(fieldname, data)
        return False

    def add_origins_to_comp(self, compid, ver, data):
        if compid in self.compids:
            index = self.compids.index(compid)
            comp = self.components[index]
            comp.set_origins(ver, data)

    def get_component(self, compid):
        if compid in self.compids:
            return self.components[self.compids.index(compid)]
        return None

    def find_upgrade_versions(self, upgrade_major):
        for comp in self.components:
            comp.find_upgrade_versions(upgrade_major)

    def validate_upgrades(self):
        detect_jar = utils.get_detect_jar()
        bd_output_path = 'upgrade-tests'

        detect_connection_opts = [
            f'--blackduck.url={globals.args.bd_url}',
            f'--blackduck.api.token={globals.args.bd_token}',
            "--detect.blackduck.scan.mode=RAPID",
            # "--detect.detector.buildless=true",
            # detect_connection_opts.append("--detect.maven.buildless.legacy.mode=false")
            f"--detect.output.path={bd_output_path}",
            "--detect.cleanup=false"
        ]
        if globals.args.bd_trustcert:
            detect_connection_opts.append('--blackduck.trust.cert=true')

        max_upgrade_count = 0
        for comp in self.components:
            if len(comp.potentialupgrades) > max_upgrade_count:
                max_upgrade_count = len(comp.potentialupgrades)
        upgrade_index = 0
        while upgrade_index <= max_upgrade_count:
            print(f'BD-Scan-Action: Validating upgrades cycle {upgrade_index+1} ...')
            # dirname = "snps-upgrade-" + direct_name + "-" + direct_version
            dirname = tempfile.TemporaryDirectory()
            # os.mkdir(dirname)
            origdir = os.getcwd()
            os.chdir(dirname.name)

            test_upgrade_list = []
            test_origdeps_list = []
            for comp in self.components:
                # Do not process components in package managers not supported by direct upgrade guidance, but use
                # regular upgrade guidance if available
                if not comp.supports_direct_upgrades():
                    globals.printdebug(f"DEBUG: Component {comp.name} via package manager {comp.pm} does not"
                                       f"support direct upgrades, skipping")
                    if comp.upgradeguidance and comp.upgradeguidance[0]:
                        comp.goodupgrade = comp.upgradeguidance[0]
                    elif comp.upgradeguidance and comp.upgradeguidance[1]:
                        comp.goodupgrade = comp.upgradeguidance[1]
                    continue

                if comp.goodupgrade == '' and len(comp.potentialupgrades) > upgrade_index:
                    if comp.prepare_upgrade(upgrade_index):

                        test_upgrade_list.append([comp.org, comp.name, comp.potentialupgrades[upgrade_index]])
                        globals.printdebug(f"Will test upgrade {comp.name}/{comp.version} to "
                                           f"{comp.potentialupgrades[upgrade_index]}")
                        test_origdeps_list.append(comp.compid)

            if len(test_origdeps_list) == 0:
                os.chdir(origdir)
                dirname.cleanup()
                upgrade_index += 1
                continue
            pm_list = []
            for comp in self.components:
                if comp.pm not in pm_list and comp.compid in test_origdeps_list:
                    pm_list.append(comp.pm)
                    comp.finalise_upgrade()

            if len(pm_list) == 1 and pm_list[0] == 'maven' and \
                    "--detect.detector.buildless=true" not in detect_connection_opts:
                detect_connection_opts.append("--detect.detector.buildless=true")

            output = False
            if globals.debug > 0:
                output = True

            pvurl, projname, vername, retval = utils.run_detect(detect_jar, detect_connection_opts, output)

            if retval == 3:
                # Policy violation returned
                rapid_scan_data, dep_dict, direct_deps_vuln = utils.process_scan(bd_output_path, globals.bd)
                # process_scan(scan_folder, bd, baseline_comp_cache, incremental, upgrade_indirect):

                last_vulnerable_dirdeps = []
                for vulndep in direct_deps_vuln.components:
                    #
                    # find comp in depver_list
                    for upgradedep, origdep in zip(test_upgrade_list, test_origdeps_list):
                        if upgradedep[1] == vulndep.name:
                            # vulnerable_upgrade_list.append([origdep, upgradedep[2]])
                            last_vulnerable_dirdeps.append(origdep)
                            break
            elif retval != 0:
                # Other Detect failure - no upgrades determined
                last_vulnerable_dirdeps = []
                for upgradedep, origdep in zip(test_upgrade_list, test_origdeps_list):
                    # vulnerable_upgrade_list.append([origdep, upgradedep[2]])
                    last_vulnerable_dirdeps.append(origdep)
            else:
                # Detect returned 0
                # All tested upgrades not vulnerable
                last_vulnerable_dirdeps = []

            for lcomp in self.components:
                if (lcomp.compid in test_origdeps_list and lcomp.compid not in last_vulnerable_dirdeps and
                        len(lcomp.potentialupgrades) >= upgrade_index and lcomp.goodupgrade == ''):
                    lcomp.set_data('goodupgrade', lcomp.potentialupgrades[upgrade_index])
            os.chdir(origdir)
            dirname.cleanup()
            upgrade_index += 1

        return

    def check_in_baselineproj(self, baseline_data):
        for basecomp in baseline_data:
            for baseorig in basecomp['origins']:
                if baseorig['externalNamespace'] != '':
                    basecompid = f"{baseorig['externalNamespace']}:{baseorig['externalId']}"
                else:
                    basecompid = baseorig['externalId']
                if basecompid in self.compids:
                    comp = self.get_component(basecompid)
                    comp.set_data('inbaseline', True)
                break

    # def check_projfiles(self):
    #     for comp in self.components:
    #         package_file, package_line = comp.get_package_file()
    #         if package_file == 'Unknown' or package_line <= 0:
    #             # component doesn't exist in pkgfile - skip
    #             continue
    #         package_file = utils.remove_cwd_from_filename(package_file)
    #         if package_file not in comp.projfiles:
    #             comp.set_data('projfiles', package_file)
    #             comp.set_data('projfilelines', package_line)

    def get_children(self, dep_dict):
        for comp in self.components:
            children = []
            for alldep in dep_dict.keys():
                if comp.compid in dep_dict[alldep]['directparents']:
                    children.append(alldep)
            comp.set_data('children', children)

    def calc_vulns(self, rapid_scan_data):
        for comp in self.components:
            max_vuln_severity = 0
            max_vuln_severity_children = 0
            existing_vulns = []
            existing_vulns_children = []
            existing_lic_violations = []
            existing_lic_violations_children = []

            for rscanitem in rapid_scan_data['items']:
                child = False
                parent = False
                if rscanitem['componentIdentifier'] == comp.compid:
                    parent = True
                else:
                    for childid in comp.children:
                        if rscanitem['componentIdentifier'] == childid:
                            child = True
                            break

                if not parent and not child:
                    continue

                for vuln in rscanitem['policyViolationVulnerabilities']:
                    # print(f"vuln={vuln}")
                    parent_name = '-'
                    parent_ver = '-'
                    if parent:
                        if vuln['name'] in existing_vulns:
                            continue
                        if max_vuln_severity < vuln['overallScore']:
                            max_vuln_severity = vuln['overallScore']
                    elif child:
                        if vuln['name'] in existing_vulns_children:
                            continue
                        if max_vuln_severity_children < vuln['overallScore']:
                            max_vuln_severity_children = vuln['overallScore']
                        parent_name = comp.name
                        parent_ver = comp.version
                    child_ns, child_name, child_ver = comp.parse_compid(rscanitem['componentIdentifier'])

                    desc = vuln['description'].replace('\n', ' ')
                    if len(desc) > 200:
                        desc = desc[:196]
                        desc += ' ...'
                    name = vuln['name']
                    link = f"{globals.args.bd_url}/api/vulnerabilities/{name}/overview"
                    vulnname = f'<a href="{link}" target="_blank">{name}</a>'

                    # if comp.inbaseline:
                    #     changed = 'No'
                    # else:
                    #     changed = 'Yes'
                    if parent_name == '-':
                        parent = f"{child_name}/{child_ver}"
                    else:
                        parent = f"{parent_name}/{parent_ver}"

                    vuln_item = [
                            parent,
                            f"{child_name}/{child_ver}",
                            vulnname,
                            str(vuln['overallScore']),
                            vuln['violatingPolicies'][0]['policyName'],
                            desc,
                            # changed
                        ]
                    if parent and vuln['name'] not in existing_vulns:
                        comp.add_vuln(name, vuln_item)
                        comp.set_data('maxvulnscore', max_vuln_severity)
                    if child and vuln['name'] not in existing_vulns_children:
                        comp.add_child_vuln(name, vuln_item)
                        comp.set_data('maxchildvulnscore', max_vuln_severity_children)

                # TODO: Revisit license violations
                for lic in rscanitem['policyViolationLicenses']:
                    parent_name = '-'
                    parent_ver = '-'
                    if parent:
                        print(f"lic={lic}")
                        if lic['name'] in existing_lic_violations:
                            continue
                        # if max_vuln_severity < vuln['overallScore']:
                        #    max_vuln_severity = vuln['overallScore']
                    elif child:
                        if lic['name'] in existing_lic_violations_children:
                            continue
                        # if max_vuln_severity_children < vuln['overallScore']:
                        #    max_vuln_severity_children = vuln['overallScore']
                        parent_name = comp.name
                        parent_ver = comp.version
                    child_ns, child_name, child_ver = comp.parse_compid(rscanitem['componentIdentifier'])

                    name = lic['name']
                    # TODO: This link is not user friendly; follow to generate correct link
                    link = lic['_meta']['href']
                    # link = f"{globals.args.bd_url}/api/vulnerabilities/{name}/overview"
                    licname = f'<a href="{link}" target="_blank">{name}</a>'

                    # if comp.inbaseline:
                    #     changed = 'No'
                    # else:
                    #     changed = 'Yes'

                    lic_item = [
                        f"{parent_name}/{parent_ver}",
                        f"{child_name}/{child_ver}",
                        licname,
                        lic['violatingPolicies'][0]['policyName'],
                        # changed
                    ]
                    if parent and lic['name'] not in existing_lic_violations:
                        comp.add_lic_violation(name, lic_item)
                        # comp.set_data('maxvulnscore', max_vuln_severity)
                    if child and lic['name'] not in existing_lic_violations_children:
                        comp.add_child_lic_violation(name, lic_item)
                        # comp.set_data('maxchildvulnscore', max_vuln_severity_children)

            # Sort the tables
            # vuln_list = sorted(vuln_list, key=itemgetter(3), reverse=True)
            # vuln_list_children = sorted(vuln_list_children, key=itemgetter(3), reverse=True)
        return

    def write_sarif(self, sarif_file):
        if os.path.exists(sarif_file):
            os.remove(sarif_file)
        if os.path.exists(sarif_file):
            print(f'BD-Scan-Action: ERROR: Unable to write SARIF file {sarif_file}')
            return False

        sarif_result = []
        sarif_tool_rule = []

        for comp in self.components:
            # md_comp_vulns_table = comp.md_table()
            projfile = ''
            projfileline = 1
            if len(comp.projfiles) > 0:
                projfile = comp.projfiles[0]
            if len(comp.projfilelines) > 0:
                projfileline = comp.projfilelines[0]

            sarif_result.append(
                {
                    'ruleId': comp.name,
                    'message': {
                        'text': comp.shorttext()
                    },
                    'locations': [
                        {
                            'physicalLocation': {
                                'artifactLocation': {
                                    'uri': projfile,
                                },
                                'region': {
                                    'startLine': projfileline,
                                }
                            }
                        }
                    ],
                    'partialFingerprints': {
                        'primaryLocationLineHash': hashlib.sha224(b"{compid}").hexdigest(),
                    }
                }
            )

            if comp.maxchildvulnscore >= 7 or comp.maxvulnscore >= 7:
                level = "error"
            elif comp.maxchildvulnscore >= 4 or comp.maxvulnscore >= 4:
                level = "warning"
            else:
                level = "note"

            if comp.goodupgrade != '':
                uhelp = f"{comp.longtext_md()}\n\nRecommended to upgrade to version {comp.goodupgrade}.\n\n"
            else:
                uhelp = f"{comp.longtext_md()}\n\nNo upgrade available at this time.\n\n"

            sarif_tool_rule.append(
                {
                    'id': comp.name,
                    'shortDescription': {
                        'text': comp.shorttext(),
                    },
                    'fullDescription': {
                        'text': comp.longtext(),
                    },
                    'help': {
                        'text': '',
                        'markdown': uhelp,
                    },
                    'defaultConfiguration': {
                        'level': level,
                    },
                    'properties': {
                        'tags': ["security"],
                        'security-severity': str(comp.maxvulnscore)
                    }
                }
            )

        code_security_scan_report = {
            '$schema': "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            'version': "2.1.0",
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'Synopsys Black Duck',
                            'organization': 'Synopsys',
                            'version': globals.scan_utility_version,
                            'rules': sarif_tool_rule,
                        }
                    },
                    'results': sarif_result,
                }
            ],
        }
        try:
            with open(sarif_file, "w") as fp:
                json.dump(code_security_scan_report, fp, indent=4)
        except Exception as e:
            print(f"BD-Scan-Action: ERROR: Unable to write to SARIF output file '{sarif_file} - '" + str(e))
            return False
        return True

    def get_comments(self, incremental):
        md_main_table = []
        md_comp_data_string = ''
        md_lic_table_string = ''
        for comp in self.components:
            if incremental and comp.inbaseline:
                continue

            if comp.get_num_vulns() > 0:
                md_main_table.append(comp.md_summary_table_row())

            md_comp_data_string += f"\n### Direct Dependency: {comp.name}/{comp.version}\n"
            if comp.goodupgrade != '':
                md_comp_data_string += f"Upgrade direct dependency '{comp.name}' to version {comp.goodupgrade} to " \
                                       f"address security policy violations in this dependency and all its child " \
                                       f"(transitive) dependencies."
            elif not globals.args.upgrade_major:
                md_comp_data_string += f"No minor upgrade available (within the same current major version); " \
                                       f"consider setting the --upgrade_major option to look for upgrades in " \
                                       f"future versions."
            elif globals.args.upgrade_major:
                md_comp_data_string += f"No upgrade available."

            if len(comp.projfiles) > 0:
                md_comp_data_string += f" This component is defined in the package manager config file " \
                                       f"'{comp.projfiles[0]}'\n"

            md_comp_data_string += comp.md_table()

            md_lic_table_string += comp.md_lic_table()

        # Sort main table here
        md_main_table = sorted(md_main_table, key=itemgetter(3), reverse=True)
        # md_main_table = sorted(md_main_table, key=itemgetter(4), reverse=True)

        sep = ' | '
        md_main_table_string = ''
        for row in md_main_table:
            md_main_table_string += '| ' + sep.join(row) + ' |\n'

        md_comments = ''
        if len(md_main_table) > 0:
            md_comments += self.md_directdeps_header + md_main_table_string

        if len(md_lic_table_string) > 1:
            md_comments += self.md_comp_lic_hdr + md_lic_table_string

        if len(md_main_table) > 0:
            md_comments += '\n\nDirect Dependencies with security policy vulnerabilities are listed below showing ' \
                           'the associated vulnerabilities in the dependency and its children (transitive ' \
                           'dependencies):\n\n' + md_comp_data_string

        return md_comments

    def print_upgrade_summary(self):
        print('\n------------------------------------------------------------------------------------')
        print('SUMMARY UPGRADE GUIDANCE:')
        for comp in self.components:
            if comp.goodupgrade != '':
                upg = f'Upgrade to {comp.goodupgrade}'
            else:
                upg = 'No Upgrade Available'
            print(f'- {comp.name}/{comp.version}: {upg}')
        print('------------------------------------------------------------------------------------\n')

    # @staticmethod
    # def supports_direct_upgrades():
    #     return False
