# import json
import sys
# import hashlib
import os
import shutil
# from operator import itemgetter

from blackduck import Client

from bdscan import bdoutput, utils, globals, asyncdata as asyncdata, classGitHubProvider, classAzureProvider


def process_bd_scan(output):
    project_baseline_name, project_baseline_version, globals.detected_package_files = \
        bdoutput.get_blackduck_status(output)

    rapid_scan_data, dep_dict, direct_deps_to_upgrade = utils.process_scan(globals.args.output, globals.bd)

    if rapid_scan_data is None:
        return None, None, None

    # Look up baseline data
    pvurl = utils.get_projver(globals.bd, project_baseline_name, project_baseline_version)
    if pvurl == '':
        print(f"BD-Scan-Action: WARN: Unable to find project '{project_baseline_name}' \
version '{project_baseline_version}' - cannot calculate incremental results")
    else:
        globals.printdebug(f"DEBUG: Project Version URL: {pvurl}")
        baseline_comps = utils.get_comps(globals.bd, pvurl)
        direct_deps_to_upgrade.check_in_baselineproj(baseline_comps)

    return rapid_scan_data, dep_dict, direct_deps_to_upgrade


# def unique(list1):
#     unique_list = []
#     for x in list1:
#         # check if exists in unique_list or not
#         if x not in unique_list:
#             unique_list.append(x)
#     return unique_list
#
#
# def create_scan_outputs(rapid_scan_data, upgrade_dict, dep_dict, direct_deps_to_upgrade):
#     def vuln_color(value):
#         if value > 9:
#             return f'<span style="color:DarkRed">{str(value)}</span>'
#         elif value > 7:
#             return f'<span style="color:Red">{str(value)}</span>'
#         elif value > 5:
#             return f'<span style="color:Orange">{str(value)}</span>'
#         else:
#             return f'{str(value)}'
#
#     def count_vulns(parentid, childid, existing_vulns):
#         if parentid != '':
#             parent_ns, parent_name, parent_ver = Utils.parse_component_id(parentid)
#         else:
#             # parent_ns = ''
#             parent_name = ''
#             parent_ver = ''
#
#         child_ns, child_name, child_ver = Utils.parse_component_id(childid)
#         if globals.args.incremental_results and child_name in globals.baseline_comp_cache:
#             if (child_ver in globals.baseline_comp_cache[child_name] and
#                     globals.baseline_comp_cache[child_name][child_ver] == 1):
#                 globals.printdebug(f"DEBUG:   Skipping child component {child_name} \
#                 version {child_ver} because it was already seen in baseline")
#                 return existing_vulns, 0, 0, []
#             else:
#                 globals.printdebug(f"DEBUG:   Including child component {child_name} \
#                 version {child_ver} because it was not seen in baseline")
#
#         vuln_count = 0
#         max_vuln_severity = 0
#         cvulns_list = []
#
#         for rscanitem in rapid_scan_data['items']:
#             if rscanitem['componentIdentifier'] == childid:
#                 for vuln in rscanitem['policyViolationVulnerabilities']:
#                     if vuln['name'] in existing_vulns:
#                         continue
#                     existing_vulns.append(vuln['name'])
#                     vuln_count += 1
#                     # print(f"vuln={vuln}")
#                     if max_vuln_severity < vuln['overallScore']:
#                         max_vuln_severity = vuln['overallScore']
#
#                     desc = vuln['description'].replace('\n', ' ')
#                     if len(desc) > 200:
#                         desc = desc[:200]
#                         desc += ' ...'
#                     name = f"{vuln['name']}"
#                     link = f"{globals.args.url}/api/vulnerabilities/{name}/overview"
#                     vulnname = f'<a href="{link}" target="_blank">{name}</a>'
#
#                     cvulns_list.append(
#                         [
#                             f"{parent_name}/{parent_ver}",
#                             f"{child_name}/{child_ver}",
#                             vulnname,
#                             vuln['overallScore'],
#                             vuln['violatingPolicies'][0]['policyName'],
#                             desc,
#                             child_ver,
#                         ]
#                     )
#                 break
#
#         # Sort the table
#         cvulns_list = sorted(cvulns_list, key=itemgetter(3), reverse=True)
#
#         # add colours to vuln scores
#         cvulns_table = []
#         for crow in cvulns_list:
#             vscore = vuln_color(crow[3])
#             # | Parent | Component | Vulnerability | Severity |  Policy | Description | Current Ver |
#          cvulns_table.append(f"| {crow[0]} | {crow[1]} | {crow[2]} | {vscore} | {crow[4]} | {crow[5]} | {crow[6]} |")
#
#         return existing_vulns, vuln_count, max_vuln_severity, cvulns_table
#     #
#     # End of count_vulns()
#
#     globals.printdebug(f"DEBUG: Entering create_scan_outputs({rapid_scan_data},\n{upgrade_dict},\n{dep_dict}")
#
#     md_directdeps_header = [
#         "",
#         "## SUMMARY Direct Dependencies with vulnerabilities:",
#         "",
#         f"| Direct Dependency | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns "
#         f"| Max Indirect Vuln Severity | Upgrade to |",
#         "| --- | --- | --- | --- | --- | --- |"
#     ]
#     md_vulns_header = [
#         "",
#         "| Parent | Child Component | Vulnerability | Score |  Policy Violated | Description | Current Ver |",
#         "| --- | --- | --- | --- | --- | --- | --- |"
#     ]
#     md_directdeps_list = []
#
#     md_all_vulns_table = md_vulns_header[:]
#
#     # for item in rapid_scan_data['items']:
#     for compid in direct_deps_to_upgrade.keys():
#         # compid = item['componentIdentifier']
#
#         comp_ns, comp_name, comp_version = Utils.parse_component_id(compid)
#
#         if compid in upgrade_dict:
#             upgrade_ver = upgrade_dict[compid]
#         else:
#             upgrade_ver = None
#
#         # If package file for this direct dep is blank, find from the detect-returned package files
#         pkgfiles = []
#         pkglines = []
#         for projfile in unique(direct_deps_to_upgrade[compid]):
#             if projfile == '':
#                 # Find component in top-level pkgfiles
#                 package_file, package_line = Utils.find_comp_in_projfiles(globals.detected_package_files, compid)
#             else:
#                 package_file, package_line = Utils.find_comp_in_projfiles([projfile], compid)
#             if package_file == 'Unknown' or package_line <= 0:
#                 # component doesn't exist in pkgfile - skip
#                 continue
#             pkgfiles.append(package_file)
#             pkglines.append(package_line)
#         if len(pkgfiles) == 0:
#             continue
#
#         children = []
#         for alldep in dep_dict.keys():
#             if compid in dep_dict[alldep]['directparents']:
#                 children.append(alldep)
#
#         # print(f"parent={comp_name}/{comp_version} - children={children}")
#
#         md_comp_vulns_table = md_vulns_header[:]
#         dir_vulns, dir_vuln_count, dir_max_sev, md_comp_vtable = count_vulns('', compid, [])
#         md_all_vulns_table.extend(md_comp_vtable)
#         md_comp_vulns_table.extend(md_comp_vtable)
#
#         children_max_sev = 0
#         children_num_vulns = 0
#         children_string = ''
#
#         for childid in children:
#             # Find child in rapidscan data
#             child_ns, child_name, child_ver = Utils.parse_component_id(childid)
#             if childid != compid:
#                 children_string += f"{child_name}/{child_ver},"
#             else:
#                 continue
#
#             dir_vulns, cvuln_count, cmax_sev, md_cvulns_table = count_vulns(compid, childid, dir_vulns)
#             md_comp_vulns_table.extend(md_cvulns_table)
#             md_all_vulns_table.extend(md_cvulns_table)
#
#             if cmax_sev > children_max_sev:
#                 children_max_sev = cmax_sev
#             children_num_vulns += cvuln_count
#
#         if upgrade_ver is None:
#             uver = 'N/A'
#         else:
#             uver = upgrade_ver
#         # pfile = Utils.remove_cwd_from_filename(package_file)
#
#         # | Direct Dependency | Max Vuln Severity | No. of Vulns | Upgrade to | File |
#         md_directdeps_list.append(
#             [
#                 f"{comp_name}/{comp_version}",
#                 dir_vuln_count,
#                 dir_max_sev,
#                 children_num_vulns,
#                 children_max_sev,
#                 uver,
#             ]
#         )
#
#         if dir_vuln_count > 0 and children_num_vulns > 0:
#           shorttext = f"The direct dependency {comp_name}/{comp_version} has {dir_vuln_count} vulnerabilities (max " \
#                         f"score {dir_max_sev}) and {children_num_vulns} vulnerabilities in child dependencies (max " \
#                         f"score {children_max_sev})."
#             longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
#             longtext = f"{shorttext}\n\nList of direct and indirect vulnerabilities:\n{','.join(dir_vulns)}"
#         elif dir_vuln_count > 0 and children_num_vulns == 0:
#           shorttext = f"The direct dependency {comp_name}/{comp_version} has {dir_vuln_count} vulnerabilities (max " \
#                         f"score {dir_max_sev})."
#             longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
#             longtext = f"{shorttext}\n\nList of direct vulnerabilities:\n{','.join(dir_vulns)}"
#         elif children_num_vulns > 0:
#            shorttext = f"The direct dependency {comp_name}/{comp_version} has {children_num_vulns} vulnerabilities " \
#                         f"in child dependencies (max score {children_max_sev})."
#             longtext_md = shorttext + "\n\n" + '\n'.join(md_comp_vulns_table) + '\n'
#             longtext = f"{shorttext}\n\nList of indirect vulnerabilities:\n{','.join(dir_vulns)}"
#         else:
#             shorttext = ''
#             longtext_md = ''
#             longtext = ''
#
#         # projfiles = []
#         # for projfile in direct_deps_to_upgrade[compid]:
#         #     if projfile != '':
#         #         projfiles.append(Utils.remove_cwd_from_filename(projfile))
#         #     else:
#         #         pass
#
#         fix_pr_node = dict()
#         if upgrade_ver is not None:
#             fix_pr_node = {
#                 'componentName': comp_name,
#                 'versionFrom': comp_version,
#                 'versionTo': upgrade_ver,
#                 'ns': comp_ns,
#                 'projfiles': pkgfiles,
#                 'comments': [f"## Dependency {comp_name}/{comp_version}\n{shorttext}"],
#                 'comments_markdown': [longtext_md],
#                 'comments_markdown_footer': ''
#             }
#
#         globals.comment_on_pr_comments.append(f"## {comp_name}/{comp_version}\n{longtext_md}")
#
#         result = {
#             'ruleId': comp_name,
#             'message': {
#                 'text': shorttext
#             },
#             'locations': [
#                 {
#                     'physicalLocation': {
#                         'artifactLocation': {
#                             'uri': pkgfiles[0],
#                         },
#                         'region': {
#                             'startLine': pkglines[0],
#                         }
#                     }
#                 }
#             ],
#             'partialFingerprints': {
#                 'primaryLocationLineHash': hashlib.sha224(b"{compid}").hexdigest(),
#             }
#         }
#         globals.results.append(result)
#
#         if children_max_sev >= 7 or dir_max_sev >= 7:
#             level = "error"
#         elif children_max_sev >= 4 or dir_max_sev >= 4:
#             level = "warning"
#         else:
#             level = "note"
#
#         if upgrade_ver is not None:
#             uhelp = f"{longtext_md}\n\nRecommended to upgrade to version {upgrade_ver}.\n\n"
#         else:
#             uhelp = f"{longtext_md}\n\nNo upgrade available at this time.\n\n"
#
#         tool_rule = {
#             'id': comp_name,
#             'shortDescription': {
#                 'text': shorttext,
#             },
#             'fullDescription': {
#                 'text': longtext,
#             },
#             'help': {
#                 'text': '',
#                 'markdown': uhelp,
#             },
#             'defaultConfiguration': {
#                 'level': level,
#             },
#             'properties': {
#                 'tags': ["security"],
#                 'security-severity': str(dir_max_sev)
#             }
#         }
#
#         globals.tool_rules.append(tool_rule)
#
#         if upgrade_ver is not None:
#             a_comp = compid.replace(':', '@').replace('/', '@').split('@')
#             globals.fix_pr_data[f"{a_comp[1]}@{a_comp[2]}"] = fix_pr_node
#
#     md_directdeps_list = sorted(md_directdeps_list, key=itemgetter(4), reverse=True)
#     md_directdeps_list = sorted(md_directdeps_list, key=itemgetter(2), reverse=True)
#
#     md_directdeps_table = md_directdeps_header
#     for crow in md_directdeps_list:
#         # | Direct Dependency | Num Direct Vulns | Max Direct Vuln Severity | Num Indirect Vulns
#         # | Max Indirect Vuln Severity | Upgrade to |",
#         md_directdeps_table.append(f"| {crow[0]} | {crow[1]} | {vuln_color(crow[2])} | {crow[3]} "
#                                    f"| {vuln_color(crow[4])} | {crow[5]} |")
#
#     globals.comment_on_pr_comments = md_directdeps_table + \
#         ['\n\n', "Vulnerable Direct dependencies listed below:\n\n"] + \
#         globals.comment_on_pr_comments
#
#
# def test_upgrades(upgrade_dict, deplist):
#     bd_connect_args = [
#         f'--blackduck.url={globals.args.url}',
#         f'--blackduck.api.token={globals.args.token}',
#     ]
#     if globals.args.trustcert:
#         bd_connect_args.append(f'--blackduck.trust.cert=true')
#     # print(deplist)
#     # good_upgrades_dict = Utils.attempt_indirect_upgrade(
#     #     pm, deplist, upgrade_dict, globals.detect_jar, bd_connect_args, globals.bd)
#     good_upgrades_dict = Utils.attempt_indirect_upgrade(
#         deplist, upgrade_dict, globals.detect_jar, bd_connect_args, globals.bd, globals.args.upgrade_indirect,
#         globals.args.upgrade_major)
#     return good_upgrades_dict
#
#
# def write_sarif(sarif_file, data):
#     try:
#         with open(sarif_file, "w") as fp:
#             json.dump(data, fp, indent=4)
#     except Exception as e:
#         print(f"BD-Scan-Action: ERROR: Unable to write to SARIF output file '{sarif_file} - '" + str(e))
#         sys.exit(1)


def main_process(output, runargs):
    globals.scm_provider = None

    if globals.args.scm == 'github':
        print(f"BD-Scan-Action: Interfacing with GitHub")
        globals.scm_provider = classGitHubProvider.GitHubProvider()
    elif globals.args.scm == 'azure':
        print(f"BD-Scan-Action: Interfacing with Azure DevOps ")
        globals.scm_provider = classAzureProvider.AzureProvider()
    elif globals.args.scm == 'gitlab':
        print(f"BD-Scan-Action: GitLab not supported yet")
        sys.exit(1)
    elif globals.args.scm == 'bitbucket':
        print(f"BD-Scan-Action: BitBucket Pipelines not supported yet")
        sys.exit(1)
    elif globals.args.scm == 'bitbucket-server':
        print(f"BD-Scan-Action: BitBucket Server/Data Center not supported yet")
        sys.exit(1)
    else:
        print(f"BD-Scan-Action: ERROR: Specified SCM '{globals.args.scm}' not supported yet")
        sys.exit(1)

    globals.scm_provider.init()

    if not globals.args.nocheck:
        if globals.args.fix_pr and not globals.scm_provider.check_files_in_commit():
            print('BD-Scan-Action: No package manager changes in commit - skipping dependency analysis')
            sys.exit(0)

        if globals.args.comment_on_pr and not globals.scm_provider.check_files_in_pull_request():
            print('BD-Scan-Action: No package manager changes in pull request - skipping dependency analysis')
            sys.exit(0)

    # Run DETECT
    print(f"BD-Scan-Action: INFO: Running Black Duck detect with the following options: {runargs}")
    pvurl, projname, vername, detect_return_code = utils.run_detect(globals.detect_jar, runargs, True)
    if detect_return_code > 0 and detect_return_code != 3:
        print(f"BD-Scan-Action: ERROR: Black Duck detect returned exit code {detect_return_code}")
        sys.exit(detect_return_code)

    if globals.args.mode == "intelligent":
        # Stop here
        print(f"BD-Scan-Action: Full/Intelligent scan performed - no further action")
        print('BD-Scan-Action: Done - SUCCESS')
        sys.exit(0)

    # Todo - Add proxy support
    globals.bd = Client(token=globals.args.token,
                        base_url=globals.args.url,
                        verify=globals.args.trustcert,
                        timeout=300)

    if globals.bd is None:
        print('BD-Scan-Action: ERROR: Unable to connect to Black Duck server - check credentials')
        print('BD-Scan-Action: Done - ERROR')
        sys.exit(1)

    # Process the Rapid scan
    print('\nBD-Scan-Action: Processing scan data ...')
    rapid_scan_data, dep_dict, direct_deps_to_upgrade = process_bd_scan(output)

    if rapid_scan_data is None:
        print('BD-Scan-Action: INFO: No policy violations found - Ending gracefully')
        print('BD-Scan-Action: Done - SUCCESS')
        sys.exit(0)

    # Get component data via async calls
    asyncdata.get_data_async(direct_deps_to_upgrade, globals.bd, globals.args.trustcert)

    # Work out possible upgrades
    globals.printdebug('BD-Scan-Action: Identifying upgrades ...')

    direct_deps_to_upgrade.calc_vulns(rapid_scan_data)
    direct_deps_to_upgrade.find_upgrade_versions(globals.args.upgrade_major)
    direct_deps_to_upgrade.validate_upgrades()
    direct_deps_to_upgrade.print_upgrade_summary()

    ret_status = True
    if globals.args.sarif is not None and globals.args.sarif != '':
        print(f"BD-Scan-Action: Writing sarif output file '{globals.args.sarif}' ...")
        ret_status = direct_deps_to_upgrade.write_sarif(globals.args.sarif)

    # generate Fix PR
    if globals.args.fix_pr:
        ok = False
        upgrade_count = 0
        for comp in direct_deps_to_upgrade.components:
            if globals.args.incremental_results and comp.inbaseline:
                continue
            if comp.goodupgrade != '':
                upgrade_count += 1
                if globals.scm_provider.comp_fix_pr(comp):
                    ok = True
            else:
                print(f'BD-Scan-Action: WARNING: Unable to create fix pull request for component {comp.name}')
        if ok:
            print(f'BD-Scan-Action: Created {upgrade_count} pull requests')
            globals.scm_provider.set_commit_status(True)
        else:
            ret_status = False
        if upgrade_count == 0:
            print('BD-Scan-Action: No upgrades available for Fix PR - skipping')
            ret_status = True

    # Optionally comment on the pull request this is for
    if globals.args.comment_on_pr:
        status_ok = True
        if len(direct_deps_to_upgrade.components) > 0:
            comment = direct_deps_to_upgrade.get_comments(globals.args.incremental_results)
            if globals.scm_provider.pr_comment(comment):
                status_ok = False
                print('BD-Scan-Action: Created comment on existing pull request')
            else:
                print('BD-Scan-Action: ERROR: Unable to create comment on existing pull request')
                ret_status = False
        else:
            print('BD-Scan-Action: No upgrades available for Comment on PR - skipping')
            ret_status = True

        globals.scm_provider.set_commit_status(status_ok)

    if os.path.isdir(globals.args.output) and os.path.isdir(os.path.join(globals.args.output, "runs")):
        shutil.rmtree(globals.args.output, ignore_errors=False, onerror=None)
        print(f'BD-Scan-Action: INFO: Cleaning up folder {globals.args.output}')

    if ret_status:
        print('BD-Scan-Action: Done - SUCCESS')
        sys.exit(0)
    else:
        print('BD-Scan-Action: Done - ERROR')
        sys.exit(1)
