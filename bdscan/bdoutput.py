# import argparse
import glob
# import hashlib
import json
import os
import sys
import re
from bdscan import globals, classComponentList, utils


# from BlackDuckUtils import MavenUtils


def get_blackduck_status(output_dir):
    bd_output_status_glob = max(glob.glob(output_dir + "/runs/*/status/status.json"), key=os.path.getmtime)
    if len(bd_output_status_glob) == 0:
        print(f"BD-Scan-Action: ERROR: Unable to find output scan files in: {output_dir}/runs/*/status/status.json")
        sys.exit(1)

    bd_output_status = bd_output_status_glob

    # print("INFO: Parsing Black Duck Scan output from " + bd_output_status)
    with open(bd_output_status) as f:
        output_status_data = json.load(f)

    detected_package_files = []
    found_detectors = 0
    for detector in output_status_data['detectors']:
        # Reverse order so that we get the priority from detect
        if detector['detectorType'] != 'GIT':
            found_detectors += 1
        for explanation in reversed(detector['explanations']):
            if str.startswith(explanation, "Found file: "):
                package_file = explanation[len("Found file: "):]
                if os.path.isfile(package_file):
                    detected_package_files.append(package_file)
                    globals.printdebug(f"DEBUG: Explanation: {explanation} File: {package_file}")

    if found_detectors == 0:
        print(f"BD-Scan-Action: WARN: No package manager scan identified (empty scan?) - Exiting")
        sys.exit(2)

    # Find project name and version to use in looking up baseline data
    project_baseline_name = output_status_data['projectName']
    project_baseline_version = output_status_data['projectVersion']

    return project_baseline_name, project_baseline_version, detected_package_files


def get_rapid_scan_results(output_dir, bd):
    # Parse the Rapid Scan output, assuming there is only one run in the directory
    filelist = glob.glob(output_dir + "/runs/*/scan/*.json")
    if len(filelist) <= 0:
        return None
    bd_rapid_output_file_glob = max(filelist, key=os.path.getmtime)
    if len(bd_rapid_output_file_glob) == 0:
        print("BD-Scan-Action: ERROR: Unable to find output scan files in: " + output_dir + "/runs/*/scan/*.json")
        return None

    bd_rapid_output_file = bd_rapid_output_file_glob
    # print("INFO: Parsing Black Duck Rapid Scan output from " + bd_rapid_output_file)
    with open(bd_rapid_output_file) as f:
        output_data = json.load(f)

    if len(output_data) <= 0 or '_meta' not in output_data[0] or 'href' not in output_data[0]['_meta']:
        return None

    developer_scan_url = output_data[0]['_meta']['href']
    globals.printdebug("DEBUG: Developer scan href: " + developer_scan_url)

    # Handle limited lifetime of developer runs gracefully
    try:
        rapid_scan_results = utils.get_json(bd, developer_scan_url)
    except Exception as e:
        print(
            f"BD-Scan-Action: ERROR: Unable to fetch developer scan '{developer_scan_url}' \
- note that these are limited lifetime and this process must run immediately following the rapid scan")
        raise

    # TODO: Handle error if can't read file
    # globals.printdebug("DEBUG: Developer scan data: " + json.dumps(rapid_scan_results, indent=4) + "\n")
    # print("DEBUG: Developer scan data: " + json.dumps(rapid_scan_results, indent=4) + "\n")

    return rapid_scan_results


# def process_rapid_scan(rapid_scan_data, incremental, baseline_comp_cache, bdio_graph, bdio_projects):
def process_rapid_scan(rapid_scan_data, bdio_graph, bdio_projects):
    import glob
    allpoms = glob.glob('**/pom.xml', recursive=True)

    import networkx as nx
    # pm = ''

    allcomps_clist = classComponentList.ComponentList()
    direct_vulnerable_clist = classComponentList.ComponentList()

    # Process all deps
    # direct_deps_to_upgrade = {}
    dep_dict = {}
    for item in rapid_scan_data:
        # print(json.dumps(item, indent=4))
        # Loop through comps to determine what needs upgrading

        dep_vulnerable = False
        # TODO: Revisit license violations
        # if len(item['policyViolationVulnerabilities']) > 0 or len(item['policyViolationLicenses']) > 0:
        if len(item['policyViolationVulnerabilities']) > 0:
            dep_vulnerable = True

        globals.printdebug(f"DEBUG: Component: {item['componentIdentifier']}")
        globals.printdebug(item)

        comp = allcomps_clist.add(item['componentIdentifier'])

        http_name = comp.get_http_name()

        dep_dict[comp.compid] = {
            'compname': comp.name,
            'compversion': comp.version,
            'compns': comp.ns,
            'directparents': [],
        }
        globals.printdebug(f"DEBUG: Looking for {http_name}")
        # ancs = nx.ancestors(bdio_graph, http_name)
        # ancs_list = list(ancs)

        # Process the paths
        dep_dict[comp.compid]['deptype'] = 'Indirect'
        for proj in bdio_projects:
            dep_paths = nx.all_simple_paths(bdio_graph, source=proj, target=http_name)
            for path in dep_paths:
                path_mod = []
                i = 0
                projfile = ''
                for p in path:
                    if not p.endswith(tuple(['/' + s for s in comp.pms])) and not p.endswith(f'/{comp.pm}') \
                            and not p.startswith('http:detect/') and not p == proj and not re.match("http:.*/%2F", p):
                        path_mod.append(p)
                    elif p.endswith(f'/{comp.pm}'):
                        projfile = comp.get_projfile(p, allpoms)
                    else:
                        # Skip this path
                        pass
                    i += 1

                direct_dep = comp.normalise_dep(path_mod[0])

                if len(path_mod) == 1 and path_mod[0] == http_name:
                    # This is actually a direct dependency
                    dep_dict[item['componentIdentifier']]['deptype'] = 'Direct'
                    dep_dict[item['componentIdentifier']]['directparents'] = []
                else:
                    dep_dict[item['componentIdentifier']]['directparents'].append(direct_dep)

                # Then log the direct dependencies directly
                # childdep = comp.normalise_dep(comp.compid)
                # if direct_dep != '' and dep_vulnerable:
                if dep_vulnerable:
                    dircomp = direct_vulnerable_clist.add(direct_dep)

                    projfile_ok = False
                    linenum = -1
                    if projfile != '' and projfile is not None:
                        linenum = dircomp.get_projfile_linenum(projfile)
                        if linenum > 0:
                            projfile_ok = True

                    if not projfile_ok:
                        for file in globals.detected_package_files:
                            linenum = dircomp.get_projfile_linenum(file)
                            if linenum > 0:
                                projfile = file
                                projfile_ok = True
                                break

                    if projfile_ok:
                        if direct_vulnerable_clist.set_data_in_comp(direct_dep, 'projfiles',
                                                                    utils.remove_cwd_from_filename(projfile)):
                            direct_vulnerable_clist.set_data_in_comp(direct_dep, 'projfilelines', linenum)

    return dep_dict, direct_vulnerable_clist
