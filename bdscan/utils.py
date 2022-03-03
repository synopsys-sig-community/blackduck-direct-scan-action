# import json
import os
import sys
import requests
import semver
# import tempfile
from pathlib import Path

# from BlackDuckUtils import NpmUtils
# from BlackDuckUtils import MavenUtils
# from BlackDuckUtils import NugetUtils
from bdscan import bdoutput, bdio, globals

import subprocess


def remove_cwd_from_filename(path):
    cwd = os.getcwd()
    cwd = cwd + "/"
    new_filename = path.replace(cwd, "")
    return new_filename


def run_detect(jarfile, runargs, show_output):
    if jarfile == '' or not os.path.isfile(jarfile):
        jarfile = get_detect_jar()

    # print('INFO: Running Black Duck Detect')

    args = ['java', '-jar', jarfile]
    args += runargs
    globals.printdebug("DEBUG: Command = ")
    globals.printdebug(args)

    retval = 1
    pvurl = ''
    projname = ''
    vername = ''
    try:
        proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        while True:
            outp = proc.stdout.readline()
            if proc.poll() is not None and outp == '':
                break
            if outp:
                if show_output:
                    print(outp.strip())
                bomstr = ' --- Black Duck Project BOM:'
                projstr = ' --- Project name:'
                verstr = ' --- Project version:'
                # noinspection PyTypeChecker
                if outp.find(bomstr) > 0:
                    pvurl = outp[outp.find(bomstr) + len(bomstr) + 1:].rstrip()
                if outp.find(projstr) > 0:
                    projname = outp[outp.find(projstr) + len(projstr) + 1:].rstrip()
                if outp.find(verstr) > 0:
                    vername = outp[outp.find(verstr) + len(verstr) + 1:].rstrip()
    except OSError:
        print('BD-Scan-Action: ERROR: Unable to run Detect')
    except Exception as e:
        print(f'BD-Scan-Action: ERROR: {str(e)}')
    else:
        retval = proc.poll()

    # if retval != 0:
    #     print('INFO: Detect returned non-zero value')
    #     # sys.exit(2)
    #
    # if projname == '' or vername == '':
    #     print('ERROR: No project or version identified from Detect run')
    #     # sys.exit(3)

    return '/'.join(pvurl.split('/')[:8]), projname, vername, retval


# def parse_component_id(component_id):
#     comp_ns = component_id.split(':')[0]
#
#     if comp_ns == "npmjs":
#         comp_ns, comp_name, comp_version = NpmUtils.parse_component_id(component_id)
#     elif comp_ns == "maven":
#         comp_ns, comp_name, comp_version = MavenUtils.parse_component_id(component_id)
#     elif comp_ns == "nuget":
#         comp_ns, comp_name, comp_version = NugetUtils.parse_component_id(component_id)
#     else:
#         print(f"BD-Scan-Action: ERROR: Package domain '{comp_ns}' is unsupported at this time")
#         sys.exit(1)
#
#     return comp_ns, comp_name, comp_version
#
#
# def get_upgrade_guidance(bd, component_identifier):
#     # Get component upgrade advice
#     globals.printdebug(f"DEBUG: Search for component '{component_identifier}'")
#     params = {
#         'q': [component_identifier]
#     }
#     try:
#         search_results = bd.get_items('/api/components', params=params)
#     except Exception as e:
#         return '', ''
#
#     # There should be exactly one result!
#     # TODO: Error checking?
#     component_result = {}
#     for result in search_results:
#         component_result = result
#
#     globals.printdebug("DEBUG: Component search result=" + json.dumps(component_result, indent=4) + "\n")
#
#     # Get component upgrade data
#     # globals.printdebug(f"DBEUG: Looking up upgrade guidance for component '{component_result['componentName']}'")
#     if 'version' not in component_result:
#         return '', ''
#     component_upgrade_data = bd.get_json(component_result['version'] + "/upgrade-guidance")
#     globals.printdebug("DEBUG: Component upgrade data=" + json.dumps(component_upgrade_data, indent=4) + "\n")
#
#     if "longTerm" in component_upgrade_data.keys():
#         long_term = component_upgrade_data['longTerm']['versionName']
#     else:
#         long_term = None
#
#     if "shortTerm" in component_upgrade_data.keys():
#         short_term = component_upgrade_data['shortTerm']['versionName']
#     else:
#         short_term = None
#
#     return short_term, long_term
#
#
# def line_num_for_phrase_in_file(comp, ver, filename, comp_ns):
#     if comp_ns == 'maven':
#         return MavenUtils.get_pom_line(comp, ver, filename)
#     else:
#         try:
#             with open(filename, 'r') as f:
#                 for (i, line) in enumerate(f):
#                     if comp.lower() in line.lower():
#                         return i
#         except Exception as e:
#             return -1
#         return -1
#
#
# def find_comp_in_projfiles(package_files, componentid):
#     comp_ns, comp_name, version = parse_component_id(componentid)
#
#     for package_file in package_files:
#         if comp_ns == 'npmjs' and package_file.endswith('package-lock.json'):
#             # Need to skip package-lock.json if component exists in package.json
#             # print('DEBUG: skipping package-lock.json')
#             continue
#         line = line_num_for_phrase_in_file(comp_name, version, package_file, comp_ns)
#         if line > 0:
#             globals.printdebug(f"DEBUG: '{comp_name}': PKG file'{package_file}' Line {line}")
#             return remove_cwd_from_filename(package_file), line
#
#     return "Unknown", 0


def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    newcomps = []
    complist = []
    for comp in comps['items']:
        if 'componentVersionName' not in comp:
            continue
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if comp['ignored'] is False and cname not in complist:
            newcomps.append(comp)
            complist.append(cname)
    return newcomps


def get_projver(bd, projname, vername):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    # projects = bd.get_resource('projects', params=params)
    for proj in projects['items']:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                print(f"BD-Scan-Action: INFO: Project '{projname}' Version '{vername}' found - will compare against "
                      f"this project")
                return ver['_meta']['href']
    print(f"BD-Scan-Action: WARN: Version '{vername}' does not exist in project '{projname}' - will skip checking "
          f"previous full scan")
    return ''


def get_detect_jar():
    if globals.detect_jar != '' and os.path.isfile(globals.detect_jar):
        return globals.detect_jar

    detect_jar_download_dir = os.getenv('DETECT_JAR_DOWNLOAD_DIR')
    jdir = ''
    if detect_jar_download_dir is None or not os.path.isdir(detect_jar_download_dir):
        jdir = os.path.join(str(Path.home()), "synopsys-detect")
        if not os.path.isdir(jdir):
            os.mkdir(jdir)
        jdir = os.path.join(jdir, 'download')
        if not os.path.isdir(jdir):
            os.mkdir(jdir)
        # outfile = os.path.join(dir, "detect7.jar")

    url = "https://sig-repo.synopsys.com/api/storage/bds-integrations-release/com/synopsys/integration/\
synopsys-detect?properties=DETECT_LATEST_7"
    r = requests.get(url, allow_redirects=True)
    if not r.ok:
        print('BD-Scan-Action: ERROR: Unable to load detect config {}'.format(r.reason))
        return ''

    rjson = r.json()
    if 'properties' in rjson and 'DETECT_LATEST_7' in rjson['properties']:
        djar = rjson['properties']['DETECT_LATEST_7'][0]
        if djar != '':
            fname = djar.split('/')[-1]
            jarpath = os.path.join(jdir, fname)
            if os.path.isfile(jarpath):
                globals.detect_jar = jarpath
                return jarpath
            print('BD-Scan-Action: INFO: Downloading detect jar file')

            j = requests.get(djar, allow_redirects=True)
            # if globals.proxy_host != '' and globals.proxy_port != '':
            #     j.proxies = {'https': '{}:{}'.format(globals.proxy_host, globals.proxy_port),}
            if j.ok:
                open(jarpath, 'wb').write(j.content)
                if os.path.isfile(jarpath):
                    globals.detect_jar = jarpath
                    return jarpath
    print('BD-Scan-Action: ERROR: Unable to download detect jar file')
    return ''


# def attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, connectopts, bd, upgrade_indirect, upgrade_major):
#     # create a pom.xml with all possible future direct_deps versions
#     # run rapid scan to check
#     # print(f'Vuln Deps = {json.dumps(deps_list, indent=4)}')
#
#     get_detect = True
#     if detect_jar != '' and os.path.isfile(detect_jar):
#         get_detect = False
#     elif globals.detect_jar != '' and os.path.isfile(detect_jar):
#         get_detect = False
#         detect_jar = globals.detect_jar
#
#     if get_detect:
#         detect_jar = get_detect_jar()
#
#     # dirname = "snps-upgrade-" + direct_name + "-" + direct_version
#     dirname = tempfile.TemporaryDirectory()
#     # os.mkdir(dirname)
#     origdir = os.getcwd()
#     os.chdir(dirname.name)
#
#     if pm == 'npm':
#         good_upgrades_dict = NpmUtils.attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, connectopts, bd,
#                                                                upgrade_indirect, upgrade_major)
#     elif pm == 'maven':
#         good_upgrades_dict = MavenUtils.attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, connectopts, bd,
#                                                                  upgrade_indirect, upgrade_major)
#     elif pm == 'nuget':
#         good_upgrades_dict = NugetUtils.attempt_indirect_upgrade(deps_list, upgrade_dict, detect_jar, connectopts, bd,
#                                                                  upgrade_indirect, upgrade_major)
#     else:
#         globals.printdebug(f'Cannot provide upgrade guidance for namepsace {pm}')
#         os.chdir(origdir)
#         dirname.cleanup()
#         return 0, None
#
#     os.chdir(origdir)
#     dirname.cleanup()
#
#     return good_upgrades_dict
#
#
# def normalise_dep(pm, compid):
#     # print('utils_upgrade_indirect()')
#     if pm == 'npmjs' or pm == 'npm':
#         return NpmUtils.normalise_dep(compid)
#     elif pm == 'maven':
#         return MavenUtils.normalise_dep(compid)
#     elif pm == 'nuget':
#         return NugetUtils.normalise_dep(compid)
#     else:
#         return ''


# def check_version_is_release(ver):
#     #
#     # 0. Check for training string for pre-releases
#     # 1. Replace separator chars
#     # 2. Check number of segments
#     # 3. Normalise to 3 segments
#     tempver = ver.lower()
#
#     for cstr in [
#         'alpha', 'beta', 'milestone', 'rc', 'cr', 'dev', 'nightly', 'snapshot', 'preview', 'prerelease', 'pre'
#     ]:
#         if tempver.find(cstr) != -1:
#             return None
#
#     arr = tempver.split('.')
#     if len(arr) == 3:
#         newver = tempver
#     elif len(arr) == 0:
#         return None
#     elif len(arr) > 3:
#         newver = '.'.join(arr[0:3])
#     elif len(arr) == 2:
#         newver = '.'.join(arr[0:2]) + '.0'
#     elif len(arr) == 1:
#         newver = f'{arr[0]}.0.0'
#     else:
#         return None
#
#     try:
#         tempver = semver.VersionInfo.parse(newver)
#     except Exception as e:
#         return None
#
#     return tempver


def process_scan(scan_folder, bd):
    bdio_graph, bdio_projects = bdio.get_bdio_dependency_graph(scan_folder)

    if len(bdio_projects) == 0:
        print("BD-Scan-Action: ERROR: Unable to find base project in BDIO file")
        sys.exit(1)

    rapid_scan_data = bdoutput.get_rapid_scan_results(scan_folder, bd)

    if rapid_scan_data is None or 'items' not in rapid_scan_data:
        return None, None, None

    # dep_dict, direct_deps_to_upgrade, pm = BlackDuckOutput.process_rapid_scan(rapid_scan_data['items'], incremental,
    dep_dict, dirdeps_to_upgrade = bdoutput.process_rapid_scan(
        rapid_scan_data['items'], bdio_graph, bdio_projects)

    # dirdeps_to_upgrade.check_projfiles()
    dirdeps_to_upgrade.get_children(dep_dict)

    return rapid_scan_data, dep_dict, dirdeps_to_upgrade


# def find_upgrade_versions(comp, upgrade_major):
#     # Clean & check the dependency string
#     # moddep = comp.compid.replace(':', '@').replace('/', '@')
#     # a_dirdep = moddep.split('@')
#     # if len(a_dirdep) < 3:
#     #     return
#     # origin = a_dirdep[0]
#     # component_name = arr[1]
#     # current_version = a_dirdep[-1]
#     v_curr = check_version_is_release(comp.version)
#     if v_curr is None:
#         return
#
#     future_vers = []
#     for ver, url in comp.versions[::-1]:
#         v_ver = check_version_is_release(ver)
#         if v_ver is None:
#             continue
#
#         # Check if entry exists in origins_dict
#         id = f"{comp.compid}/{ver}"
#         if id in comp.origins:
#             for over in comp.origins[id]:
#                 if 'originName' in over and 'originId' in over and over['originName'] == comp.ns:
#                     a_over = over['originId'].split(':')
#                     if a_over[0] == a_dirdep[1] and a_over[1] == a_dirdep[2]:
#                         future_vers.append([ver, url])
#                         break
#         # if len(comp.origins) > 0 and ver in comp.origins.keys():
#         #     for over in comp.origins[id]:
#
#     def find_next_ver(verslist, major, minor, patch):
#         foundver = ''
#         found_rels = [1000, -1, -1]
#
#         for ver, url in verslist:
#             v_ver = check_version_is_release(ver)
#             if major < v_ver.major < found_rels[0]:
#                 found_rels = [v_ver.major, v_ver.minor, v_ver.patch]
#                 foundver = ver
#             elif v_ver.major == major:
#                 if v_ver.minor > found_rels[1] and v_ver.minor > minor:
#                     found_rels = [major, v_ver.minor, v_ver.patch]
#                     foundver = ver
#                 elif v_ver.minor == found_rels[1] and v_ver.patch > found_rels[2] and v_ver.patch > patch:
#                     found_rels = [major, v_ver.minor, v_ver.patch]
#                     foundver = ver
#
#         return foundver, found_rels[0]
#
#     #
#     # Find the initial upgrade (either latest in current version major range or guidance_short)
#     v_guidance_short = check_version_is_release(comp.upgradeguidance[0])
#     v_guidance_long = check_version_is_release(comp.upgradeguidance[1])
#     foundvers = []
#     if v_guidance_short is None:
#         # Find final version in current major range
#         verstring, guidance_major_last = find_next_ver(future_vers, v_curr.major, v_curr.minor, v_curr.patch)
#     else:
#         verstring = comp.upgradeguidance[0]
#         guidance_major_last = v_guidance_short.major + 1
#     if verstring != '':
#         foundvers.append(verstring)
#
#     if v_guidance_long is None:
#         # Find final minor version in next major range
#         verstring, guidance_major_last = find_next_ver(future_vers, guidance_major_last, -1, -1)
#     else:
#         verstring = comp.upgradeguidance[1]
#         guidance_major_last = v_guidance_long.major
#     if verstring != '' and upgrade_major:
#         foundvers.append(verstring)
#
#     if upgrade_major:
#         while len(foundvers) <= 3:
#             verstring, guidance_major_last = find_next_ver(future_vers, guidance_major_last + 1, -1, -1)
#             if verstring == '':
#                 break
#             foundvers.append(verstring)
#
#     return foundvers
