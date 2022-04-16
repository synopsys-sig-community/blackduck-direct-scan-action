# import json
import os
import sys
import requests
# import semver
# import tempfile
from pathlib import Path

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


def get_comps(bd, pv):
    comps = get_json(bd, pv + '/components')
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


def get_json(bd, url):
    url += '?limit=1000'
    result = bd.get_json(url)
    all_data = result
    total = result['totalCount']
    downloaded = 1000
    while total > downloaded:
        req_url = f"{url}&offset={downloaded}"
        result = bd.get_json(req_url)
        all_data['items'] = all_data['items'] + result['items']
        downloaded += 1000

    return all_data
