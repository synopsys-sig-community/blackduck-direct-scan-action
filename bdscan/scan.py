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

    rapid_scan_data, dep_dict, direct_deps_to_upgrade = utils.process_scan(globals.args.output_folder, globals.bd)

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


def main_process(output, runargs):
    globals.scm_provider = None

    if globals.debug > 0:
        print('\n'.join([f'{k}: {v}' for k, v in sorted(os.environ.items())]))

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

    if not globals.scm_provider.init():
        print('BD-Scan-Action: No action defined - nothing to do')
        sys.exit(0)

    if not globals.args.no_files_check:
        if globals.args.fix_pr and not globals.scm_provider.check_files_in_commit():
            print('BD-Scan-Action: No package manager changes in commit - skipping dependency analysis')
            sys.exit(0)

        if globals.args.comment_on_pr and not globals.scm_provider.check_files_in_pull_request():
            print('BD-Scan-Action: No package manager changes in pull request - skipping dependency analysis')
            sys.exit(0)

    # Run DETECT
    if globals.args.incremental_results and globals.args.mode == "rapid":
        runargs.append("--detect.blackduck.rapid.compare.mode=BOM_COMPARE")

    if globals.args.mode == "intelligent":
        runargs.append(f"--detect.excluded.directories={globals.args.output_folder}")

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
    globals.bd = Client(token=globals.args.bd_token,
                        base_url=globals.args.bd_url,
                        verify=globals.args.bd_trustcert,
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
    asyncdata.get_data_async(direct_deps_to_upgrade, globals.bd, globals.args.bd_trustcert)

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
        if len(direct_deps_to_upgrade.components) > 0:
            comment = direct_deps_to_upgrade.get_comments(globals.args.incremental_results)
            if globals.scm_provider.pr_comment(comment):
                status_ok = False
                print('BD-Scan-Action: Created comment on existing pull request')
            else:
                print('BD-Scan-Action: ERROR: Unable to create comment on existing pull request')
                status_ok = False
        else:
            print('BD-Scan-Action: No upgrades available for Comment on PR - skipping')
            status_ok = True

        globals.scm_provider.set_commit_status(status_ok)
        ret_status = status_ok

    if os.path.isdir(globals.args.output_folder) and os.path.isdir(os.path.join(globals.args.output_folder, "runs")):
        shutil.rmtree(globals.args.output_folder, ignore_errors=False, onerror=None)
        print(f'BD-Scan-Action: INFO: Cleaning up folder {globals.args.output_folder}')

    if ret_status:
        print('BD-Scan-Action: Done - Returning OK')
        sys.exit(0)
    else:
        print('BD-Scan-Action: Done - Returning FAIL')
        sys.exit(1)
