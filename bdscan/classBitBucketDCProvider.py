import json
import random
import re
import os
# import shutil
import sys
# import tempfile
import requests

from bdscan import classSCMProvider
from bdscan import globals

# from bdscan import utils

class BitBucketDCProvider(classSCMProvider.SCMProvider):
    def __init__(self):
        super().__init__()
        self.scm = 'bitbucket-dc'
        self.bb_url = ''
        self.bb_username = ''
        self.bb_password = ''
        self.bb_project = ''
        self.bb_repo = ''
        self.bb_ref = ''
        self.bb_branch = ''
        self.bb_pull_number = ''

    def init(self):
        globals.printdebug(f"DEBUG: Initializing BitBucketDC SCM Provider")

        self.bb_url = os.getenv("BITBUCKET_URL")
        self.bb_username = os.getenv("BITBUCKET_USERNAME")
        self.bb_password = os.getenv("BITBUCKET_PASSWORD")
        self.bb_project = os.getenv("BITBUCKET_PROJECT")
        self.bb_repo = os.getenv("BITBUCKET_REPO")
        self.bb_ref = os.getenv("BITBUCKET_REF")
        globals.printdebug(f'BITBUCKET_REF={self.bb_ref}')
        self.bb_branch = os.getenv("BITBUCKET_BRANCH")
        self.bb_pull_number = os.getenv("BITBUCKET_PULL_NUMBER")

        if not self.bb_url or not self.bb_username or not self.bb_password or not self.bb_project \
                or not self.bb_repo or not self.bb_ref or not self.bb_branch:
            print("BD-Scan-Action: ERROR: Cannot find BITBUCKET_URL, BITBUCKET_USERNAME, BITBUCKET_PASSWORD, "
                  "BITBUCKET_PROJECT, BITBUCKET_REF and/or BITBUCKET_BRANCH "
                  "in the environment - are you running from a BitBucket pipeline?")
            sys.exit(1)

        return True

    def comp_commit_file_and_create_fixpr(self, comp, files_to_patch):
        if len(files_to_patch) == 0:
            print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
            return False

        new_branch_seed = '%030x' % random.randrange(16 ** 30)
        # new_branch_seed = secrets.token_hex(15)
        new_branch_name = self.bb_branch + "-snps-fix-pr-" + new_branch_seed

        globals.printdebug(f"DEBUG: Create branch '{new_branch_name}'")

        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/branches"

        data = json.dumps({
            "name": new_branch_name,
            "startPoint": self.bb_ref
        })
        r = requests.post(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                          data=data)

        if (r.status_code > 250):
            print(f"ERROR: Unable to create BitBucket branch name={new_branch_name} ({r.status_code}:")
            print(r.json())
            sys.exit(1)

        commit_message = f"Update {comp.name} to fix known security vulnerabilities"

        # for file_to_patch in globals.files_to_patch:
        for pkgfile in files_to_patch:
            globals.printdebug(f"DEBUG: Get SHA for file '{pkgfile}'")
            # orig_contents = repo.get_contents(pkgfile)

            # print(os.getcwd())
            globals.printdebug(f"DEBUG: Upload file '{pkgfile}'")
            try:
                with open(files_to_patch[pkgfile], 'r') as fp:
                    new_contents = fp.read()
            except Exception as exc:
                print(f"BD-Scan-Action: ERROR: Unable to open package file '{files_to_patch[pkgfile]}'"
                      f" - {str(exc)}")
                return False

            globals.printdebug(f"DEBUG: Update file '{pkgfile}' with commit message '{commit_message}'")

            # headers = {'content-type': 'application/json'}
            headers = {}

            bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/browse/{pkgfile}"

            data = {
                "branch": new_branch_name,
                "content": new_contents,
                "message": commit_message,
                "sourceCommitId": self.bb_ref
            }
            data_json = json.dumps(data)
            print(f"DEBUG: url={bb_url} data={data} headers={headers}")
            r = requests.put(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                             files=data)

            if (r.status_code > 250):
                print(f"ERROR: Unable to upload BitBucket file name={pkgfile} ({r.status_code})")
                sys.exit(1)

            print(f"DEBUG: Committed file {pkgfile}")

        pr_body = f"\n# Synopsys Black Duck Auto Pull Request\n" \
                  f"Upgrade {comp.name} from version {comp.version} to " \
                  f"{comp.goodupgrade} in order to fix security vulnerabilities:\n\n"

        pr_body = pr_body + comp.longtext_md()

        globals.printdebug(f"DEBUG: Submitting pull request:")
        globals.printdebug(pr_body)

        pr_create_data = {
            "title": f"Black Duck: Upgrade {comp.name} to version "
                     f"{comp.goodupgrade} to fix known security vulnerabilities",
            "description": pr_body,
            "state": "OPEN",
            "open": True,
            "closed": False,
            "fromRef": {
                "id": f"refs/heads/{new_branch_name}",
                "name": None,
                "project": {
                    "key": self.bb_project
                }
            },
            "toRef": {
                "id": f"refs/heads/{self.bb_branch}",
                "name": None,
                "project": {
                    "key": self.bb_project
                }
            },
            "locked": False
        }

        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests"

        print(f"DEBUG: url={bb_url} data={data_json} headers={headers}")
        r = requests.post(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                          json=pr_create_data)

        if (r.status_code > 250):
            print(f"ERROR: Unable to create BitBucket pull request for branch={new_branch_name} ({r.status_code}):")
            print(r.json())
            sys.exit(1)

        print(f"DEBUG: Created PR: {r.json()}")

        return True

    def comp_fix_pr(self, comp):
        pulls = self.bitbucket_get_pull_requests()

        ret = True
        globals.printdebug(f"DEBUG: Fix '{comp.name}' version '{comp.version}' in "
                           f"file '{comp.projfiles}' using ns '{comp.ns}' to version "
                           f"'{comp.goodupgrade}'")

        pull_request_title = f"Black Duck: Upgrade {comp.name} to version " \
                             f"{comp.goodupgrade} to fix known security vulnerabilities"
        if pull_request_title in pulls:
            globals.printdebug(f"DEBUG: Skipping pull request for {comp.name}' version "
                               f"'{comp.goodupgrade} as it is already present")
            return

        files_to_patch = comp.do_upgrade_dependency()

        if len(files_to_patch) == 0:
            print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
            return False

        if not self.comp_commit_file_and_create_fixpr(comp, files_to_patch):
            ret = False
        return ret

    def pr_comment(self, comment):
        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests/{self.bb_pull_number}/activities?limit=1"

        isLastPage = False
        nextPageStart = 0
        pr_comments = []
        while isLastPage == False:
            print(f"DEBUG: url={bb_url} headers={headers}")
            r = requests.get(bb_url + f"&start={nextPageStart}", verify=False,
                             auth=(self.bb_username, self.bb_password), headers=headers)

            if (r.status_code > 250):
                print(
                    f"ERROR: Unable to get BitBucket pull request activities number={self.bb_pull_number} ({r.status_code}):")
                print(r.json())
                sys.exit(1)

            print(f"DEBUG: Got PR Comments: {r.json()}")

            for pr_comment in r.json()['values']:
                pr_comments.append(pr_comment)

            if 'nextPageStart' in r.json():
                nextPageStart = r.json()['nextPageStart']
            if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
                isLastPage = True

        if globals.debug: print(f"DEBUG: Got All PR Comments: {pr_comments}")

        existing_comment = None
        existing_comment_version = 0
        # Check if existing comment
        for pr_comment in pr_comments:
            if "comment" not in pr_comment: continue
            globals.printdebug(f"DEBUG: Issue comment={pr_comment['comment']['text']}")
            if "Synopsys Black Duck - Security" in pr_comment['comment']['text']:
                existing_comment = pr_comment['comment']['id']
                existing_comment_version = pr_comment['comment']['version']

        comments_markdown = f"# {globals.comment_on_pr_header}\n" + f"\n{comment}"

        if len(comments_markdown) > 32767:
            comments_markdown = comments_markdown[:32767]

        if existing_comment is not None:
            globals.printdebug(
                f"DEBUG: Update/edit existing comment for PR #{self.bb_pull_number}\n{comments_markdown}")

            globals.printdebug(f"DEBUG: Create new comment for PR #{self.bb_pull_number}")

            headers = {'content-type': 'application/json'}

            bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests/{self.bb_pull_number}/comments/{existing_comment}"

            data = {
                "text": comments_markdown,
                "version": existing_comment_version
            }
            r = requests.put(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                             json=data)

            if (r.status_code > 250):
                print(
                    f"ERROR: Unable to update BitBucket PR comment on pull={self.bb_pull_number} comment={existing_comment} ({r.status_code}:")
                print(r.json())
                print(r.text())
                sys.exit(1)

        else:
            globals.printdebug(f"DEBUG: Create new comment for PR #{self.bb_pull_number}")

            headers = {'content-type': 'application/json'}

            bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests/{self.bb_pull_number}/comments"

            data = {
                "text": comments_markdown
            }

            r = requests.post(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                              json=data)

            if (r.status_code > 250):
                print(
                    f"ERROR: Unable to create BitBucket PR comment on pull={self.bb_pull_number} ({r.status_code}:")
                print(r.json())
                sys.exit(1)

        if (os.path.exists(globals.args.code_insights)):
            globals.printdebug(f"DEBUG: Reading code insights report and annotations")
            file_base = os.path.splitext(globals.args.code_insights)[0]
            file_report = globals.args.code_insights
            file_annotations = file_base + "-annotations.json"

            with open(file_report) as f:
                report_json = json.load(f)
            with open(file_annotations) as f:
                annotations_json = json.load(f)

            # curl --verbose \
            # -H "Content-type: application/json" \
            # -H "Authorization: Bearer MTU5MTU1NzIyMzU4Oh+a6gzAaBSBkXfOv3DDHq4nRJ4w" \
            # -X PUT \
            # -d @synopsys-bitbucket-sast-report.json \
            # "$BBS_URL/rest/insights/latest/projects/$BBS_PROJECT/repos/$BBS_REPO/commits/$COMMIT_ID/reports/$REPORT_KEY"

            report_key = "com.synopsys.blackduck.report"
            bb_url = f"{self.bb_url}/rest/insights/latest/projects/{self.bb_project}/repos/{self.bb_repo}/commits/{self.bb_ref}/reports/{report_key}"

            globals.printdebug(f"DEBUG: DELETE Code Insights report url={bb_url} headers={headers}")
            r = requests.delete(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers)
            if (r.status_code > 250):
                print(f"ERROR: Unable to delete existing BitBucket code insights report: ({r.status_code})")
                sys.exit(1)


            globals.printdebug(f"DEBUG: PUT Code Insights report url={bb_url} data={report_json} headers={headers}")
            r = requests.put(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                             json=report_json)

            if (r.status_code > 250):
                print(f"ERROR: Unable to upload BitBucket code insights report: ({r.status_code})")
                sys.exit(1)

            print(f"DEBUG: Uploaded code insights report")

            #
            # echo ----------------------------------
            # echo Create annotations
            # echo ----------------------------------
            # # Create the annotations
            # curl --verbose \
            # -H "Content-type: application/json" \
            # -H "Authorization: Bearer MTU5MTU1NzIyMzU4Oh+a6gzAaBSBkXfOv3DDHq4nRJ4w" \
            # -X POST \
            # -d @synopsys-bitbucket-sast-annotations.json \
            # "$BBS_URL/rest/insights/latest/projects/IB/repos/insecure-bank/commits/$COMMIT_ID/reports/$REPORT_KEY/annotations"

            bb_url = f"{self.bb_url}/rest/insights/latest/projects/{self.bb_project}/repos/{self.bb_repo}/commits/{self.bb_ref}/reports/{report_key}/annotations"

            globals.printdebug(f"DEBUG: POST Code Insights annotations url={bb_url} data={annotations_json} headers={headers}")
            r = requests.post(bb_url, verify=False, auth=(self.bb_username, self.bb_password), headers=headers,
                             json=annotations_json)

            if (r.status_code > 250):
                print(f"ERROR: Unable to upload BitBucket code insights annotations: ({r.status_code})")
                sys.exit(1)

            print(f"DEBUG: Uploaded code insights annotations")



        return True

    def set_commit_status(self, is_ok):
        globals.printdebug(f"DEBUG: No commit status for BitBucket.")
        return True

    def check_files_in_pull_request(self):
        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests/{self.bb_pull_number}/changes?limit=1"

        isLastPage = False
        nextPageStart = 0
        changes = []
        while isLastPage == False:
            print(f"DEBUG: url={bb_url} headers={headers}")
            r = requests.get(bb_url + f"&start={nextPageStart}", verify=False,
                             auth=(self.bb_username, self.bb_password), headers=headers)

            if (r.status_code > 250):
                print(f"ERROR: Unable to get BitBucket PR change history for ref={self.bb_ref} ({r.status_code}:")
                print(r.json())
                sys.exit(1)

            if globals.debug: print(f"DEBUG: BitBucket response={json.dumps(r.json(), indent=4)}")

            for change in r.json()['values']:
                changes.append(change)

            if 'nextPageStart' in r.json():
                nextPageStart = r.json()['nextPageStart']
            if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
                isLastPage = True

        print(f"DEBUG: Full list of changes={changes}")

        found = False
        for commit_file in changes:
            if os.path.basename(commit_file['path']['name']) in globals.pkg_files:
                found = True
                break

            if os.path.splitext(commit_file['path']['name'])[-1] in globals.pkg_exts:
                found = True
                break

        return found


    def check_files_in_commit(self):
        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/commits/{self.bb_ref}/changes?limit=10"

        isLastPage = False
        nextPageStart = 0
        commits = []
        while isLastPage == False:
            print(f"DEBUG: url={bb_url} headers={headers}")
            r = requests.get(bb_url + f"&start={nextPageStart}", verify=False,
                             auth=(self.bb_username, self.bb_password), headers=headers)

            if (r.status_code > 250):
                print(f"ERROR: Unable to get BitBucket PR commit history for ref={self.bb_ref} ({r.status_code}:")
                print(r.json())
                sys.exit(1)

            if globals.debug: print(f"DEBUG: BitBucket response={json.dumps(r.json(), indent=4)}")

            for commit in r.json()['values']:
                commits.append(commit)

            if 'nextPageStart' in r.json():
                nextPageStart = r.json()['nextPageStart']
            if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
                isLastPage = True

        print(f"DEBUG: Full list of commits={commits}")

        found = False
        for commit_file in commits:
            if globals.debug: print(f"DEBUG: commit_file={commit_file['path']['name']}")
            if os.path.basename(commit_file['path']['name']) in globals.pkg_files:
                found = True
                break

            if os.path.splitext(commit_file['path']['name'])[-1] in globals.pkg_exts:
                found = True
                break

        return found

    def bitbucket_get_pull_requests(self):
        globals.printdebug(f"DEBUG: Index pull requests, Look up BitBucket repo '{self.bb_repo}'")

        headers = {'content-type': 'application/json'}

        bb_url = f"{self.bb_url}/rest/api/1.0/projects/{self.bb_project}/repos/{self.bb_repo}/pull-requests?limit=1"

        isLastPage = False
        nextPageStart = 0
        pulls = []
        while isLastPage == False:
            print(f"DEBUG: url={bb_url} headers={headers}")
            r = requests.get(bb_url + f"&start={nextPageStart}", verify=False,
                             auth=(self.bb_username, self.bb_password), headers=headers)

            if (r.status_code > 250):
                print(
                    f"ERROR: Unable to get BitBucket pull request activities number={self.bb_pull_number} ({r.status_code}):")
                print(r.json())
                sys.exit(1)

            print(f"DEBUG: Got PR Comments: {r.json()}")

            for pull in r.json()['values']:
                pulls.append(pull)

            if 'nextPageStart' in r.json():
                nextPageStart = r.json()['nextPageStart']
            if 'isLastPage' in r.json() and r.json()['isLastPage'] == True:
                isLastPage = True

        if globals.debug: print(f"DEBUG: Got all pull requests={pulls}")

        pull_requests = []

        # TODO Should this handle other bases than master?
        for pull in pulls:
            globals.printdebug(f"DEBUG: Pull request number: {pull['id']}: {pull['title']}")
            pull_requests.append(pull['title'])

        return pull_requests