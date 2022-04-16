import base64
import json
import random
# import re
import os
# import shutil
import sys
# import tempfile

from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication

from bdscan import classSCMProvider
from bdscan import globals

# from bdscan import utils

# import azure
# import azure.devops
import requests
from azure.devops.v6_0.git import GitPushRef, GitRefUpdate, GitPush, GitCommitRef, GitPullRequest, \
    GitPullRequestCommentThread, Comment, GitPullRequestSearchCriteria


class AzureProvider(classSCMProvider.SCMProvider):
    def __init__(self):
        super().__init__()
        self.scm = 'azure'

        self.azure_base_url = ''
        self.azure_api_token = ''
        self.azure_pull_request_id = ''
        self.azure_project = ''
        self.azure_project_id = ''
        self.azure_repo_id = ''
        self.azure_build_source_branch = ''

        self.azure_credentials = None
        self.azure_connection = None

        self.azure_git_client = None

    def init(self):
        globals.printdebug(f"DEBUG: Initializing Azure DevOps SCM Provider")

        self.azure_base_url = os.getenv('SYSTEM_COLLECTIONURI')
        self.azure_api_token = os.getenv('SYSTEM_ACCESSTOKEN')
        if not self.azure_api_token:
            self.azure_api_token = os.getenv('AZURE_API_TOKEN')
        self.azure_pull_request_id = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
        self.azure_project = os.getenv('SYSTEM_TEAMPROJECT')
        self.azure_project_id = os.getenv('SYSTEM_TEAMPROJECTID')
        self.azure_repo_id = os.getenv('BUILD_REPOSITORY_ID')
        self.azure_build_source_branch = os.getenv('BUILD_SOURCEBRANCH')

        globals.printdebug(f'DEBUG: Azure DevOps base_url={self.azure_base_url} api_token={self.azure_api_token} '
                           f'pull_request_id={self.azure_pull_request_id} project={self.azure_project} '
                           f'project_id={self.azure_project_id} repo_id={self.azure_repo_id}')

        if not self.azure_base_url or not self.azure_project or not self.azure_repo_id or not self.azure_api_token \
                or not self.azure_project_id:
            print(f'BD-Scan-Action: ERROR: Azure DevOps requires that SYSTEM_COLLECTIONURI, SYSTEM_TEAMPROJECT,'
                  'SYSTEM_TEAMPROJECTID, SYSTEM_ACCESSTOKEN or AZURE_API_TOKEN, and BUILD_REPOSITORY_ID be set.')
            sys.exit(1)

        if globals.args.comment_on_pr and not self.azure_pull_request_id:
            print(f'BD-Scan-Action: ERROR: Azure DevOps requires that SYSTEM_PULLREQUEST_PULLREQUESTID be set'
                  'when operating on a pull request')
            sys.exit(1)

        if globals.args.fix_pr and not self.azure_build_source_branch:
            print(f'BD-Scan-Action: ERROR: Azure DevOps requires that BUILD_SOURCEBRANCH be set'
                  'when operating on a pull request')
            sys.exit(1)

        self.azure_credentials = BasicAuthentication('', self.azure_api_token)
        self.azure_connection = Connection(base_url=self.azure_base_url, creds=self.azure_credentials)

        # Get a client (the "core" client provides access to projects, teams, etc)
        self.azure_git_client = self.azure_connection.clients.get_git_client()

        return True

    def azure_create_branch(self, from_ref, branch_name):
        authorization = str(base64.b64encode(bytes(':' + self.azure_api_token, 'ascii')), 'ascii')

        url = f"{self.azure_base_url}/_apis/git/repositories/{self.azure_repo_id}/refs?api-version=6.0"

        headers = {
            'Authorization': 'Basic ' + authorization
        }

        body = [
            {
                'name': f"refs/heads/{branch_name}",
                'oldObjectId': '0000000000000000000000000000000000000000',
                'newObjectId': from_ref
            }
        ]

        if globals.debug > 0:
            print("DEBUG: perform API Call to ADO: " + url + " : " + json.dumps(body, indent=4, sort_keys=True) + "\n")
        r = requests.post(url, json=body, headers=headers)

        if r.status_code == 200:
            if globals.debug > 0:
                print(f"DEBUG: Success creating branch")
                print(r.text)
            return True
        else:
            print(f"BD-Scan-Action: ERROR: Failure creating branch: Error {r.status_code}")
            print(r.text)
            return False

    def comp_commit_file_and_create_fixpr(self, comp, files_to_patch):
        if len(files_to_patch) == 0:
            print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
            return False

        new_branch_seed = '%030x' % random.randrange(16 ** 30)
        new_branch_name = f"synopsys-enablement-{new_branch_seed}"

        globals.printdebug(f"DEBUG: Get commit for head of {self.azure_build_source_branch}'")

        commits = self.azure_git_client.get_commits(self.azure_repo_id, None)
        head_commit = commits[0]

        globals.printdebug(f"DEBUG: Head commit={head_commit.commit_id}")

        globals.printdebug(f"DEBUG: Creating new ref 'refs/heads/{new_branch_name}'")
        self.azure_create_branch(head_commit.commit_id, new_branch_name)

        gitRefUpdate = GitRefUpdate()
        gitRefUpdate.name = f"refs/heads/{new_branch_name}"
        gitRefUpdate.old_object_id = head_commit.commit_id

        gitPush = GitPush()
        gitPush.commits = []
        gitPush.ref_updates = [gitRefUpdate]

        # for file_to_patch in globals.files_to_patch:
        for pkgfile in files_to_patch:
            globals.printdebug(f"DEBUG: Upload file '{pkgfile}'")
            try:
                with open(files_to_patch[pkgfile], 'r') as fp:
                    new_contents = fp.read()
            except Exception as exc:
                print(f"BD-Scan-Action: ERROR: Unable to open package file '{files_to_patch[pkgfile]}'"
                      f" - {str(exc)}")
                return False

            gitCommitRef = GitCommitRef()
            gitCommitRef.comment = "Added Synopsys pipeline template"
            gitCommitRef.changes = [
                {
                    'changeType': 'edit',
                    'item': {
                        'path': pkgfile
                    },
                    'newContent': {
                        'content': new_contents,
                        'contentType': 'rawText'
                    }
                }
            ]

            gitPush.commits.append(gitCommitRef)

            # globals.printdebug(f"DEBUG: Update file '{pkgfile}' with commit message '{commit_message}'")
            # file = repo.update_file(pkgfile, commit_message, new_contents, orig_contents.sha, branch=new_branch_name)

        push = self.azure_git_client.create_push(gitPush, self.azure_repo_id)

        if not push:
            print(f"BD-Scan-Action: ERROR: Create push failed")
            sys.exit(1)

        pr_title = f"Black Duck: Upgrade {comp.name} to version {comp.goodupgrade} fix known security vulerabilities"
        pr_body = f"\n# Synopsys Black Duck Auto Pull Request\n" \
                  f"Upgrade {comp.name} from version {comp.version} to " \
                  f"{comp.goodupgrade} in order to fix security vulnerabilities:\n\n"

        gitPullRequest = GitPullRequest()
        gitPullRequest.source_ref_name = f"refs/heads/{new_branch_name}"
        gitPullRequest.target_ref_name = self.azure_build_source_branch
        gitPullRequest.title = pr_title
        gitPullRequest.description = pr_body

        pull = self.azure_git_client.create_pull_request(gitPullRequest, self.azure_repo_id)

        if not pull:
            print(f"BD-Scan-Action: ERROR: Create pull request failed")
            sys.exit(1)

        return True

    def comp_fix_pr(self, comp):
        ret = True
        globals.printdebug(f"DEBUG: Fix '{comp.name}' version '{comp.version}' in "
                           f"file '{comp.projfiles}' using ns '{comp.ns}' to version "
                           f"'{comp.goodupgrade}'")

        pull_request_title = f"Black Duck: Upgrade {comp.name} to version " \
                             f"{comp.goodupgrade} to fix known security vulnerabilities"

        search_criteria = None  # GitPullRequestSearchCriteria()

        pulls = self.azure_git_client.get_pull_requests(self.azure_repo_id, search_criteria)
        for pull in pulls:
            if pull_request_title in pull.title:
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
        pr_threads = self.azure_git_client.get_threads(self.azure_repo_id, self.azure_pull_request_id)
        existing_thread = None
        existing_comment = None
        for pr_thread in pr_threads:
            for pr_thread_comment in pr_thread.comments:
                if pr_thread_comment.content and globals.comment_on_pr_header in pr_thread_comment.content:
                    existing_thread = pr_thread
                    existing_comment = pr_thread_comment

        comments_markdown = f"# {globals.comment_on_pr_header}\n{comment}"

        if len(comments_markdown) > 65535:
            comments_markdown = comments_markdown[:65535]

        if existing_comment is not None:
            globals.printdebug(f"DEBUG: Update/edit existing comment for PR #{self.azure_pull_request_id}\n"
                               f"{comments_markdown}")

            pr_thread_comment = Comment()
            pr_thread_comment.parent_comment_id = 0
            pr_thread_comment.content = comments_markdown
            pr_thread_comment.comment_type = 1

            retval = self.azure_git_client.update_comment(pr_thread_comment, self.azure_repo_id,
                                                          self.azure_pull_request_id, existing_thread.id,
                                                          existing_comment.id)

            globals.printdebug(f"DEBUG: Updated thread, retval={retval}")
        else:
            globals.printdebug(f"DEBUG: Create new thread for PR #{self.azure_pull_request_id}")

            pr_thread_comment = Comment()
            pr_thread_comment.parent_comment_id = 0
            pr_thread_comment.content = comments_markdown
            pr_thread_comment.comment_type = 1

            pr_thread = GitPullRequestCommentThread()
            pr_thread.comments = [pr_thread_comment]
            pr_thread.status = 1

            retval = self.azure_git_client.create_thread(pr_thread, self.azure_repo_id, self.azure_pull_request_id)

            globals.printdebug(f"DEBUG: Created thread, retval={retval}")
        return True

    def set_commit_status(self, is_ok):
        globals.printdebug(f"WARNING: Azure DevOps does not support set_commit_status")
        return

    def check_files_in_pull_request(self):
        globals.printdebug(f"WARNING: Azure DevOps does not support querying changed files, returning True")
        found = True
        return found

    def check_files_in_commit(self):
        globals.printdebug(f"WARNING: Azure DevOps does not support querying committed files, returning True")
        found = True
        return found
