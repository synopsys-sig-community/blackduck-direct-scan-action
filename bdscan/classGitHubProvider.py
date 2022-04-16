import random
import re
import os
# import shutil
import sys
# import tempfile

from bdscan import classSCMProvider
from bdscan import globals

# from bdscan import utils

from github import Github


class GitHubProvider(classSCMProvider.SCMProvider):
    def __init__(self):
        super().__init__()
        self.scm = 'github'
        self.github_token = ''
        self.github_repo = ''
        self.github_ref = ''
        self.github_api_url = ''
        self.github_sha = ''
        self.github_ref_type = ''
        self.github_ref_name = ''
        self.github_event_name = ''

    def init(self):
        globals.printdebug(f"DEBUG: Initializing GitHub SCM Provider")
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_repo = os.getenv("GITHUB_REPOSITORY")
        self.github_ref = os.getenv("GITHUB_REF")
        globals.printdebug(f'GITHUB_REF={self.github_ref}')
        self.github_api_url = os.getenv("GITHUB_API_URL")
        self.github_sha = os.getenv("GITHUB_SHA")
        globals.printdebug(f'GITHUB_SHA={self.github_sha}')
        self.github_ref_type = os.getenv("GITHUB_REF_TYPE")
        globals.printdebug(f'GITHUB_REF_TYPE={self.github_ref_type}')
        self.github_ref_name = os.getenv("GITHUB_REF_NAME")
        globals.printdebug(f'GITHUB_REF_NAME={self.github_ref_name}')
        self.github_event_name = os.getenv("GITHUB_EVENT_NAME")
        globals.printdebug(f'GITHUB_EVENT_NAME={self.github_event_name}')

        if not self.github_token or not self.github_repo or not self.github_ref or not self.github_api_url \
                or not self.github_sha:
            print(f'BD-Scan-Action: ERROR: GitHub requires that GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF,'
                  'GITHUB_API_URL, and GITHUB_SHA be set.')
            sys.exit(1)

        # If no action set in options, then use github_event_name to set activity
        if not globals.args.fix_pr and not globals.args.comment_on_pr and not globals.args.sarif:
            if self.github_event_name == 'pull_request':
                globals.args.comment_on_pr = True
            elif self.github_event_name == 'push':
                globals.args.fix_pr = True
            elif self.github_event_name == 'workflow_dispatch':
                return True
            else:
                return False
        elif self.github_event_name is not None and self.github_event_name != '':
            # Check the specified action matches the event_name
            if globals.args.fix_pr and self.github_event_name != 'push':
                return False
            if globals.args.comment_on_pr and self.github_event_name != 'pull_request':
                return False

        return True

    def comp_commit_file_and_create_fixpr(self, g, comp, files_to_patch):
        if len(files_to_patch) == 0:
            print('BD-Scan-Action: WARN: Unable to apply fix patch - cannot determine containing package file')
            return False
        if self.github_ref_type != 'branch':
            print('BD-Scan-Action: WARN: Unable to apply fix patch - github_ref_type is not branch')
            return False

        globals.printdebug(f"DEBUG: Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)
        globals.printdebug(repo)

        globals.printdebug(f"DEBUG: Get HEAD commit from '{self.github_repo}'")
        commit = repo.get_commit('HEAD')
        globals.printdebug(commit)

        new_branch_seed = '%030x' % random.randrange(16 ** 30)
        # new_branch_seed = secrets.token_hex(15)
        new_branch_name = self.github_ref + "-snps-fix-pr-" + new_branch_seed
        globals.printdebug(f"DEBUG: Create branch '{new_branch_name}'")
        ref = repo.create_git_ref("refs/heads/" + new_branch_name, commit.sha)
        globals.printdebug(ref)

        commit_message = f"Update {comp.name} to fix known security vulnerabilities"

        # for file_to_patch in globals.files_to_patch:
        for pkgfile in files_to_patch:
            globals.printdebug(f"DEBUG: Get SHA for file '{pkgfile}'")
            orig_contents = repo.get_contents(pkgfile)

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
            file = repo.update_file(pkgfile, commit_message, new_contents, orig_contents.sha, branch=new_branch_name)

        pr_body = f"\n# Synopsys Black Duck Auto Pull Request\n" \
                  f"Upgrade {comp.name} from version {comp.version} to " \
                  f"{comp.goodupgrade} in order to fix security vulnerabilities:\n\n"

        pr_body = pr_body + comp.longtext_md()
        globals.printdebug(f"DEBUG: Submitting pull request:")
        globals.printdebug(pr_body)
        pr = repo.create_pull(title=f"Black Duck: Upgrade {comp.name} to version "
                                    f"{comp.goodupgrade} fix known security vulerabilities",
                              body=pr_body, head=new_branch_name, base=self.github_ref_name)
        return True

    def comp_fix_pr(self, comp):
        # external
        # fix_pr_node = {
        #     'componentName': comp_name,
        #     'versionFrom': comp_version,
        #     'versionTo': upgrade_ver,
        #     'ns': comp_ns,
        #     'projfiles': pkgfiles,
        #     'comments': [f"## Dependency {comp_name}/{comp_version}\n{shorttext}"],
        #     'comments_markdown': [longtext_md],
        #     'comments_markdown_footer': ''
        # }

        globals.printdebug(f"DEBUG: Connect to GitHub at {self.github_api_url}")
        g = Github(self.github_token, base_url=self.github_api_url)

        pulls = self.github_get_pull_requests(g)

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

        if not self.comp_commit_file_and_create_fixpr(g, comp, files_to_patch):
            ret = False
        return ret

    def pr_comment(self, comment):
        globals.printdebug(f"DEBUG: Connect to GitHub at {self.github_api_url}")
        g = Github(self.github_token, base_url=self.github_api_url)

        globals.printdebug(f"DEBUG: Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)
        globals.printdebug(repo)

        globals.printdebug(f"DEBUG: Look up GitHub ref '{self.github_ref}'")
        # Remove leading refs/ as the API will prepend it on it's own
        # Actually look pu the head not merge ref to get the latest commit so
        # we can find the pull request
        ref = repo.get_git_ref(self.github_ref[5:].replace("/merge", "/head"))
        globals.printdebug(ref)

        # github_sha = ref.object.sha

        pull_number_for_sha = ref.ref.split('/')[2]
        globals.printdebug(f"DEBUG: Pull request #{pull_number_for_sha}")

        if pull_number_for_sha is None or not pull_number_for_sha.isnumeric():
            print(f"BD-Scan-Action: ERROR: Unable to find pull request #{pull_number_for_sha}")
            return False
        pull_number_for_sha = int(pull_number_for_sha)

        pr = repo.get_pull(pull_number_for_sha)

        pr_comments = repo.get_issues_comments(sort='updated', direction='desc')
        existing_comment = None
        for pr_comment in pr_comments:
            globals.printdebug(f"DEBUG: Issue comment={pr_comment.body}")
            arr = re.split('[/#]', pr_comment.html_url)
            if len(arr) >= 7:
                this_pullnum = arr[6]
                if not this_pullnum.isnumeric():
                    continue
                this_pullnum = int(this_pullnum)
            else:
                continue
            if this_pullnum == pull_number_for_sha and globals.comment_on_pr_header in pr_comment.body:
                globals.printdebug(f"DEBUG: Found existing comment")
                existing_comment = pr_comment

        # Tricky here, we want everything all in one comment. So prepare a header, then append each of the comments and
        # create a comment
        # comments_markdown = [
        #     "| Component | Vulnerability | Severity |  Policy | Description | Current Ver | Upgrade to |",
        #     "| --- | --- | --- | --- | --- | --- | --- |"
        # ]
        #
        # for comment in globals.comment_on_pr_comments:
        #     comments_markdown.append(comment)
        comments_markdown = f"# {globals.comment_on_pr_header}\n{comment}"

        if len(comments_markdown) > 65535:
            comments_markdown = comments_markdown[:65535]

        if existing_comment is not None:
            globals.printdebug(
                f"DEBUG: Update/edit existing comment for PR #{pull_number_for_sha}\n{comments_markdown}")
            # existing_comment.edit("\n".join(comments_markdown))
            existing_comment.edit(comments_markdown)
        else:
            globals.printdebug(f"DEBUG: Create new comment for PR #{pull_number_for_sha}")
            self.github_create_pull_request_comment(g, pr, comments_markdown)
            # JC: Commenting out the below, we identified this earlier
            # issue = repo.get_issue(number=pr.number)
            # issue.create_comment(comments_markdown)
        return True

    def set_commit_status(self, is_ok):
        globals.printdebug(f"DEBUG: Set check status for commit '{self.github_sha}', connect to GitHub at "
                           f"{self.github_api_url}")
        g = Github(self.github_token, base_url=self.github_api_url)

        globals.printdebug(f"DEBUG: Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)
        globals.printdebug(repo)

        if not is_ok:
            status = repo.get_commit(sha=self.github_sha).create_status(
                state="failure",
                target_url="https://synopsys.com/software",
                description="Black Duck security scan found vulnerabilities",
                context="Synopsys Black Duck"
            )
        else:
            status = repo.get_commit(sha=self.github_sha).create_status(
                state="success",
                target_url="https://synopsys.com/software",
                description="Black Duck security scan clear from vulnerabilities",
                context="Synopsys Black Duck"
            )

        globals.printdebug(f"DEBUG: Status:")
        globals.printdebug(status)
        return

    def check_files_in_pull_request(self):
        globals.printdebug(f"DEBUG: Connect to GitHub at {self.github_api_url}")
        g = Github(self.github_token, base_url=self.github_api_url)

        globals.printdebug(f"DEBUG: Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)
        globals.printdebug(repo)

        globals.printdebug(f"DEBUG: Look up GitHub ref '{self.github_ref}'")
        # Remove leading refs/ as the API will prepend it on it's own
        # Actually look pu the head not merge ref to get the latest commit so
        # we can find the pull request
        ref = repo.get_git_ref(self.github_ref[5:].replace("/merge", "/head"))
        globals.printdebug(ref)

        # github_sha = ref.object.sha

        # pulls = repo.get_pulls(state='open', sort='created', base=repo.default_branch, direction="desc")
        # pr = None
        # pr_commit = None
        globals.printdebug(f"DEBUG: Pull requests:")

        pull_number_for_sha = None
        m = re.search('pull/(.+?)/', self.github_ref)
        if m:
            pull_number_for_sha = int(m.group(1))

        globals.printdebug(f"DEBUG: Pull request #{pull_number_for_sha}")

        if pull_number_for_sha is None:
            print(f"ERROR: Unable to find pull request #{pull_number_for_sha}, must be operating on a push or "
                  f"other event")
            sys.exit(1)

        pr = repo.get_pull(pull_number_for_sha)

        found = False
        for pr_commit in pr.get_commits():
            for commit_file in pr_commit.raw_data['files']:
                if os.path.basename(commit_file['filename']) in globals.pkg_files:
                    found = True
                    break

                if os.path.splitext(commit_file['filename'])[-1] in globals.pkg_exts:
                    found = True
                    break

        return found

    def check_files_in_commit(self):
        g = Github(self.github_token, base_url=self.github_api_url)
        repo = g.get_repo(self.github_repo)
        commit = repo.get_commit('HEAD')
        globals.printdebug(commit)

        # if self.github_event_name == 'push' and commit.commit.message.find('Synopsys Black Duck Auto Pull
        # Request') > 0:
        m = re.search('Merge pull request #[0-9]* from .*/.*-snps-fix-pr-', commit.commit.message)
        n = re.search('Black Duck: Upgrade', commit.commit.message)
        if m and n:
            # Check if this commit is from a previous run of this action and skip if so
            globals.printdebug(f"DEBUG: Comment {commit.commit.message} encountered - will skip scan")
            return False

        found = False
        for commit_file in commit.files:
            if os.path.basename(commit_file.filename) in globals.pkg_files:
                found = True
                break

            if os.path.splitext(commit_file.filename)[-1] in globals.pkg_exts:
                found = True
                break

        return found

    def github_create_pull_request_comment(self, g, pr, comments_markdown):
        globals.printdebug(f"DEBUG: Entering github_create_pull_request_comment comments_markdown={comments_markdown}")

        globals.printdebug(f"DEBUG: Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)

        body = comments_markdown

        issue = repo.get_issue(number=pr.number)

        globals.printdebug(f"DEBUG: Create pull request review comment for pull request #{pr.number} "
                           f"with the following body:\n{body}")
        issue.create_comment(body)

    def github_get_pull_requests(self, g):
        globals.printdebug(f"DEBUG: Index pull requests, Look up GitHub repo '{self.github_repo}'")
        repo = g.get_repo(self.github_repo)
        globals.printdebug(repo)

        pull_requests = []

        # TODO Should this handle other bases than master?
        pulls = repo.get_pulls(state='open', sort='created', base='master', direction="desc")
        for pull in pulls:
            globals.printdebug(f"DEBUG: Pull request number: {pull.number}: {pull.title}")
            pull_requests.append(pull.title)

        return pull_requests
