# import re
# import os
# import semver
# from operator import itemgetter
#
# from bdscan import utils

class SCMProvider:

    def __init__(self):
        self.scm = "generic"

    def set_data(self, field_name, data):
        if field_name == 'scm':
            self.scm = data
        return True

    def init(self):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return

    def comp_fix_pr(self, comp):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return

    def pr_comment(self, comment):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return

    def set_commit_status(self, is_ok):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return

    def check_files_in_pull_request(self):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return

    def check_files_in_commit(self):
        print(f'BD-Scan-Action: WARNING: Generic SCM provider does not support any actions, please configure provider')
        return
