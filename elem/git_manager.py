from git import Repo
from git.repo import fun
import os

class GitManager(object):

    def __init__(self, content_path, content_repo, folder=''):

        if content_path is None:
            self.content_path = os.path.dirname(os.path.realpath(__file__))
            if folder is not '':
                self.content_path += os.path.sep
                self.content_path += folder
        else:
            self.content_path = content_path
        self.content_path = os.path.relpath(self.content_path)
        self.content_repo = content_repo

    def refresh_repository(self):
        repo = None
        origin = None
        if fun.is_git_dir(self.content_path):
            repo = Repo(self.content_path)
        else:
            repo = Repo.init(self.content_path)

        try:
            origin = repo.remote('origin')
        except ValueError:
            origin = repo.create_remote('origin', self.content_repo)
        origin.fetch()

        if 'master' not in repo.heads:
            repo.create_head('master', origin.refs.master)
        repo.heads.master.set_tracking_branch(origin.refs.master)
        repo.heads.master.checkout()
        origin.pull()
