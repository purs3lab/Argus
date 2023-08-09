#    _____ __________  ________ ____ ___  _________
#   /  _  \\______   \/  _____/|    |   \/   _____/
#  /  /_\  \|       _/   \  ___|    |   /\_____  \ 
# /    |    \    |   \    \_\  \    |  / /        \
# \____|__  /____|_  /\______  /______/ /_______  /
#         \/       \/        \/                 \/ 
# 
# Copyright (C) 2023 Siddharth Muralee

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from urllib.parse import urlparse

from argus_components.common.config import LOCAL_FOLDER, RESULTS_FOLDER
from argus_components.common.pylogger import get_logger
from argus_components.common.githandler import clone_repo

from argus_components.plugins import GHAction

logger = get_logger("repo")

class Action:
    LOCAL_ACTION = 1
    REMOTE_ACTION = 2

    def __init__(self, action_url, options_dict, action_path, action_type = REMOTE_ACTION):
        self.action_url = action_url
        self.options_dict = options_dict
        self.action_path = action_path
        self.action_type = action_type

        if self.action_type == self.REMOTE_ACTION and "github.com" not in self.action_url:
            raise Exception("Only GitHub Actions are supported for now")

        if self.action_type == self.LOCAL_ACTION:
            pass
        elif self.action_type == self.REMOTE_ACTION:
            self.action_name = self._get_action_name_from_url()
            self.name = self.action_name.replace("#", "/")
        else:
            raise Exception("Invalid action type")

        logger.info(f"Initialzed Action : {self.action_name}")
    
    def run(self):
        if self.action_type == self.LOCAL_ACTION:
            self._run_local_action()
        elif self.action_type == self.REMOTE_ACTION:
            self._run_remote_action()
        
    def _run_local_action(self):
        pass 

    def _run_remote_action(self):
        folder = LOCAL_FOLDER / self.action_name
        logger.info(f"Cloning action to {folder}")
        # clone the repository
        clone_repo(self.action_url, folder, self.options_dict)
        # Get action Object
        action_obj = GHAction.identify_action(self.name, self.action_path, folder, self)
        self.report = action_obj.run()

    def _get_action_name_from_url(self):
        # https://github.com/repo/action_name/optional_path/optional_path2
        # need to return action_name
        # let's get both the repo name and the action name
        path = urlparse(self.action_url).path
        repo, action = path.split("/")[1], path.split("/")[2]

        return repo + "#" + action

    def save_report_to_file(self):
        file_name = RESULTS_FOLDER / f"{self.action_name}_{self.options_dict['value']}.sarif"
        return self.report.get_report(file_name)
    
    def print_report(self):
        return self.report.get_report(None)