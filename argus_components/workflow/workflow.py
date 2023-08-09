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

from argus_components.common.pylogger import get_logger

logger = get_logger("workflow_parser")

class Workflow:
    target_classes = []

    def __init__(self, repo_path):
        self.repo_path = repo_path

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)

    @staticmethod
    def initialize_workflows(repo_path):
        workflows = []
        for workflow_class in Workflow.target_classes:
            possible_wfs = workflow_class.find_workflows(repo_path)
            for wf in possible_wfs:
                try: 
                    workflows.append(workflow_class(wf, repo_path=repo_path))
                except AssertionError: 
                    logger.critical(f"Workflow {wf} is not valid")
        return workflows
    
    @staticmethod
    def find_workflows(repo_path):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError
    