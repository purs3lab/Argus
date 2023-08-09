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

import os

from argus_components.common.config import LOCAL_FOLDER, RESULTS_FOLDER
from argus_components.common.pylogger import get_logger
from argus_components.common.githandler import clone_repo

from argus_components.workflow import Workflow
from argus_components.ir import WorkflowIR
import argus_components.taintengine as TaintEngine
import argus_components.action as Action
import argus_components.report as Report
import argus_components.ci as CI

logger = get_logger("repo")

class Repo:
    def __init__(self, repo_url : str, option_dict : dict): 
        self.repo_url = repo_url
        self.option_dict = option_dict    
        self.repo_name = self._get_repo_name_from_url()
        self.owner_name = self._get_repo_owner_from_url()
        self.actions = []
        self.sub_repos = []

        self.folder = LOCAL_FOLDER / f"{self.owner_name}#{self.repo_name}"
        logger.info(f"Cloning repository to {self.folder}")
        # clone the repository
        clone_repo(self.repo_url, self.folder, self.option_dict)

        self.workflows = Workflow.initialize_workflows(self.folder)    
        self.workflow_reports = []

    def run(self, workflow_path : str = None):
        # Find the workflows in the repository
        flag = False
        for workflow in self.workflows: 
            if workflow_path == None or workflow.workflow_path == workflow_path:
                ir_obj = WorkflowIR.get_IR(workflow) 
                self.workflow_reports.append(Report.WorkflowReport(
                    TaintEngine.TaintEngine(ir_obj, self).run_workflow(),
                    ir_obj
                ))
                flag = True
        if flag == False and workflow_path != None:
            logger.error(f"Workflow {workflow_path} not found in repository {self.repo_url}")
        elif flag == False:
            logger.error(f"No workflows found in repository {self.repo_url}")


    def _get_repo_name_from_url(self):
        return self.repo_url.split("/")[-1].split(".")[0]    

    def _get_repo_owner_from_url(self):
        return self.repo_url.split("/")[-2]
    
    def find_workflow_by_path(self, workflow_path : str) -> WorkflowIR:
        for workflow in self.workflows:
            if workflow.workflow_path == workflow_path:
                return WorkflowIR.get_IR(workflow)
        return None        

    # 
    # Handle sub-repos
    # 

    def initialize_sub_repo(self, repo_url : str, option_dict : dict):
        repo = Repo(repo_url, option_dict)
        for action in self.get_evaluated_actions():
            repo.add_evaluated_action(action)
        self.sub_repos.append(repo)
        return repo

    def get_sub_repo(self, repo_url : str):
        for repo in self.sub_repos:
            if repo.repo_url == repo_url:
                return repo
        return None

    #
    # Handle evaluated actions
    # 

    def add_evaluated_action(self, action):
        self.actions.append(action)

    def get_evaluated_actions(self):
        return self.actions
    
    def is_action_evaluated(self, action_name : str, action_path : str, action_version : str):
        options = CI.GithubCI.get_option_dict_from_sting(action_version)
        logger.debug (f"Checking if action {action_name}#{action_version} is evaluated")
        for action in self.actions:
            if action.name == action_name and action.options_dict == options and action.action_path == action_path:
                logger.debug(f"Action {action_name}#{action_version} is evaluated")
                return action
        logger.debug(f"Action {action_name}#{action_version} is not evaluated")
        return None

    def save_report_to_file(self):
        for workflow_report in self.workflow_reports:
            wf_name = os.path.basename(workflow_report.workflow_path).split(".")[0]
            workflow_report.get_report(RESULTS_FOLDER / f"{self.owner_name}#{self.repo_name}#{wf_name}.sarif")
    
    def print_report(self):
        for workflow_report in self.workflow_reports:
            workflow_report.get_report(None)