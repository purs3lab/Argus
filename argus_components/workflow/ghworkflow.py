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
from __future__ import annotations

import glob
import os
import yaml
import json
from typing import Dict, List, Tuple, Union
from uuid import uuid4
from hashlib import sha256

from .workflow import Workflow

from argus_components.common.pylogger import get_logger
from argus_components.ci import GithubCI

logger = get_logger("argus_components.workflow.ghworkflow")

NO_ACTION = 0
GITHUB_ACTION = 1
THIRD_PARTY_ACTION = 2
DOCKER_ACTION = 3
LOCAL_ACTION = 4

COMMIT_REF = 0
TAG_REF = 1
BRANCH_REF = 2
NON_THIRD_PARTY_REF = 3
NO_VERSION = 4
DOCKER_TAG_REF = 5
DOCKER_COMMIT_REF = 6
DOCKER_NO_REF = 7
NON_FIRST_PARTY_REF = 8

class GHWorkflow(Workflow):

    @staticmethod
    def find_workflows(repo_path):
        # finc all workflows with .yml and .yaml extensions
        workflows = []

        for extension in ['*.yml', '*.yaml']:
            workflows.extend(glob.glob(os.path.join(repo_path, '.github', 'workflows', extension), recursive=False))

        return workflows 

    def read_workflow(self):
        try:
            with open(self.workflow_full_path, "r") as workflow_file:
                self.content = yaml.safe_load(workflow_file)
        except FileNotFoundError:
            raise FileNotFoundError("Workflow file not found")

    def __init__(self, workflow_path, repo_path):
        self.uid = str(uuid4())
        self.repo_path = repo_path
        self.workflow_full_path = workflow_path
        self.workflow_path = os.path.relpath(workflow_path, repo_path)
        self.read_workflow()

        # Inputs that are passed to the workflow if it's a resuable workflow
        self.workflow_inputs : List[Dict] = []
        # Secrets that are passed to the workflow if it's a reusable workflow
        self.workflow_input_secrets : List[Dict] = [] 
        # Outputs that are passed from the workflow if it's a reusable workflow
        self.workflow_outputs : List[Dict] = []
        # Triggers that are defined in the workflow
        self.triggers : List[Dict] = []
        # Permissions of token that is defined in the workflow
        self.write_permission : Bool = False

        self.jobs = []
        self.parse_workflow()
        
    def parse_workflow(self):
        """ Parses the workflow file """
        self.name = self.get_name()
        
        # Triggers have on -> which is a special case in yaml, gets loaded to True
        # We automatically append to the triggers list (self.triggers)
        self.parse_triggers("on")
        self.parse_triggers(True)    

        # We parse the permissions of the workflow
        self.parse_workflow_permissions()
        
        ctr = 0
        for job_name, body in self.get_jobs().items():
            self.jobs.append(GHWorkflowJob(job_name, body, ctr))
            ctr += 1

        self.env = self.get_env()        

    def parse_triggers(self, filter):
        """ Parses the triggers """
        trigger = self.content.get(filter, None)
        if trigger is None:
            return []
        if isinstance(trigger, dict):
            for keyword, config in trigger.items():
                if keyword == "workflow_call":
                    if config == None:
                        self.triggers.append({
                            "type" : "workflow_call",
                            "condition" : ""
                        })
                        continue
                    self.parse_workflow_inputs(config)
                    self.parse_workflow_input_secrets(config)
                    self.workflow_outputs = self.parse_worfklow_outputs(config)
                else: 
                    self.triggers.append({
                        "type" : keyword,
                        "condition" : json.dumps(config)
                    })
        elif isinstance(trigger, list):
            for item in trigger:
                self.triggers.append({
                        "type" : item,
                        "condition" : ""
                })
        elif isinstance(trigger, str):
            self.triggers.append({
                "type" : trigger,
                "condition" : ""
            })
        else:
            logger.error(f"[Error] Wrong type for trigger : {type(trigger), trigger}")
    
    # https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-git1hub-actions#onworkflow_callinputs 
    def parse_workflow_inputs(self, config : dict):
        if config.get("inputs", None) == None:
            return
        
        for input_name, input_value in config.get("inputs", {}).items():
            if input_value == None:
                continue
            self.workflow_inputs.append({
                "name" : input_name,
                "type" : "reusable_input",
                "datatype" : input_value.get('type', "unknown"),
                "required" : input_value.get('required', True),
                "value" : input_value.get('default', ""),
                "CIvars" : GithubCI.get_github_variables_from_string(input_value.get('default', ""))
            })

        logger.debug("Workflow inputs : ", self.workflow_inputs)

    # https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_callsecrets     
    def parse_workflow_input_secrets(self, config : dict):
        if config.get("secrets", None) == None:
            return
        for secret_name, details in config.get("secrets", {}).items():
            self.workflow_input_secrets.append({
                "name" : secret_name,
                "type" : "reusable_secret",
                "required" : details.get('required', True),
                "datatype" : "unknown",
                "value" : "",
                "CIvars" : []
            })

        logger.debug("Workflow input secrets : ", self.workflow_input_secrets)

    # https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_calloutputs
    def parse_worfklow_outputs(self, config : dict):
        secrets = {k: v["value"] for k, v in config.get("outputs", {}).items()}
        return GithubCI.pack_to_dict_format(secrets, "resuable_outputs")

    # https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#env    
    def parse_workflow_env(self):
        return GithubCI.pack_to_dict_format(self.get_env(), "env")

    def parse_workflow_permissions(self) -> None:
        """Parses the permissions of the workflow"""
        permissions = self.get_permissions()
            
        if permissions == None:
            # TODO: change this to False for new repos
            self.write_permission = True
            return

        if isinstance(permissions, str):
            if permissions == "write-all":
                self.write_permission = True
        elif isinstance(permissions, dict):
            for permission_name, permission_value in permissions.items():
                if permission_value == "write":
                    self.write_permission = True
                    return

        logger.debug("Workflow doesn't seem to have any write permissions")
        return    

    #
    # Getters
    #  

    @property
    def is_self_hosted(self):
        for job in self.jobs:
            if job.is_self_hosted:
                return True
        
    def get_name(self):
        """Returns the name of the workflow"""
        return self.content.get("name", "")

    def get_jobs(self):
        """Returns the jobs in the workflow"""
        return self.content.get("jobs", {})
    
    def get_env(self):
        """Returns the global environment variables in the workflow"""
        return self.content.get("env", None)

    def get_permissions(self):
        """Returns the permissions of the workflow"""
        return self.content.get("permissions", None)

    #
    # Debugging
    # 

    def __str__(self):
        ret = f"Workflow : {self.name}\n"
        ret += f"Triggers : {self.triggers}\n"
        ret += f"Jobs : {self.jobs}\n"
        ret += f"Env : {self.env}\n"
        return ret

class GHWorkflowJob:

    def __init__(self, job_name, body : dict, job_num = 0):
        self.id = job_name
        self.job_num = job_num
        self.name = job_name
        self.body = body
        self.steps : List[GHWorkflowStep] = []
        self.needs = []
        self.root_parser()

    def root_parser(self):    
        self.permissions = self.body.get("permissions", None)
        self.runs_on = self.body.get("runs-on", None)
        self.condition = self.body.get("if", "")
        for step_num, step in enumerate(self.body.get("steps", [])):
            self.steps.append(GHWorkflowStep(step, (self.job_num * 100) +  step_num))
        self.reusable_wfl = self.body.get("uses", None)

    def parse_job_env(self):
        return GithubCI.pack_to_dict_format(self.body.get("env", None), "env")
    
    def parse_wfl_args(self):
        return GithubCI.pack_to_dict_format(self.body.get("with", None), "arg")
    
    def parse_job_outputs(self):
        return GithubCI.pack_to_dict_format(self.body.get("outputs", None), "output")

    def parse_needs(self) -> List:
        needs = self.body.get("needs", [])
        if isinstance(needs, str):
            return [needs]
        elif isinstance(needs, list):
            return needs
        else:
            raise Exception(f"Unknown needs type : {type(needs)}")
        return []
    
        
                    
class GHWorkflowStep:
    
    def __init__(self, step_config : dict, step_num = 0):
        self.step_config = step_config
        self.id = step_config.get("id", "task_" + str(step_num))
        self.name = step_config.get("name", "")
        self.step_num = step_num

        self.run = {
            "type" : "Unknown",
            "cmd" : "",
            "name" : "",
            "version" : "",
            "shell" : "bash", # Default shell is bash
        }

        # Make sure the step has a run or uses command
        assert "run" in step_config or "uses" in step_config, f"Step {self.id} [{step_config}] has no run or uses command"
        # Make sure the step doesn't have both a run and uses command
        assert not ("run" in step_config and "uses" in step_config), f"Step [{self.id}] has both run and uses commands"

        # Parse the commands
        if "run" in step_config:
            self.run["type"] = "shell_cmd"
            self.run["cmd"] = step_config["run"]
            self.run["shell"] = step_config.get("shell", "bash")
        elif "uses" in step_config:
            self.run["type"] = "gh_action"
            self.run["name"] = GHWorkflowStep.get_action_name(step_config["uses"])
            self.run["version"] = GHWorkflowStep.get_action_version(step_config["uses"])
    
        # Parse Arguments      
        self.condition = step_config.get("if", "") 

    def prepare_args(self):
        return GithubCI.pack_to_dict_format(self.step_config.get("with", None), "arg")

    def prepare_env(self):
        return GithubCI.pack_to_dict_format(self.step_config.get("env", None), "env")

    def prepare_cmd_ci_vars(self):
        return GithubCI.get_github_variables_from_string(self.run["cmd"])

    @staticmethod
    def get_action_name(action_name):
        try:
            return action_name.split("@")[0]
        except IndexError:
            return action_name
    
    @staticmethod
    def get_action_version(action_name):
        try:
            return action_name.split("@")[1]
        except IndexError:
            return None
