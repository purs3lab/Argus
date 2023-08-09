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

from argus_components.ci.github import GithubCI
from argus_components.workflow.ghworkflow import GHWorkflowStep
from .workflowir import WorkflowIR, TaskGroup, Task, Exec
from ..workflow import GHWorkflow, GHWorkflowJob

class GHWorkflowIR(WorkflowIR):

    def __init__(self, workflow: GHWorkflow):
        self._convert_to_IR(workflow)   
    
    @staticmethod
    def is_convertable(workflow : GHWorkflow):
        return isinstance(workflow, GHWorkflow)

    def _convert_to_IR(self, workflow : GHWorkflow):
        self.uid = workflow.uid
        self.wf_name = workflow.name
        self.workflow_path = workflow.workflow_path
        self.triggers = workflow.triggers
        self.has_write_permissions = workflow.write_permission

        self.workflow_inputs = workflow.workflow_inputs
        self.workflow_outputs = workflow.workflow_outputs
        self.workflow_env = workflow.parse_workflow_env()

        # if workflow has inputs or outputs, it is reusable
        self.is_reusable = len(self.workflow_inputs) > 0 or len(self.workflow_outputs) > 0 
        
        self.task_groups = []
        # Convert jobs        
        for job in workflow.jobs:
            self.task_groups.append(GHTaskGroup.get_task_group_type(job)) 
        
        # Find dependencies - to be used later
        self.dependencies = self.find_dependencies()

        self.root_groups = []
        self.task_groups_in_order = []
        self.parse_order()
        self.get_ordered_task_groups()


    def find_dependencies(self):
        self.dependent_actions = self._find_dependent_actions()
        self.dependent_workflows = self._find_dependent_workflows()
        return self.dependent_actions + self.dependent_workflows

    @property
    def has_secrets(self):
        for vars in self.get_ci_vars():
            print(vars)
            if vars["type"] == "secret":
                return True
        return False

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.workflow_env) 
        ret += GithubCI.get_ci_vars_from_packed(self.workflow_inputs)
        for task_group in self.task_groups:
            ret += task_group.get_ci_vars()
        return ret

    def _find_dependent_actions(self):
        actions = []
        for task in self.task_groups:
            if isinstance(task, GHNormalTaskGroup):
                actions.extend(task.actions_used)

        # remove duplicates of the list of dicts
        # the name and version should be unique
        visited = []
        set_actions = []
        for action in actions:
            if (action["name"], action["version"]) in visited:
                continue
            visited.append((action["name"], action["version"]))
            set_actions.append(action)
        return set_actions
        
    def _find_dependent_workflows(self):
        wfs = set()
        for task in self.task_groups:
            if isinstance(task, GHResuableTaskGroup):
                wfs.add(task.workflow)
        return list(wfs)

    def parse_order(self):
        for task_group in self.task_groups:
            if task_group.needs == []:
                self.root_groups.append(task_group)
                continue

            for parent_group_name in task_group.needs:
                parent_group = self.find_task_group_with_name(parent_group_name)
                if parent_group == None:
                    raise Exception(f"Job {parent_group_name} not found in workflow {self.uid}")
                parent_group.add_child(task_group)
                task_group.add_parent(parent_group)

    def find_task_group_with_name(self, name: str):
        return next((task_group for task_group in self.task_groups if task_group.name == name), None)

    # Iterate through the root task_groups and get the task_groups in order
    def get_ordered_task_groups(self):
        for root_job in self.root_groups:
            self.task_groups_in_order.append(root_job)
        
        
        non_root_task_groups = [task_group for task_group in self.task_groups if task_group not in self.root_groups] 

        cnt = 0
        while len(non_root_task_groups) > 0:
            for task_group in non_root_task_groups:
                if all(x in self.task_groups_in_order for x in task_group.parents):
                    self.task_groups_in_order.append(task_group)
                    non_root_task_groups.remove(task_group)
                    break
            cnt += 1

            if cnt > 1000:
                raise Exception("Got a circular dependency in the workflow")


    def __str__(self):
        ret = "=====================\n"
        ret += f"Workflow : {self.uid}\n"
        ret += f"Reusable : {self.is_reusable}\n"
        for task_group in self.task_groups:
            ret += str(task_group)
        ret += "=====================\n"
        return ret
    
class GHTaskGroup(TaskGroup):
    """
        GHTaskGroup is a class that represents a task group in a workflow
        It is congruent to a job in a github workflow
        Hence it's generated from a GHWorkflowJob
    """

    target_classes = []

    def __init__(self, job : GHWorkflowJob):
        self.children = []
        self.parents = []
        self.needs = job.parse_needs()
        self.env = job.parse_job_env()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)

    @staticmethod
    def get_task_group_type(job : GHWorkflowJob):
        """
            Returns the correct subclass of GHTaskGroup based on the job
        """
        for cls in GHTaskGroup.target_classes:
            if cls.is_current_type(job):
                return cls(job)
        return None

    @staticmethod
    def is_current_type(job : GHWorkflowJob):
        raise NotImplementedError

    def add_child(self, child_job : GHWorkflowJob):
        self.children.append(child_job)
    
    def add_parent(self, parent_job : GHWorkflowJob):
        self.parents.append(parent_job)

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        return ret

    @property
    def self_hosted(self):
        if isinstance(self.runs_on, list):
            for run in self.runs_on:
                if run == "self-hosted":
                    return True
        elif isinstance(self.runs_on, str):
            if self.runs_on == "self-hosted":
                return True
        else:
            return False
        return False

    @property
    def has_children(self):
        return len(self.children) > 0
    
    def __str__(self):
        ret = "Not Implemented"

class GHNormalTaskGroup(GHTaskGroup):
    """ 
        GHNormalTaskGroup is a class that represents a task group in a workflow
        It is congruent to a job in a github workflow, when the job does not consits of a reusable workflow        
    """

    def __init__(self, job : GHWorkflowJob):
        super().__init__(job)
        self._convert_to_IR(job)

    def _convert_to_IR(self, job : GHWorkflowJob):
        self.id = job.id
        self.name = job.name
        self.runs_on = job.runs_on

        self.outputs = job.parse_job_outputs()

        self.tasks = []
        for step in job.steps:
            self.tasks.append(GHTask.get_exec_type(step))        

        #self.dependencies = self.get_dependencies()
    
    @staticmethod
    def is_current_type(job : GHWorkflowJob):
        if job.reusable_wfl == None:
            return True
        return False
        
    @property
    def actions_used(self):
        actions = []
        for task in self.tasks:
            if isinstance(task, GHActionTask):
                actions.append(task.action)
        return actions

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        for task in self.tasks:
            ret += task.get_ci_vars()
        return ret

    def __str__(self):
        ret = f"TaskGroup {self.id} : {self.name}\n"
        for task in self.tasks:
            ret += str(task)
        return ret


class GHResuableTaskGroup(GHTaskGroup):
    """
        GHResuableTaskGroup is a class that represents a task group in a workflow
        It is congruent to a job in a github workflow, when the job consits of a reusable workflow
        https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_iduses
    """
    LOCAL_WORKFLOW = 1
    REMOTE_WORKFLOW = 2

    def __init__(self, job : GHWorkflowJob):
        super().__init__(job)
        self._convert_to_IR(job)
    
    @staticmethod
    def is_current_type(job : GHWorkflowJob):
        if job.reusable_wfl != None:
            return True
        return False

    def _convert_to_IR(self, job : GHWorkflowJob):
        self.id = job.id
        self.name = job.name
        self.runs_on = job.runs_on

        self.workflow = job.reusable_wfl
        self.args = job.parse_wfl_args()
        self.outputs = job.parse_job_outputs()

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        ret += GithubCI.get_ci_vars_from_packed(self.args)
        ret += GithubCI.get_ci_vars_from_packed(self.outputs)
        return ret

    def __str__(self):
        ret = f"TaskGroup {self.id} : {self.name}\n"
        ret += f"\tResusable Workflow : {self.workflow}\n"
        ret += f"\t\t Repo : {self.workflow_repo}\n"
        ret += f"\t\t Type : {self.workflow_type}\n"
        ret += f"\t\t Path : {self.workflow_path}\n"
        ret += f"\t\t Options : {self.option_dict}\n"
        return ret

    @property
    def workflow_type(self):
        if self.workflow.startswith("./"):
            return GHResuableTaskGroup.LOCAL_WORKFLOW
        else:
            return GHResuableTaskGroup.REMOTE_WORKFLOW
    
    @property
    def workflow_repo(self):
        import os
        creds = os.getenv("GITHUB_CREDS")
        if creds:
            creds += "@"
        else:
            creds = ""
        workflow_name = self.workflow
        if "@" in workflow_name:
            workflow_name = workflow_name.split("@")[0]
        return f"https://{creds}github.com/" + "/".join(workflow_name.split("/")[:2])

    @property
    def workflow_path(self):
        workflow_name = self.workflow
        if "@" in workflow_name:
            workflow_name = workflow_name.split("@")[0]
        return "/".join(workflow_name.split("/")[2:])
    
    @property
    def option_dict(self):
        if "@" in self.workflow:
            return GithubCI.get_option_dict_from_sting(self.workflow.split("@")[1])
        else:
            return {}

class GHTask(Task):
    """  
        GHTask is a class that represents a task in a workflow
        It is congruent to a step in a job, and is a part of a task group
        Hence it's generated from a GHWorkflowStep 
    """
    target_classes = []

    def __init__(self, step : GHWorkflowStep):
        self.id = step.id
        self.name = step.name
        self.step_no = int(step.step_num % 100)
        self.env = step.prepare_env()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)
    
    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        return ret

    @staticmethod
    def get_exec_type(exec):
        for cls in GHTask.target_classes:
            if cls.get_exec_type(exec):
                return cls(exec)
        raise NotImplementedError

    def __str__(self):
        return f"\tTask {self.id} : {self.name}\n"
    
class GHActionTask(GHTask):
    """ 
        ActionExec is a class that represents a GitHub Action
    """
    LOCAL_ACTION = 1
    DOCKERHUB_ACTION = 2
    REMOTE_ACTION = 3

    def __init__(self, step : GHWorkflowStep):
        super().__init__(step)
        self._convert_to_IR(step)

    def _convert_to_IR(self, step : GHWorkflowStep):
        self.id = step.id
        self.name = step.name

        # parse the exec type
        exec = step.run
        self.action_version = exec["version"]
        self.action_parse_type = GHActionTask.get_action_parse_type(exec["name"])
        if self.action_parse_type == GHActionTask.LOCAL_ACTION:
            self.action_name = ""
            self.action_path = exec["name"]
        elif self.action_parse_type == GHActionTask.REMOTE_ACTION:
            self.action_name, self.action_path = GHActionTask.split_action_name(exec["name"])
        else:
            self.action_name = exec["name"]
            self.action_path = ""

        self.args = step.prepare_args()

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        ret += GithubCI.get_ci_vars_from_packed(self.args)
        return ret

    @staticmethod
    def split_action_name(action_name):
        chunks = action_name.split("/") 
        if len(chunks) < 2:
            return None, None
        
        if len(chunks) > 2:
            return chunks[0] + "/" + chunks[1], "/".join(chunks[2:])
        else:
            return chunks[0] + "/" + chunks[1], None

    @staticmethod
    def get_exec_type(step : GHWorkflowStep) -> bool:
        # make sure that "type" is present in the dict, and it's of type "gh_action", "gh_dockerhub_action", "gh_local_action"
        if not "type" in step.run:
            return False
        if not step.run["type"] in ["gh_action"]:
            return False
        return True
    
    @staticmethod
    def get_action_parse_type(action_name : str = None):
        if action_name == None:
            return None
        name = action_name.strip()
        if name.startswith("actions/"):
            return GHActionTask.REMOTE_ACTION
        elif name.startswith("docker:"):
            return GHActionTask.DOCKERHUB_ACTION 
        elif name.startswith("./"):
            return GHActionTask.LOCAL_ACTION
        else:
            return GHActionTask.REMOTE_ACTION 
    
    @property
    def options_dict(self):
        return GithubCI.get_option_dict_from_sting(self.action_version)

    @property
    def action_url(self):
        import os
        creds = os.getenv("GITHUB_CREDS")
        if creds:
            creds += "@"
        else:
            creds = ""
        return f"https://{creds}github.com/{self.action_name}"

    @property
    def action(self):
        return {"name" : self.action_name, "version" : self.action_version}

    def __str__(self):
        return super().__str__() + f"\t\tAction : {self.action_name} ({self.action_version})\n"

class GHRunTask(GHTask):
    """ 
        RunExec is a class that represents a Command to be executed. 
        It can be a bash command or any other script that is supported by Github Actions platform
    """
    
    def __init__(self, step : GHWorkflowStep):
        super().__init__(step)
        self._convert_to_IR(step)

    def _convert_to_IR(self, step : GHWorkflowStep):
        self.id = step.id
        self.name = step.name

        # parse the exec type
        exec = step.run
        self.command = exec["cmd"]
        self.shell = exec["shell"]
        self.command_parse_type = exec["type"]
        self.ci_vars = step.prepare_cmd_ci_vars()
        
        self.args = step.prepare_args()

    def get_ci_vars(self):
        ret = []
        ret += GithubCI.get_ci_vars_from_packed(self.env)
        ret += GithubCI.get_ci_vars_from_packed(self.args)
        ret += self.ci_vars
        return ret

    @staticmethod
    def get_exec_type(step : GHWorkflowStep) -> bool:
        # make sure that "type" is present in the dict, and it's of type "run"
        if not "type" in step.run:
            return False
        if not step.run["type"] in ["shell_cmd"]:
            return False
        return True
    
    def __str__(self):
        # print only the first 20 characters of the command
        return super().__str__() + f"\t\tRun ({self.shell}) : {self.command[:min(len(self.command), 20)]}...\n"
        