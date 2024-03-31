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
from typing import Dict, List

from argus_components.ir import WorkflowIR, GHWorkflowIR, GHTaskGroup, GHTask, GHNormalTaskGroup, GHResuableTaskGroup, GHActionTask, GHRunTask
from argus_components.common.pylogger import get_logger
from argus_components.ci import GithubCI

import argus_components.action as Action
import argus_components.repo as Repo
import argus_components.plugins as plugins
import argus_components.report as Report

logger = get_logger("taintengine")

class TaintObj(object):
    IN_WORKFLOW = 0
    IN_REUSABLE = 1
    IN_COMPOSITE = 2

    def __init__(self, name, type, parent_nodes = [], location = IN_WORKFLOW, is_object=False, engine : TaintEngine = None,curr_task = "unk"):
        self.name = name
        self.type = type
        self.location = location
        self.curr_task = curr_task
        self.is_object = False
        self.engine = engine
        self.sink_location = ""

        if parent_nodes == None: 
            parent_nodes = []
        elif isinstance(parent_nodes, TaintObj):
            parent_nodes = [parent_nodes]

        assert (isinstance(parent_nodes, list) and all(isinstance(x, TaintObj) for x in parent_nodes))

        if parent_nodes == []:
            self.parent_nodes = []            
            self.is_root = True
        else:
            self.parent_nodes = parent_nodes
            self.is_root = False

    def __str__(self):
        return f"Taint Object<name={self.name},type={self.type},path={self.path}>"

    @property
    def report_dict(self):
        return {
            "source": self.root_node[0].name,
            "name": self.root_node[0].name,
            "type": self.root_node[0].type,
            "source_location" : self.root_node[0].location,
            "source_type" : self.root_node[0].type,
            "sinks" : [{
                "sink" : self.name,
                "name" : self.name,
                "taint_name" : self.name,
                "sink_location" : self.sink_location,
                "sink_type" : self.type,
            }],
        }
    
    def set_sink_location(self, location):
        self.sink_location = location

    @property
    def path_count(self):
        if self.is_root:
            return 0
        return max([parent_node.path_count + 1 for parent_node in self.parent_nodes])
    
    @property
    def multiple_paths(self):
        if self.is_root:
            return False
        if len(self.parent_nodes) > 1:
            return True
        else:
            return self.parent_nodes[0].multiple_paths

    @property
    def path(self):
        if self.is_root:
            return [(self.name, self.type)]
        if len(self.parent_nodes) == 1:
            return self.parent_nodes[0].path + [(self.name, self.type)]
        else:
            #TODO: Handle multiple parents
            return self.parent_nodes[0].path + [self.name] 

    @property
    def root_name(self):
        if self.is_root:
            return [self.name]
        return list(set([roots for parent_node in self.parent_nodes for roots in parent_node.root_name]))

    @property
    def root_node(self):
        if self.is_root:
            return [self]
        return list(set([node for parent_node in self.parent_nodes for node in parent_node.root_node]))

    @property
    def root_location(self):
        if self.is_root:
            return [self.location]
        return list(set([loc for parent_node in self.parent_nodes for loc in parent_node.root_location]))

    @property
    def is_root_object(self):
        if self.is_root:
            return self.is_object
        return any([parent_node.is_root_object for parent_node in self.parent_nodes])

class TaintEngine:
    WORKFLOW_LEVEL = 0
    TASK_GROUP_LEVEL = 1
    TASK_LEVEL = 2

    WFL_MODE = 0
    ACTION_MODE = 1    

    ALERT_NONE = 0
    ARG_TO_SINK = 1 
    ENV_TO_SINK = 2
    TAINT_TO_SINK = 3
    SHELL_WITH_TAINT = 4
    TAINT_TO_LOCAL = 5
    ENV_TO_SHELL_WITH_TAINT = 6
    TAINT_TO_DOCKER = 7
    TAINT_TO_DEF_DOCKER = 8
    TAINT_TO_UNKNOWN = 9
    
    ALERT_DONOTUSE = 10
    ARG_TO_LSINK = 11 
    ENV_TO_LSINK = 12
    REUSABLE_WF_TAINT_OUTPUT = 13
    CONTEXT_TO_SINK = 14

    ALERT_NAME = [
        "NONE", "ARG_TO_SINK", "ENV_TO_SINK", "TAINT_TO_SINK", "SHELL_WITH_TAINT", "TAINT_TO_LOCAL", "ENV_TO_SHELL_WITH_TAINT", "TAINT_TO_DOCKER", "TAINT_TO_DEF_DOCKER", "TAINT_TO_UNKNOWN"
    ]
    TAINT_LEVELS = [WORKFLOW_LEVEL, TASK_GROUP_LEVEL, TASK_LEVEL]

    def __init__(self, workflow : GHWorkflowIR, repo, parent_repo = None):

        assert isinstance(workflow, GHWorkflowIR) or isinstance(workflow, GHNormalTaskGroup), "TaintEngine only supports GHWorkflowIR and GHNormalTaskGroup"

        if isinstance(workflow, GHWorkflowIR):
            assert isinstance(repo, Repo.Repo), "TaintEngine only supports Repo"
            self.workflow = workflow
            self.repo = repo
            self.curr_type = TaintEngine.WFL_MODE
        else:
            assert isinstance(repo, Action.Action), "TaintEngine only supports Action"
            self.workflow = workflow
            self.action = repo
            self.task_group = workflow
            self.repo = parent_repo
            self.curr_type = TaintEngine.ACTION_MODE

        self.current_task_group = None
        self.current_task = None
        self.intitialized = False
        self.in_composite = False
        
        self.tainted_args = []

        self.tainted_inputs = []
        self.composite_inputs = []
        self.tainted_variables = []
        self.tainted_outputs : Dict[str, Dict[str, List[TaintObj]]] = {}
        self.tainted_job_outputs : Dict[str, List[TaintObj]] = {}

        self.nested_composite_count = 0
        self.current_composite_action = None
        self.nested_composite_inputs = []
        self.composite_ctr = 0
        self.saved_task_groups = []
        
        # Initialize the tainted envs
        self.tainted_envs = {}
        self.tainted_envs[self.WORKFLOW_LEVEL] = []
        self.tainted_envs[self.TASK_GROUP_LEVEL] = []
        self.tainted_envs[self.TASK_LEVEL] = []
        
        self.alerts = []
        self.override_location = None
        
        # self.wf_inputs = inputs
        # self.in_reusable = False
        # if len(self.wf_inputs) != 0:
        #     self.in_reusable = True
        # for inp in self.wf_inputs:
        #     self.taint_input(inp)

    def taint_packed_data(self, packed_data : dict, output_type = "", input_type = "", level = None, verbose = False):
        """
        Applies taint propogation based on the type of the packed data

        Packed data is a list of dictionaries with the following keys:
        - name: Name of the packed data
        - type: Type of the packed data
        - CIvars: List of CI variables that are used to construct the packed data
        - value: Value of the packed data  

        I should probably make a class for this
        """
        assert isinstance(packed_data, list), "Packed data must be a list of dictionaries"
        assert all([isinstance(item, dict) for item in packed_data]), "Packed data must be a list of dictionaries"

        ret = []
        for item in packed_data:
            if verbose:
                print(f"Processing packed data : {item}")
            sources = self.input_taint_by_type(input_type, item, output_type)
            if sources != []:
                if "sinks" in item:
                    for sink in item['sinks']:
                        obj = TaintObj(
                            name=sink['taint_name'],
                            type=output_type,
                            parent_nodes=sources,
                            location=self.get_location(),
                            engine=self
                        )
                        ret.append(self.output_taint_by_type(obj, output_type, level))
                else:
                    obj = TaintObj(
                        # The name of the tainted object, will be used to match later
                        name=item['taint_name'] if 'taint_name' in item else item['name'],
                        # The type of the tainted object, will be used to match later
                        type=output_type,
                        # Parent nodes, form a DAG which will allow us to track the flow of taint
                        parent_nodes=sources,
                        # The location information of the tainted object (eg, task name, workflow name etc)
                        location=self.get_location(),
                        # Engine
                        engine=self
                    )
                    ret.append(self.output_taint_by_type(obj, output_type, level))
        return ret
    
    

    def input_taint_by_type(self, input_taint_type, packed_data, output_taint_type = ""):
        """
        Here, we are checking if the input is tainted or not. We need to check at different places depending on the input type

        input_taint_type: The type of the input. Can be one of the following:
        - arg: The input is an argument to a task
        - env: The input is an environment variable
        - context: The input is a context variable
        - "" : unknown types
        """
        assert "name" in packed_data, f"Input must have a name {packed_data}"

        # This means that the input is a packed variable
        if input_taint_type == "packed":
            if "CIvars" in packed_data:
                return self.contains_tainted_variable(packed_data)
            else:
                return self.is_tainted_variable(packed_data)
        elif input_taint_type == "maketaint":
            # Only for this we pass the entire packed data
            return self.make_taint_object(packed_data, output_taint_type)
        elif input_taint_type == "arg":
            return self.is_tainted_arg(packed_data["name"])
        elif input_taint_type == "env":
            return self.is_env_tainted(packed_data["name"])
        elif input_taint_type == "context":
            return TaintObj(
                name=packed_data["name"],
                type=output_taint_type,
                parent_nodes=[],
                location=self.get_location(),
                engine=self
            )
        elif input_taint_type == "output":
            # It's an output, so we need to check if the output is tainted
            return self.is_output_tainted(packed_data["name"])
        elif input_taint_type == "job_output":
            return self.is_job_output_tainted(packed_data["name"])
        else:
            raise Exception(f"Unknown input taint type: {input_taint_type}")

    
    def output_taint_by_type(self, obj, type, level = None):
        """
        Here, we are propogating the taint from the input to the output. 

        We add the taint based on the type of output being tainted         
        """
        if type == "env":
            self.taint_env(obj, level)
            return None
        if type == "input":
            self.taint_input(obj)
            return None
        elif type == "output":
            self.taint_output(obj)
            return None
        elif type == "job_output":
            self.taint_job_output(obj)
            return None
        elif type == "wf_output":
            return obj
        elif type == "arg":
            self.taint_arg(obj)
            return None
        else:
            raise Exception(f"Unknown output taint type: {type}")

    def check_packed_data(self, packed_data, input_type = "", alert_type = ""):
        print(f"Checking packed data {packed_data}")
        for item in packed_data:
            tainted = self.input_taint_by_type(input_type, item)
            if tainted:
                taint_obj = TaintObj(
                    name=item['taint_name'] if 'taint_name' in item else item['name'],
                    type=item['type'],
                    parent_nodes=tainted,
                    location=self.get_location(),
                    engine=self
                )
                taint_obj.set_sink_location(self.get_location())
                logger.info(f"ALERT RAISED @ {self.get_location()}")
                self.raise_alert(
                    alert_type=alert_type,
                    taint_obj=taint_obj,
                )

    def run_workflow(self):
                 
        self.set_override_location("workflow_inputs")
        self.taint_packed_data(
            packed_data=self.workflow.workflow_inputs, 
            input_type="maketaint", 
            output_type="input", 
            level=self.WORKFLOW_LEVEL
        )
        self.unset_override_location()

        # Let's start by tainting the env variables, that are used in the workflow
        # These env variables are defined at the workflow level and persist in all the tasks
        # unless they are overwritten by the task or task_group level env variables
        self.taint_packed_data(
            packed_data=self.workflow.workflow_env, 
            input_type="packed", 
            output_type="env", 
            level=self.WORKFLOW_LEVEL
        )

        # Now let's analyze the jobs in the workflow
        for task_group in self.workflow.task_groups_in_order:
            
            # Set the current task group to the id of the task group we are analyzing
            self.current_task_group = task_group

            # Taint the env variables defined at the task group level
            # These env variables are defined at the task group level and persist in all the tasks in the task group
            # unless they are overwritten by the task level env variables
            self.taint_packed_data(
                packed_data=task_group.env, 
                input_type="packed", 
                output_type="env",
                level=self.TASK_GROUP_LEVEL
            )

            # TaskGroup can be a resuable workflow, which means we need to find the reusable workflow and analyze it
            # with the current context
            if isinstance(task_group, GHResuableTaskGroup):
                self.handle_reusable_workflow(task_group)
                continue
            # TaskGroup is a normal sequence of tasks
            # We need to analyze each task in the task group
            elif isinstance(task_group, GHNormalTaskGroup):
                for task in task_group.tasks:
                    logger.debug(f"Task: {task.id}")

                    self.current_task = task
                    self.handle_task(task)

            # Taint the outputs of the task group
            # These outputs are defined at the task group level and persist in all the tasks in the task group            
            if task_group.outputs != None:
                self.taint_packed_data(
                    packed_data=task_group.outputs, 
                    input_type="packed", 
                    output_type="job_output", 
                    level=self.TASK_GROUP_LEVEL
                )

            # Clear the env and step outputs of the task group
            self.clear_taint_at_level(self.TASK_GROUP_LEVEL)


        # Return the outputs of the workflow that are tainted
        return self.pack_workflow_results()

    def pack_workflow_results(self):
        results = {
            # Workflow Arg to Sink
            "ArgToSink" : [],
            # Any direct context to Sink that started in the workflow
            "ContextToSink" : [],
            # Workflow Arg to Output
            "ArgToOutput" : [],
            # Any direct context to Output that started in the workflow
            "ContextToOutput" : [],         
        }

        self.set_override_location("workflow_outputs")
        self.check_packed_data(self.workflow.workflow_outputs, input_type="packed", alert_type="OutputTainted")
        self.unset_override_location()

        for alert in self.alerts:
            # If shell command is tainted
            if alert["type"] == "OutputTainted":
                if any(root_node.type == "context" for root_node in alert["taint_obj"].root_node):
                    results["ContextToOutput"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "output" for root_node in alert["taint_obj"].root_node):
                    results["ContextToOutput"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "input" for root_node in alert["taint_obj"].root_node):
                    results["ArgToOutput"].append(alert["taint_obj"].report_dict)
                else:
                    Exception("Unknown root node type")            
            else:
                if any(root_node.type == "context" for root_node in alert["taint_obj"].root_node):
                    results["ContextToSink"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "output" for root_node in alert["taint_obj"].root_node):
                    results["ContextToSink"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "input" for root_node in alert["taint_obj"].root_node):
                    results["ArgToSink"].append(alert["taint_obj"].report_dict)
                else:
                    Exception("Unknown root node type")
        return results


    def run_task_group(self, all_inputs = [], outputs = []):

        self.set_override_location("action_inputs")
        # Taint all the inputs defined, even if they don't have any taint
        self.taint_packed_data(
            packed_data=all_inputs, 
            input_type="maketaint", 
            output_type="input", 
            level=self.TASK_GROUP_LEVEL
        )
        self.unset_override_location()

        self.current_task_group = self.task_group
        # Taint the env variables defined at the task group level
        # These env variables are defined at the task group level and persist in all the tasks in the task group
        # unless they are overwritten by the task level env variables
        self.taint_packed_data(
            packed_data=self.task_group.env, 
            input_type="packed", 
            output_type="env",
            level=self.TASK_GROUP_LEVEL
        )

        if isinstance(self.task_group, GHResuableTaskGroup):
            Exception("Composite Actions can't have reusable workflows")
        elif isinstance(self.task_group, GHNormalTaskGroup):
            # TaskGroup is a normal sequence of tasks
            # We need to analyze each task in the task group
            for task in self.task_group.tasks:
                logger.debug(f"Task: {task.id}")

                self.current_task = task
                self.handle_task(task)
        else:
            Exception("Unknown Task Group Type")

        # Return all the tainted outputs
        # TODO: 
        return self.pack_task_group_results(outputs)
    
    def pack_task_group_results(self, outputs):
        results = {
            # Taint originates from tainted input, and is propogated to a sink
            "ArgToSink" : [],
            # Taint originates from tainted context inside the action, and is propogated to a sink
            "ContextToSink" : [],
            # Taint originates from tainted input, and is propogated to the output
            "ArgToOutput" : [],
            # Taint originates from tainted context inside the action, and is propogated to the output
            "ContextToOutput" : [],
        }

        self.set_override_location("outputs")
        self.check_packed_data(outputs, input_type="packed", alert_type="OutputTainted")
        self.unset_override_location()

        for alert in self.alerts:
            # If shell command is tainted
            if alert["type"] == "OutputTainted":
                if any(root_node.type == "context" for root_node in alert["taint_obj"].root_node):
                    results["ContextToOutput"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "input" for root_node in alert["taint_obj"].root_node):
                    results["ArgToOutput"].append(alert["taint_obj"].report_dict)
                else:
                    Exception("Unknown root node type")            
            else:
                if any(root_node.type == "context" for root_node in alert["taint_obj"].root_node):
                    results["ContextToSink"].append(alert["taint_obj"].report_dict)
                elif any(root_node.type == "input" for root_node in alert["taint_obj"].root_node):
                    results["ArgToSink"].append(alert["taint_obj"].report_dict)
                else:
                    Exception("Unknown root node type")
        return results


    def handle_reusable_workflow(self, task_group : GHResuableTaskGroup):
        logger.debug(f"Handling Reusable Task Group: {task_group.id} | {task_group.workflow}")

        # Taint the inputs of the reusable workflow
        self.set_override_location("reusable_workflow_inputs")
        self.taint_packed_data(
            packed_data=task_group.args, 
            input_type="packed", 
            output_type="arg", 
            level=self.TASK_LEVEL
        )
        self.unset_override_location()

        sub_repo = None
        if task_group.workflow_type == GHResuableTaskGroup.LOCAL_WORKFLOW:
            workflow_ir = self.repo.find_workflow_by_path(task_group.workflow_path)
            sub_repo = self.repo
        elif task_group.workflow_type == GHResuableTaskGroup.REMOTE_WORKFLOW:
            sub_repo = self.repo.initialize_sub_repo(task_group.workflow_repo, task_group.option_dict)            
            workflow_ir = sub_repo.find_workflow_by_path(task_group.workflow_path)
        else:
            raise Exception("Unknown workflow Task group type")

        # Pass the same metadata to the reusable workflow
        # maybe we need to cache it.  
        wf_report = Report.WorkflowReport(
            TaintEngine(workflow_ir, sub_repo).run_workflow(),
            workflow_ir
        )

        self.check_workflow_sinks(task_group, wf_report)
        self.propogate_workflow_taint(task_group, wf_report)


    def handle_task(self, task : GHTask):
        logger.debug(f"handle_task: {task}")
        # Taint the env variables
        self.taint_packed_data(task.env, 
            input_type="packed", 
            output_type="env", 
            level=self.TASK_LEVEL,
            )

        if isinstance(task, GHActionTask):
            # Taint the args
            self.taint_packed_data(
                task.args, 
                input_type="packed", 
                output_type="arg", 
                level=self.TASK_LEVEL,
                )
            
            self.handle_action(task)
        elif isinstance(task, GHRunTask):
            self.handle_shell_cmd(task)
        else:
            raise Exception("Unknown task type")
        self.clear_taint_at_level(self.TASK_LEVEL)

#
# handle actions
# 

    def handle_action(self, ac_task : GHActionTask):
        assert isinstance(ac_task, GHActionTask) == True, "handle_action: ac_task is not GHActionTask"
    
        if ac_task.action_parse_type == GHActionTask.LOCAL_ACTION:
            # #TODO: pass args
            # action : Action.Action = self.repo.is_action_evaluated(ac_task.action_name, ac_task.action_path, ac_task.action_version)
            # if action == None:
            #     action = Action.Action(ac_task.action_path, {}, ac_task.action_path)
            #     action.run()
            #     self.repo.add_evaluated_action(action)
            # else:
            #     logger.info(f"Action {ac_task.action_name} : Version {ac_task.action_version} is already evaluated.. using cache")
            # self.check_action_sinks(ac_task, action.report)
            # self.propogate_action_taint(ac_task, action.report)
            pass
        elif ac_task.action_parse_type == GHActionTask.REMOTE_ACTION:
            #TODO: pass args
            # try:
                action : Action.Action = self.repo.is_action_evaluated(ac_task.action_name, ac_task.action_path, ac_task.action_version)
                if action == None:
                    action = Action.Action(ac_task.action_url, ac_task.options_dict, ac_task.action_path, parent_repo=self.repo)
                    action.run()
                    self.repo.add_evaluated_action(action)
                else:
                    logger.info(f"Action {ac_task.action_name} : Version {ac_task.action_version} is already evaluated.. using cache")
                # action.print_report()
                self.check_action_sinks(ac_task, action.report)
                self.propogate_action_taint(ac_task, action.report)
            # except Exception as e:
            #     logger.error(f"Error while evaluating action {ac_task.action_name} : {ac_task.action_version} : {ac_task.action_url}")
            #     logger.error(e)
                
        elif ac_task.action_parse_type == GHActionTask.DOCKERHUB_ACTION:
            # Taise an alert if there is taint loss
            pass
        else:
            raise Exception("Unknown action type")

    def handle_shell_cmd(self, task : GHRunTask):
        logger.debug(f"Handling shell command {str(task)}")

        # Check if the shell command is tainted       
        self.check_packed_data(
            task.ci_vars, 
            input_type="packed", 
            alert_type="ShellCmdTainted", 
        )

        if task.shell == "bash" or task.shell == "":
            parsed = plugins.Bash.parse_bash_command(task.command)
            self.check_packed_data(
                parsed["env_vars"], 
                input_type="env",
                alert_type="TaintedEnvShellCmd"
            )
            self.taint_packed_data(
                parsed["set_envs"],
                input_type="packed",
                output_type="env", 
                level=self.TASK_GROUP_LEVEL    
            )
            self.taint_packed_data(
                parsed["set_outputs"], 
                input_type="packed", 
                output_type="output", 
                level=self.TASK_GROUP_LEVEL
            )
#
# JS actions
# 

    hardcoded_sinks = {
        "actions/github-script" : [{
            "type" : "arg",
            "name" : "script",
            "input_type" : "arg",
            "alert_type" : "WFArgToSink",
            "addedBy" : "r3x" 
        }]
    }

    def check_workflow_sinks(self, task : GHResuableTaskGroup, report : Report.WorkflowReport):
        assert isinstance(task, GHResuableTaskGroup), "check_workflow_sinks: task is not GHResuableTaskGroup"
        assert isinstance(report, Report.WorkflowReport), "check_workflow_sinks: report is not WorkflowReport"

        rworkflow = report.workflow
        for input in rworkflow.workflow_inputs:
            # We need to taint the args that are passed to the workflow 
            if input["name"] in [arg["name"] for arg in task.args]:
                continue
        
            self.taint_packed_data(
                [input],
                input_type="packed",
                output_type="arg",
                level=self.TASK_LEVEL
            )

        # Check if the workflow passes a tained argument to a sink
        self.check_packed_data(
            report.arg_to_sink,
            input_type="arg",
            alert_type="RWFArgToSink"
        )

        # Check if the workflow passes a context to the sink
        self.check_packed_data(
            report.context_to_sink,
            input_type="maketaint",
            alert_type="RWFContextToSink"
        )


    def check_action_sinks(self, task : GHActionTask, report : Report.ActionReport):
        assert isinstance(task, GHActionTask), "check_action_sinks: task is not GHActionTask"
        assert isinstance(report, Report.ActionReport), "check_action_sinks: report is not ActionReport"

        action = report.action

        # Taint all the default arguments
        for input in action.parsed_inputs:
            if input["name"] in [arg["name"] for arg in task.args]:
                continue
            
            self.taint_packed_data(
                [input],
                input_type="packed",
                output_type="arg",
                level=self.TASK_LEVEL
            )

        # Check if the action passes a tained argument to a sink
        self.check_packed_data(
            report.arg_to_sink,
            input_type="arg",
            alert_type="WFArgToSink"
        )

        # Check if the action passes a tained environment variable to a sink
        self.check_packed_data(
            report.env_to_sink,
            input_type="env",
            alert_type="WFEnvToSink"
        )

        # Check if any context is passed to a sink
        self.check_packed_data(
            report.context_to_sink,
            input_type="maketaint",
            alert_type="WFContextToSink"
        )

        # Check if there's a hardcoded sink
        if action.name in self.hardcoded_sinks:
            for sink in self.hardcoded_sinks[action.name]:
                self.check_packed_data(
                    [sink],
                    input_type=sink["input_type"],
                    alert_type=sink["alert_type"]
                )

    def propogate_workflow_taint(self, task : GHResuableTaskGroup, report : Report.WorkflowReport):
        assert isinstance(task, GHResuableTaskGroup), "propogate_workflow_taint: task is not GHResuableTaskGroup"
        assert isinstance(report, Report.WorkflowReport), "propogate_workflow_taint: report is not WorkflowReport"

        # Check if we have any taint going into an output
        self.taint_packed_data(
            report.arg_to_output,
            input_type="arg",
            output_type="output",
        )

        # Context to output
        self.taint_packed_data(
            report.context_to_output,
            input_type="context",
            output_type="output",
        )


    def propogate_action_taint(self, task : GHActionTask, report : Report.ActionReport):
        assert isinstance(task, GHActionTask), "propogate_action_taint: task is not GHActionTask"
        assert isinstance(report, Report.ActionReport), "propogate_action_taint: report is not ActionReport"
        
        # Then check if we have any taint going into an output
        self.taint_packed_data(
            report.arg_to_output,
            input_type="arg",
            output_type="output",
        )

        # Arg to env
        self.taint_packed_data(
            report.arg_to_env,
            input_type="arg",
            output_type="env",
            level=self.TASK_GROUP_LEVEL
        )

        # Env to output
        self.taint_packed_data(
            report.env_to_output,
            input_type="env",
            output_type="output",
        )

        # Env to env
        self.taint_packed_data(
            report.env_to_env,
            input_type="env",
            output_type="env",
            level=self.TASK_GROUP_LEVEL
        )

        # Context to output
        self.taint_packed_data(
            report.context_to_output,
            input_type="context",
            output_type="output",
        )

        # Context to env
        self.taint_packed_data(
            report.context_to_env,
            input_type="context",
            output_type="env",
            level=self.TASK_GROUP_LEVEL
        )       
        
#
# Check if a CIvar is tainted
#

    def contains_tainted_variable(self, object):
        # logger.debug(f"Checking CIvar {object}")
    
        source_set = []
        for civar in object["CIvars"]:
            taint_obj = self.is_tainted_variable(civar)
            if taint_obj:
                if isinstance(taint_obj, list):
                    source_set.extend(taint_obj)
                else:
                    source_set.append(taint_obj)
        return source_set

    def is_tainted_variable(self, civar) -> TaintObj:
        # logger.debug(f"Checking if {civar} is tainted")

        # check if it's a taint source
        if GithubCI.is_CIvar_tainted(civar):
            # Create a new taint object
            return TaintObj(
                    name=civar["expression"], 
                    type=civar["type"],
                    location=self.get_location(),
                    engine=self
                ) 

        if GithubCI.is_CIvar_tainted_object(civar):
            # Create a new taint object
            return TaintObj(
                    name=civar["expression"], 
                    type=civar["type"],
                    location=self.get_location(),
                    is_object=True,
                    engine=self
                )        

        if civar["type"] == "context":
            if civar["name"].startswith("event.inputs."):
                taint_obj = self.is_input_tainted(civar["name"][13:])
                if taint_obj:
                    return taint_obj

        # check if it's a step output that's tainted
        if civar["type"] == "steps":
            taint_obj = self.is_output_tainted(civar["name"])
            if taint_obj:
                return taint_obj

        # check if it's a job output that's tainted
        if civar["type"] == "needs":
            taint_obj = self.is_job_output_tainted(civar["name"])
            if taint_obj:
                return taint_obj

        if civar["type"] == "env":
            taint_obj = self.is_env_tainted(civar["name"])
            if taint_obj:
                return taint_obj

        if civar["type"] == "inputs":
            taint_obj = self.is_input_tainted(civar["name"])
            if taint_obj:
                return taint_obj

        return None
    
    def make_taint_object(self, packed_data : dict, output_type : str = ""):
        return TaintObj(
            name=packed_data["name"],
            type=packed_data["type"] if output_type == "" else output_type,
            parent_nodes=[],
            location=self.get_location(),
            engine=self
        )

#
# Taint addition 
#

    def taint_env(self, env : TaintObj, level : int):
        assert isinstance(env, TaintObj), "taint_env must be passed a TaintObj"
               
        if env in self.tainted_envs[level]:
            logger.debug(f"Env {env.name} already tainted at level {level}")
        else:
            logger.debug(f"Tainting env {env.name} at level {level}")
            self.tainted_envs[level].append(env)

    def taint_arg(self, arg : TaintObj):
        assert isinstance(arg, TaintObj), "taint_arg must be passed a TaintObj"

        if arg in self.tainted_args:
            logger.debug(f"Arg {arg.name} is already tainted")
        else:
            logger.debug(f"Tainting arg {arg.name}")
            self.tainted_args.append(arg)


    def taint_output(self, output : TaintObj):
        assert isinstance(output, TaintObj), "taint_output must be passed a TaintObj"
        logger.debug(f"Tainting output {output.name}")

        if self.current_task_group in self.tainted_outputs:
            task_outputs = self.tainted_outputs[self.current_task_group]
            if self.current_task in task_outputs:
                task_outputs[self.current_task].append(output)
            else:
                task_outputs[self.current_task] = [output]
        else:
            task_outputs = {}
            self.tainted_outputs[self.current_task_group] = task_outputs
            task_outputs[self.current_task] = [output]

    def taint_job_output(self, output):
        assert isinstance(output, TaintObj), "taint_job_output must be passed a TaintObj"

        logger.debug(f"Tainting job output {self.current_task_group} || {output}")
        if self.current_task_group in self.tainted_job_outputs:
            self.tainted_job_outputs[self.current_task_group].append(output)
        else:
            self.tainted_job_outputs[self.current_task_group] = [output]

    
# 
# Check if tainted
#
    def is_env_tainted(self, curr_env : str):
        assert isinstance(curr_env, str), "is_env_tainted must be passed a string"

        for level in self.TAINT_LEVELS:
            for env in self.tainted_envs[level]:
                if env.name == curr_env:
                    return env
        return None
    
    def is_tainted_arg(self, curr_arg : str):
        assert isinstance(curr_arg, str), "is_tainted_arg must be passed a string"

        for arg in self.tainted_args:
            if arg.name == curr_arg:
                logger.debug(f"Arg {curr_arg} is tainted")
                return arg
        logger.debug(f"Arg {curr_arg} is not tainted")
        return None

    def is_output_tainted(self, output : str):
        assert isinstance(output, str), "is_output_tainted must be passed a string"
        logger.debug(f"Checking if output {output} is tainted")

        if "==" in output:
            output = output.split("==")[0].strip()
        path = output.split(".")
        # IF path is only one element, then it's a task output
        if len(path) <= 1:
            if self.current_task_group in self.tainted_outputs:
                task_outputs = self.tainted_outputs[self.current_task_group]
                if self.current_task in task_outputs:
                    return task_outputs[self.current_task]    
            return None
        elif len(path) == 2:
            task_name, outputs = path
            assert outputs == "outputs", "is_output_tainted must be passed a string of the form task.outputs.output_name"
            if self.current_task_group in self.tainted_outputs:
                task_outputs = self.tainted_outputs[self.current_task_group]
                for task in task_outputs:
                    if task.id == task_name:
                        return task_outputs[task]
            return None 
        elif len(path) == 3:
            task_name, outputs, output_name = path
            assert outputs == "outputs", "is_output_tainted must be passed a string of the form task.outputs.output_name"
            if self.current_task_group in self.tainted_outputs:
                task_outputs = self.tainted_outputs[self.current_task_group]
                for task in task_outputs:
                    if task.id == task_name:
                        for curr_output in task_outputs[task]:
                            if curr_output.name == output_name:
                                return curr_output
        else:
            raise Exception(f"Output {output} is not a valid output")
        return None

    def is_job_output_tainted(self, output_name):
        assert isinstance(output_name, str), "is_job_output_tainted must be passed a string"

        path = output_name.split(".")
        if len(path) == 0:
            if output_name in self.tainted_job_outputs:
                return self.tainted_job_outputs[output_name]
            return None 
        elif len(path) == 1 or len(path) == 2:
            # this is passing the entire output object
            if path[0] in self.tainted_job_outputs:
                return self.tainted_job_outputs[path[0]]
            return None 
        elif path[1] == "outputs":
            if path[0] in self.tainted_job_outputs:
                for output in self.tainted_job_outputs[path[0]]:
                    if output.name == path[2]:
                        return output
        return None 

#
#  Input taint tracking features
# 

    def taint_input(self, input_obj : TaintObj):
        assert isinstance(input_obj, TaintObj), "taint_input must be passed a TaintObj"

        logger.debug(f"Tainting input {self.current_task_group} {input_obj.name}")
        if input_obj  in self.tainted_inputs:
            logger.debug(f"Input {input_obj.name} is already tainted")
        else:
            logger.debug(f"Tainting input {input_obj.name}")
            self.tainted_inputs.append(input_obj)
    
    def is_input_tainted(self, input_name : str):
        assert isinstance(input_name, str), "is_input_tainted must be passed a string"

        logger.debug(f"Checking if input {self.current_task_group} || {input_name} is tainted")
        for input_obj in self.tainted_inputs:
            if input_obj.name == input_name:
                return input_obj
        return None


#
#  Taint cleanup functions 
#

    def clear_taint_at_level(self, level):
        self.tainted_envs[level] = []
        self.tainted_args = []


#
# Raise alerts 
# 

    def raise_alert(self, alert_type, taint_obj, details={}):
        self.alerts.append({
            "type" : alert_type,
            "taint_obj" : taint_obj,
            "details" : details
        })

    def get_location(self):
        if self.override_location: 
            return self.override_location
    
        ret = ""        
        if self.curr_type == TaintEngine.WFL_MODE:
            ret += f"{self.workflow.wf_name} | "
        elif self.curr_type == TaintEngine.ACTION_MODE:
            ret += f"{self.action.action_name} | "    

        if self.current_task_group:
            ret += f"Job : {self.current_task_group.id} | "  
        else:
            raise Exception("No task group set")

        if self.current_task:
            ret += f"Step : {self.current_task.id} ({self.current_task.step_no}th step)"

        return ret

    def set_override_location(self, location : str):
        assert self.override_location is None, "Override location is already set"
        ret = ""
        if self.curr_type == TaintEngine.WFL_MODE:
            ret += f"{self.workflow.wf_name} | "
        elif self.curr_type == TaintEngine.ACTION_MODE:
            ret += f"{self.action.action_name} | "    
        ret += location

        self.override_location = ret

    def unset_override_location(self):
        self.override_location = None