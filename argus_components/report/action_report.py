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

import sarif_om
from jschema_to_python.to_json import to_json

from argus_components.common.config import ENABLE_LOW_PRIORITY_REPORTS
import argus_components.plugins as plugins

from .report import Report

class ActionReport(Report):
    SAFE_ENV = [
      "GITHUB_ACTION", "GITHUB_ACTION_PATH", "GITHUB_ACTION_REPOSITORY", "GITHUB_ACTIONS",
      "GITHUB_ACTOR", "GITHUB_API_URL", "GITHUB_BASE_REF", "GITHUB_ENV", "GITHUB_EVENT_NAME",
      "GITHUB_EVENT_PATH", "GITHUB_GRAPHQL_URL", "GITHUB_JOB", "GITHUB_PATH", "GITHUB_REF",
      "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER",
      "GITHUB_SERVER_URL", "GITHUB_SHA", "GITHUB_WORKFLOW", "GITHUB_WORKSPACE"
    ]
    
    def __init__(self, report_dict : dict, action):
        self.action = action
        if isinstance(action, plugins.GHJSAction):
            self.parse_js_report(report_dict)
        elif isinstance(action, plugins.GHCompositeAction):
            self.parse_composite_report(report_dict)
        elif isinstance(action, plugins.GHDockerAction):
            self.parse_docker_report(report_dict)
        else:
            raise Exception("Unknown action type")

    def parse_docker_report(self, report_dict):
        # Sinks
        self.arg_to_sink = []
        # Composite action can't be passed environment variables
        self.env_to_sink = []
        # context to sink
        self.context_to_sink = []

        # Propagations 
        self.arg_to_output = []
        self.env_to_output = []
        self.arg_to_env = [] 
        self.env_to_env = []
        self.context_to_output = []
        self.context_to_env = []



    def parse_js_report(self, report_dict):
        """
        report looks like -
        {'ArgToSink': [{'name': '"wxhook"', 'source': 'file:/tmp/TDesignOteam#create-report/daily-issue.js:6:16', 'type': 'input', 'sinks': [{'function': 'exec', 'sink': 'file:/tmp/TDesignOteam#create-report/daily-issue.js:26:5'}, {'function': 'exec', 'sink': 'file:/tmp/TDesignOteam#create-report/daily-xiaolv.js:85:9'}], 'sinkset': ['exec']}], 'ArgToLSink': [], 'EnvtoSink': [], 'EnvtoLSink': [], 'ArgToOutput': [], 'EnvtoOutput': [], 'ContextToSink': [{'name': 'context ... e.title', 'source': 'file:/tmp/TDesignOteam#create-report/daily-issue.js:11:15', 'type': 'context', 'sinks': [{'function': 'exec', 'sink': 'file:/tmp/TDesignOteam#create-report/daily-issue.js:26:5'}], 'sinkset': ['exec']}], 'ContextToLSink': [], 'ContextToOutput': []}
        """
        if ENABLE_LOW_PRIORITY_REPORTS:
            self.arg_to_sink = self._convert_to_packed_format(report_dict['ArgToSink'] + report_dict['ArgToLSink'])
            self.env_to_sink = self._convert_to_packed_format(report_dict['EnvtoSink'] + report_dict['EnvtoLSink'], filter_func = lambda report: report["name"] not in ActionReport.SAFE_ENV)
            self.context_to_sink = self._convert_to_packed_format(report_dict['ContextToSink'] + report_dict['ContextToLSink'])
        else:
            self.arg_to_sink = self._convert_to_packed_format(report_dict['ArgToSink'])
            self.env_to_sink = self._convert_to_packed_format(report_dict['EnvtoSink'], filter_func = lambda report: report["name"] not in ActionReport.SAFE_ENV)
            self.context_to_sink = self._convert_to_packed_format(report_dict['ContextToSink'])

        self.arg_to_output = self._convert_to_packed_format(report_dict['ArgToOutput'], function_name = "setOutput")
        self.env_to_output = self._convert_to_packed_format(report_dict['EnvtoOutput'], function_name = "setOutput", filter_func = lambda report: report["name"] not in ActionReport.SAFE_ENV)
        self.context_to_output = self._convert_to_packed_format(report_dict['ContextToOutput'], function_name = "setOutput")
        self.context_to_env = self._convert_to_packed_format(report_dict['ContextToOutput'], function_name = "exportVariable") 
        self.arg_to_env = self._convert_to_packed_format(report_dict['ArgToOutput'], function_name = "exportVariable")
        self.env_to_env = self._convert_to_packed_format(report_dict['EnvtoOutput'], function_name = "exportVariable", filter_func = lambda report: report["name"] not in ActionReport.SAFE_ENV)

    def _convert_to_packed_format(self, reports, filter_func = None, function_name = ""):
        final_reports = []
        for report in filter(filter_func, reports):
            final_reports.append({
                "source": report["name"],
                "name": report["name"], # Name of the argument or context
                "type": report["type"], # type - arg, env, context
                "source_location" : report["source"],
                "source_type": report["type"],
                "sinks" : []
            })
            
            for sink in report["sinks"]:
                if function_name == "" or sink["function"] == function_name:
                    final_reports[-1]["sinks"].append({
                        "sink": sink["function"],
                        "name": sink.get("name", ""), # Name of the taint
                        "taint_name": sink.get("name", ""), # Name of the taint
                        "sink_location": sink["sink"],
                    })
        return final_reports

    def parse_composite_report(self, report_dict):
        # Sinks
        self.arg_to_sink = report_dict['ArgToSink']
        # Composite action can't be passed environment variables
        self.env_to_sink = []
        # context to sink
        self.context_to_sink = report_dict['ContextToSink']

        # Propagations 
        self.arg_to_output = report_dict['ArgToOutput']
        self.env_to_output = []
        self.arg_to_env = [] 
        self.env_to_env = []
        self.context_to_output = report_dict['ContextToOutput']
        self.context_to_env = []

    def get_report(self, output_file):
        if isinstance(self.action, plugins.GHJSAction):
            return self.get_js_report(output_file)
        elif isinstance(self.action, plugins.GHCompositeAction):
            return self.get_composite_report(output_file)

    def get_js_report(self, output_file):

        run = sarif_om.Run(tool=sarif_om.Tool(driver=sarif_om.ToolComponent(name="Argus", version="0.1.1")), results=[])
        
        run.results.extend(self._convert_to_sarif_report(self.arg_to_sink, ("ArgToSink", 0), 
            message="An input argument ({name}) is being passed into a dangerous sink ({sink_link}). It is possible that a user of this action could pass in a tainted parameter that could cause the action to behave in an unexpected way.",
            severity="warning"))
        
        run.results.extend(self._convert_to_sarif_report(self.env_to_sink, ("EnvToSink", 1),
            message="An environment variable ({name}) is being passed into a dangerous sink ({sink_link}). It is possible that a user of this action could pass in a tainted parameter that could cause the action to behave in an unexpected way.",
            severity="warning"))
        
        run.results.extend(self._convert_to_sarif_report(self.context_to_sink, ("ContextToSink", 2),
            message="A tainted Context Variable ({name}) is being passed into a dangerous sink ({sink_link}). It is possible that a user of this action could pass in a tainted parameter that could cause the action to behave in an unexpected way.",
            severity="error"))

        run.results.extend(self._convert_to_sarif_report(self.arg_to_output, ("ArgToOutput", 3),
            message="An input argument ({name}) is being passed back as an output ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))

        run.results.extend(self._convert_to_sarif_report(self.arg_to_env, ("ArgToEnv", 4),
            message="An input argument ({name}) is being passed back as an environment variable ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))

        run.results.extend(self._convert_to_sarif_report(self.context_to_output, ("ContextToOutput", 5),
            message="A tainted Context Variable ({name}) is being passed back as an output ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))
        
        run.results.extend(self._convert_to_sarif_report(self.context_to_env, ("ContextToEnv", 6),
            message="A tainted Context Variable ({name}) is being passed back as an environment variable ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))            

        sarif_report = sarif_om.SarifLog(
            schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version="2.1.0",
            runs=[run]
        )

        if output_file == None:
            print(to_json(sarif_report))
        else:
            with open(output_file, "w") as f:
                f.write(to_json(sarif_report))

    def _convert_to_sarif_report(self, reports_set, category, message="", severity="note"):
        results = []
        for issue in reports_set:
            # Add a new result for each issue

            result = sarif_om.Result(
                message=sarif_om.Message(
                    text=message.format(
                        name=issue['source'], 
                        sink_link=self._generate_sink_links(issue['sinks'])
                    )
                ),
                locations=[
                    sarif_om.Location(
                        physical_location=sarif_om.PhysicalLocation(
                            artifact_location=sarif_om.ArtifactLocation(uri=issue['source_location']),
                            region=sarif_om.Region(start_line=int(issue['source_location'].split(":")[-2]))
                        )
                    )
                ],
                related_locations=[],
                rule_id=category[0],
                rule_index=category[1],
                level=severity
            )
            
            for ctr, sink in enumerate(issue['sinks']):
                result.related_locations.append(
                    sarif_om.Location(
                        id=ctr,
                        physical_location=sarif_om.PhysicalLocation(
                            artifact_location=sarif_om.ArtifactLocation(uri=sink['sink_location']),
                            region=sarif_om.Region(start_line=int(sink['sink_location'].split(":")[-2]))
                        )
                    )
                )
            results.append(result)
        return results
    
    def _generate_sink_links(self, sinks):
        sink_str = ""
        for ctr, sink in enumerate(sinks):
            if 'sink' not in sink:
                sink['sink'] = 'Here'
            sink_str += f"[{sink['sink']}]({str(ctr)}),"
        return sink_str[:-1]

    def get_composite_report(self, output_file):


        run = sarif_om.Run(tool=sarif_om.Tool(driver=sarif_om.ToolComponent(name="Argus", version="0.1.1")), results=[])
        
        run.results.extend(self._convert_to_sarif_report_no_loc(self.arg_to_sink, ("ArgToSink", 0), 
            message="An input argument ({name}) is being passed into a dangerous sink ({sink_link}). It is possible that a user of this action could pass in a tainted parameter that could cause the action to behave in an unexpected way.",
            severity="warning"))

        run.results.extend(self._convert_to_sarif_report_no_loc(self.context_to_sink, ("ContextToSink", 1),
            message="A tainted Context Variable ({name}) is being passed into a dangerous sink ({sink_link}). It is possible that a user of this action could pass in a tainted parameter that could cause the action to behave in an unexpected way.",
            severity="error"))
        
        run.results.extend(self._convert_to_sarif_report_no_loc(self.arg_to_output, ("ArgToOutput", 2),
            message="An input argument ({name}) is being passed back as an output ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))
    
        run.results.extend(self._convert_to_sarif_report_no_loc(self.context_to_output, ("ContextToOutput", 3),
            message="A tainted Context Variable ({name}) is being passed back as an output ({sink_link}). It is possible that a user of this action could use this output in an insecure manner.",
            severity="note"))

        sarif_report = sarif_om.SarifLog(
            schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version="2.1.0",
            runs=[run]
        )
        
        if output_file == None:
            print(to_json(sarif_report))
        else:
            with open(output_file, "w") as f:
                f.write(to_json(sarif_report))
    
    def _convert_to_sarif_report_no_loc(self, reports_set, category, message="", severity="note"):
        results = []
        for issue in reports_set:
            # Add a new result for each issue
            result = sarif_om.Result(
                message=sarif_om.Message(
                    text=message.format(
                        name=issue['source'], 
                        sink_link=self._generate_sink_links(issue['sinks'])
                    )
                ),
                locations=[
                    sarif_om.Location(
                        physical_location=sarif_om.PhysicalLocation(
                            artifact_location=sarif_om.ArtifactLocation(uri=issue['source_location']),
                        )
                    )
                ],
                related_locations=[],
                rule_id=category[0],
                rule_index=category[1],
                level=severity
            )
            
            for ctr, sink in enumerate(issue['sinks']):
                result.related_locations.append(
                    sarif_om.Location(
                        id=ctr,
                        physical_location=sarif_om.PhysicalLocation(
                            artifact_location=sarif_om.ArtifactLocation(uri=sink['sink_location']),
                        )
                    )
                )
            results.append(result)
        return results