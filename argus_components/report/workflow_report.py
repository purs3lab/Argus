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

from .report import Report
import argus_components.ir as IR
import argus_components.ci as Github

class WorkflowReport(Report):
    
    def __init__(self, report_dict : dict, workflow_obj : IR.WorkflowIR):
        assert isinstance(report_dict, dict), "Report must be a dictionary"
        assert isinstance(workflow_obj, IR.WorkflowIR), "Workflow must be a WorkflowIR object"

        self.workflow : IR.WorkflowIR = workflow_obj
        self.workflow_path = workflow_obj.workflow_path
        self.parse_report(report_dict)

    def parse_report(self, report_dict):
        self.arg_to_sink = report_dict["ArgToSink"]
        self.context_to_sink = report_dict["ContextToSink"]

        self.arg_to_output = report_dict["ArgToOutput"]
        self.context_to_output = report_dict["ContextToOutput"]

    def get_report(self, output_file):
        run = sarif_om.Run(tool=sarif_om.Tool(driver=sarif_om.ToolComponent(name="Argus", version="0.1.1")), results=[])

        # Add ArgToSink results
        run.results.extend(self._convert_to_sarif_report(self.arg_to_sink, ("ArgToSink", 0), 
            message="[{severity}] Argument {name} flows to sink {sink_link}"))

        run.results.extend(self._convert_to_sarif_report(self.context_to_sink, ("ContextToSink", 1), 
            message="[{severity}] Context {name} flows to sink {sink_link}"))

        run.results.extend(self._convert_to_sarif_report(self.arg_to_output, ("ArgToOutput", 2), 
            message="[{severity}] Argument {name} flows to output {sink_link}"))

        run.results.extend(self._convert_to_sarif_report(self.context_to_output, ("ContextToOutput", 3), 
            message="[{severity}] Context {name} flows to output {sink_link}"))
        
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

    def _generate_sink_links(self, sinks):
        sink_str = ""
        for ctr, sink in enumerate(sinks):
            if 'sink' not in sink:
                sink['sink'] = 'Here'
            sink_str += f"[{sink['sink']}]({str(ctr)}),"
        return sink_str[:-1]

    def get_severity(self, reports_set):
        # Has secrets in it or permissions set
        if self.workflow.has_write_permissions or self.workflow.has_secrets:
            severity = Github.GithubCI.get_severity(reports_set['source'])

            if severity == "high": 
                return ("High Severity", "error")
            elif severity == "medium":
                return ("Medium Severity", "warning")
            else:
                return ("Low Severity", "note")
            # During evaluation we marked the action ones, now we don't have them
            # Need to get data from JS as to what the source is
        else:
            return ("Low Severity", "note")


    def _convert_to_sarif_report(self, reports_set, category, message="", severity="note"):
        results = []
        for issue in reports_set:
            # Add a new result for each issue
            result = sarif_om.Result(
                message=sarif_om.Message(
                    text=message.format(
                        name=issue['source'], 
                        sink_link=self._generate_sink_links(issue['sinks']),
                        severity=self.get_severity(issue)[0]
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
                level=self.get_severity(issue)[1]
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

