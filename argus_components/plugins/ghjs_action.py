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
import pathlib
import yaml

from .ghaction import GHAction
from argus_components.utils import CodeQL
from argus_components.common.config import LOCAL_FOLDER
from argus_components.common.pylogger import get_logger
from argus_components.report import ActionReport
import argus_components.ci as ci

logger = get_logger("ghjs_action")

class GHJSAction(GHAction):

    def __init__(self, action_name, action_path, action_folder, action_yml_path, action):
        self.action_name = action_name
        self.name = action_name.replace("#", "/")
        self.action_path = action_path
        self.action_folder : pathlib.Path = action_folder
        self.action_yml_path = action_yml_path
        self.action = action
        self.parsed_inputs = []
        self.parsed_outputs = []

    @staticmethod
    def detect_type(action_type):
        # call get_yaml_type from the superclass
        if action_type == "node16" or action_type == "node14" or action_type == "node12":
            return True
        return False

    def parse_inputs(self, yml):
        for input_name, input_value in yml.get("inputs", {}).items():
            self.parsed_inputs.append({
                "name": input_name,
                "type": "action_input",
                "required" : input_value.get("required", True),
                "value" : input_value.get("default", ""),
                "CIvars": ci.GithubCI.get_github_variables_from_string(input_value.get("default", ""))
            })

    def parse_outputs(self, yml):
        for output_name, output_value in yml.get("outputs", {}).items():
            self.parsed_outputs.append({
                "name": output_name,
                "type": "action_output",
                "value" : output_value.get("value", ""),
                "CIvars": ci.GithubCI.get_github_variables_from_string(output_value.get("value", ""))
            })


    def run(self):
        with open(self.action_yml_path, 'r') as f:
            action_yml = yaml.safe_load(f)
            self.parse_inputs(action_yml)
            self.parse_outputs(action_yml)

        # Run CodeQL
        codeql_folder = LOCAL_FOLDER / f"{self.action_name.replace('/', '#')}_codeql"

        if not codeql_folder.exists():
            logger.debug(f"Creating folder {codeql_folder}")
            CodeQL.compile_codeql_db(self.action_folder, codeql_folder)
        else:
            logger.debug(f"CodeQL folder {codeql_folder} already exists")

        # Run CodeQL query
        if CodeQL.query_results_present(codeql_folder):
            logger.debug(f"CodeQL query results already present in {codeql_folder}")
        else:
            logger.debug(f"Running CodeQL query in {codeql_folder}")
            results = CodeQL.run_codeql_query(codeql_folder)

        results = CodeQL.parse_codeql_results(codeql_folder)
        return ActionReport(results, self)