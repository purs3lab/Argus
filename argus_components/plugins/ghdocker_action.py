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

import yaml
from .ghaction import GHAction

from argus_components.report import ActionReport
import argus_components.ci as ci

class GHDockerAction(GHAction):

    def __init__(self, action_name, action_path, action_folder, action_yml_path, action):
        self.action_name = action_name
        self.name = action_name.replace("#", "/")
        self.action_path = action_path
        self.action_folder = action_folder
        self.action_yml_path = action_yml_path
        self.action = action
        self.parsed_inputs = []
        self.parsed_outputs = []

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

    @staticmethod
    def detect_type(action_type):
        # call get_yaml_type from the superclass
        if action_type == "docker":
            return True
        return False

    def run(self):
        # read action_yml_path
        with open(self.action_yml_path, 'r') as f:
            action_yml = yaml.safe_load(f)
            self.parse_inputs(action_yml)
            self.parse_outputs(action_yml)
        return ActionReport({}, self)