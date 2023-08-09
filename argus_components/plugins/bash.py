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

import re
from argus_components.ci import GithubCI
    
class Bash:

    @staticmethod
    def parse_bash_command(command : str):
        # first we get all the ENV variables from the command
        env_vars = re.findall(r"\$[A-Z_]+", command)
        all_env_vars = []
        for env_var in env_vars:
            all_env_vars.append({
                "name" : env_var,
                "type" : "env",
                "value" : "",
                "CIvars" : []
            })


        set_envs = []

        # Check if it contians a write to the GITHUB_ENV file
        github_env = re.compile(r"echo \"(?P<output_name>\w+?)=(?P<output_value>.*)\"[ \t]*>>[ \t]*\$GITHUB_ENV")
        github_env_matches = github_env.findall(command)
        for output_name, output_value in github_env_matches:
            set_envs.append({
                "name" : output_name,
                "value" : output_value,
                "type" : "env",
                "CIvars" : GithubCI.get_github_variables_from_string(output_value),
            })

        # Create regex to match env variables
        env_regex = r"::set-env name=(?P<env_name>\w+?)::(?P<env_value>.*)"
        env_matches = re.findall(env_regex, command)
        for env_name, env_value in env_matches:
            set_envs.append({
                "name" : env_name,
                "value" : env_value,
                "type" : "env",
                "CIvars" : GithubCI.get_github_variables_from_string(env_value),
            })
        
            # TODO: Create regex to match type1 set output commands
        set_outputs = []
        # Check if it contains a write to the GITHUB_OUTPUT file
        github_output = r"echo [\"\'](?P<output_name>\w+?)=(?P<output_value>.*)[\'\"][ \t]*>>[ \t\"]*\$GITHUB_OUTPUT[ \t\"]*"
        github_output_matches = re.findall(github_output, command)
        for output_name, output_value in github_output_matches:
            set_outputs.append({
                "name" : output_name,
                "value" : output_value,
                "type" : "output",
                "CIvars" : GithubCI.get_github_variables_from_string(output_value),
            })

        # Create a Regex to match outputs
        output_regex = r"::set-output name=(?P<output_name>\w+?)::(?P<output_value>.*)"
        # Match the regex
        output_matches = re.findall(output_regex, command)
        for output_name, output_value in output_matches:
            set_outputs.append({
                "name" : output_name,
                "value" : output_value,
                "type" : "output",
                "CIvars" : GithubCI.get_github_variables_from_string(output_value),
            })

        return {
            "env_vars" : all_env_vars,
            "set_envs" : set_envs,
            "set_outputs" : set_outputs,
        }