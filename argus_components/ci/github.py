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
from typing import List, Dict
from distutils.version import StrictVersion

from argus_components.common.pylogger import get_logger
logger = get_logger(__name__)

import re
    
class GithubCI:
    regex_strings_vars = [
        r"secrets.[A-Za-z0-9_\-.]+",
        r"github.[A-Za-z0-9_\-.]+",
        r"env.[A-Za-z0-9_\-.]+",
        r"steps.[A-Za-z0-9_\-.]+",
        r"matrix.[A-Za-z0-9_\-.]+",
        r"needs.[A-Za-z0-9_\-.]+",
        r"strategy.[A-Za-z0-9_\-.]+",
        r"runner.[A-Za-z0-9_\-.]+",
        r"job.[A-Za-z0-9_\-.]+",
        r"jobs.[A-Za-z0-9_\-.]+",
        r"inputs.[A-Za-z0-9_\-.]+",
        r"GITHUB_[A-Za-z0-9_\-.]+",
        r"RUNNER_[A-Za-z0-9_\-.]+",
    ]

    GITHUB_TAINT_CI_LIST = [
        r"event\.issue\.title",
        r"event\.issue\.body",
        
        r"event\.pull_request\.title",
        r"event\.pull_request\.body",
        r"event\.pull_request\.head\.ref",
        r"event\.pull_request\.head\.label",
        
        r"event\.discussion\.title",
        r"event\.discussion\.body",

        r"event\.comment\.body",
        
        r"event\.review\.body",
        r"event\.review_comment\.body",
        r"event\.pages.*\.page_name",
        
        r"event\.commits.*\.message",
        r"event\.commits.*\.author\.email",
        r"event\.commits.*\.author\.name",

        r"event\.head_commit\.message",
        r"event\.head_commit\.author\.email",
        r"event\.head_commit\.author\.name",
        r"event\.head_commit\.committer\.email",
        r"event\.head_commit\.committer\.name",

        r"event\.workflow_run\.head_branch",
        r"event\.workflow_run\.head_commit\.message",
        r"event\.workflow_run\.head_commit\.author\.email",
        r"event\.workflow_run\.head_commit\.author\.name",
        r"event\.workflow_run\.pull_requests.*\.head\.ref",
        r"head_ref",
    ]

    GITHUB_TAINT_SEVERITY = {
        r"event\.issue\.title" : "high",
        r"event\.issue\.body" : "high",
        
        r"event\.pull_request\.title" : "high",
        r"event\.pull_request\.body" : "high",
        r"event\.pull_request\.head\.ref" : "low",
        r"event\.pull_request\.head\.label" : "low",
        
        r"event\.discussion\.title" : "high",
        r"event\.discussion\.body" : "high",

        r"event\.comment\.body" : "high",
        
        r"event\.review\.body" : "high",
        r"event\.review_comment\.body" : "high",
        r"event\.pages.*\.page_name" : "high",
        
        r"event\.commits.*\.message" : "medium",
        r"event\.commits.*\.author\.email" : "medium",
        r"event\.commits.*\.author\.name" : "medium",

        r"event\.head_commit\.message" : "medium",
        r"event\.head_commit\.author\.email" : "medium",
        r"event\.head_commit\.author\.name" : "medium",
        r"event\.head_commit\.committer\.email" : "medium",
        r"event\.head_commit\.committer\.name" : "medium",

        r"event\.workflow_run\.head_branch" : "low",
        r"event\.workflow_run\.head_commit\.message" : "medium",
        r"event\.workflow_run\.head_commit\.author\.email" : "medium",
        r"event\.workflow_run\.head_commit\.author\.name" : "medium",
        r"event\.workflow_run\.pull_requests.*\.head\.ref" : "low",
        r"head_ref" : "low",
    }

    GITHUB_TAINT_CI_OBJECT_LIST = [
        "event.comment",
        
        "event.issue.pull_request",
        "event.issue",

        "event.pull_request",
        "event.pull_request.commits",
        "event.pull_request.head.repo",
        "event.pull_request.labels",
    
        "event.commits",
        
        "event.workflow_run",
        "event.workflow_run.pull_requests",
    ]

    GITHUB_TAINT_CI_OBJECT_SEVERITY = {
        "event.comment" : "medium", 
        
        "event.issue.pull_request" : "medium",
        "event.issue" : "medium",

        "event.pull_request" : "medium",
        "event.pull_request.commits" : "medium",
        "event.pull_request.head.repo" : "medium",
        "event.pull_request.labels" : "medium",
    
        "event.commits" : "medium",
        
        "event.workflow_run" : "medium",
        "event.workflow_run.pull_requests" : "medium",
    }


    @staticmethod
    def pack_to_dict_format(items_dict : dict, type : str): 
        ret = []
        if items_dict is None:
            return ret
        if isinstance(items_dict, str):
            return [{
                "type": type,
                "value": items_dict,
                "name": f"special_case_{type}",
                "CIvars" : GithubCI.get_github_variables_from_string(items_dict)
            }]

        for key, item in items_dict.items():
            ret.append({
                "type": type,
                "name": key,
                "value": item,
                "CIvars" : GithubCI.get_github_variables_from_string(item)
            })
        return ret

    @staticmethod
    def get_ci_vars_from_packed(packed : dict):
        ret = []
        for item in packed:
            ret.extend(item["CIvars"])
        return ret

    @staticmethod
    def get_severity(key : str):
        for regex, severity in GithubCI.GITHUB_TAINT_SEVERITY.items():
            if re.search(regex, key):
                return severity
        
        for regex, severity in GithubCI.GITHUB_TAINT_CI_OBJECT_SEVERITY.items():
            if re.search(regex, key):
                return severity
        
        # During evaluation we marked the action ones, now we don't have them
        # Need to get data from JS as to what the source is
        return "high"

        
    @staticmethod
    def get_github_variables_from_string(cmd_string : str) -> List[Dict[str, str]]:
        """
        Returns a dictionary of GitHub variables from a string.
        """
        # GitHub variables are in the form of ${{VAR_NAME}}
        # This regex matches the variable name
        if not isinstance(cmd_string, str):
            # log the type of the cmd_string
            logger.debug(f"cmd_string is not a string. It is of type {type(cmd_string)}")
            return []

        # Use a more complex regex
        #regex = r"\${{([a-zA-Z.\-_\(\)= ]+)}}"
        # TODO: check with the team
        # Catch both ${{VAR}} and ${{VAR}}
        regex = r"\${+(.*?)}+"
        matches = re.findall(regex, cmd_string)

        results = []
        for match in matches:
            # Remove leading and trailing whitespace
            match = match.strip()

            # try to parse it as a github variable
            result = GithubCI.parse_github_var(match)
            if result:
                # check if the result's expression is already in the results
                if result["expression"] not in [x["expression"] for x in results]:
                    results.append(result)
            
            # There is a chance that it might be a function
            # merge results with the results from the function and skip duplicates
            results.extend([x for x in GithubCI.parse_github_function(match) if x not in results])

        return results
    
        
    @staticmethod
    def parse_github_function(func_str : str):
        """
        Check if the string is a github defined function name
        """
        results = []
        for regexstr in GithubCI.regex_strings_vars:
            matches = re.findall(regexstr, func_str)
            for match in matches:
                result = GithubCI.parse_github_var(match)
                # avoid duplicates, by checking the expression
                if result and result["expression"] not in [x["expression"] for x in results]:
                    is_duplicate = False
                    for x in results:
                        if result["expression"] in x["expression"]:
                            is_duplicate = True
                            break
                    if not is_duplicate:
                        results.append(result)
        return results


    @staticmethod
    def parse_github_var(match : str):
        match_strings = {
            "secrets." : "secret",
            "github." : "context",
            "GITHUB_" : "context",
            "env." : "env",
            "steps." : "steps",
            "runner." : "runner",
            "RUNNER_" : "runner",
            "job." : "job",
            "matrix." : "matrix",
            "strategy." : "strategy",
            "needs." : "needs",
            "inputs." : "inputs",
            "jobs." : "jobs",
        }       

        def pack_to_dict(match, type) -> Dict[str, str]:
            name = match
            if "." in name:
                name = name.split(".", 1)[1]
                # IDK why I added this,
                # but if there are error, remove this
                if " " in name:
                    name = name.split(" ", 1)[0]
            return {
                "name" : name,
                "expression" : f"{match}",
                "type" : type
            }


        for match_str, type in match_strings.items():
            if match.startswith(match_str):
                return pack_to_dict(match, type)
        return None

    @staticmethod
    def is_CIvar_tainted(ci_var : dict, CIplatfrom : str = "github"):
        '''
            Check if the current CI variable is tainted or not
            Return True if it is supposed to be tainted
            This only accounts for the CI variables that can be controlled by some attacker

        Sample ci_var:
            {   
                "name" : env_name,
                "expression" : f"{match}",
                "type" : "env"
            }

        
            Currently only supports Github CI variables
        '''

        if ci_var["type"] == "context":
            # check if the context variable matches any of the regex
            # expressions in GITHUB_TAINT_CI_LIST
            for regexstr in GithubCI.GITHUB_TAINT_CI_LIST:
                if re.match(regexstr, ci_var["name"]):
                    return True
        return False

    @staticmethod
    def is_CIvar_tainted_object(ci_var : dict, CIplatfrom : str = "github"):
        if ci_var["type"] == "context":
            # check if the context variable matches any of the regex
            # expressions in GITHUB_TAINT_CI_LIST
            for rstr in GithubCI.GITHUB_TAINT_CI_OBJECT_LIST:
                if rstr == ci_var["name"]:
                    return True
        return False

    @staticmethod
    def is_CIvar_tainted_dual(ci_var : dict, CIplatform : str = "github"):
        return GithubCI.is_CIvar_tainted(ci_var, CIplatform) or GithubCI.is_CIvar_tainted_object(ci_var, CIplatform)

    @staticmethod    
    def get_option_dict_from_sting(version):
        if version == None:
            raise Exception("Version cannot be None")
        if len(version) == 40:
            try:
                int(version, 16)
                return {"type" : "commit", "value" : version}
            except Exception:
                pass
        elif version.startswith("v") and GithubCI.is_version_number(version[1:]):
            return {"type" : "tag", "value" : version}
        elif version == "latest":
            return {"type" : "tag", "value" : version}
        elif version.startswith("releases/v") and GithubCI.is_version_number(version[11:]):
            return {"type" : "tag", "value" : version}
        else:
            if GithubCI.is_version_number(version.strip()): 
                return {"type" : "tag", "value" : version}
            else:
                return {"type" : "branch", "value" : version}

    @staticmethod    
    def is_version_number(number):
        # Try to convert to int
        try:
            int(number)
            return True
        except Exception:
            pass
        # try to convert to version number
        try:
            StrictVersion(number)
            return True
        except Exception:
            return False