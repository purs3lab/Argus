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

import json
import os
import pathlib
import subprocess
import urllib
from time import sleep

from argus_components.common.config import CODEQL_BIN, QUERY_PATH
from argus_components.common.pylogger import get_logger

logger = get_logger("repo")

DANGEROUS_SINKS_FILE = "DangerousSinks.bqrs"
LESS_DANGEROUS_SINKS_FILE = "LessDangerousSinks.bqrs"
ENV_SINKS_FILE = "EnvSinks.bqrs"
LESS_ENV_SINKS_FILE = "LessEnvSinks.bqrs"
ENV_OUTPUT_TAINTING_FILE = "EnvOutputTainting.bqrs"
OUTPUT_TAINTING_FILE = "OutputTainting.bqrs"
CONTEXT_SINKS_FILE = "ContextSinks.bqrs"
LESS_CONTEXT_SINKS_FILE = "LessContextSinks.bqrs"
CONTEXT_OUTPUT_FILE = "ContextOutput.bqrs"

ALL_FILES = [DANGEROUS_SINKS_FILE, LESS_DANGEROUS_SINKS_FILE, ENV_SINKS_FILE, 
             LESS_ENV_SINKS_FILE, ENV_OUTPUT_TAINTING_FILE, OUTPUT_TAINTING_FILE, 
             CONTEXT_SINKS_FILE, LESS_CONTEXT_SINKS_FILE, CONTEXT_OUTPUT_FILE]

def run_cmd(command, env=None, cwd=None, verbose=False, timeout=25 * 60, error_msg = "", raise_timeout=False):
    try:
        logger.debug(f"Running command : {command}\n with {cwd} and {env}")
        out = subprocess.run(
            command, env=env, shell=True, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if verbose:
            print(f"STDOUT has {out.stdout.decode('latin-1')}")
            print(f"STDERR has {out.stderr.decode('latin-1')}")
        return out.stdout.decode("latin-1"), out.stderr.decode("latin-1")
    except subprocess.TimeoutExpired as e:
        logger.error(f"The {error_msg} Command Timed out", extra={"cmd" : command, "error" : e})
        return "", ""
    except Exception as e:
        logger.exception(f"{error_msg} failed", extra={'cmd' : command, 'error' : e})


def parse_url(url):
    return urllib.parse.unquote(url)

def _check_if_db_exists(repo_path : pathlib.Path) -> bool:
    folder = repo_path / "db-javascript"
    if folder.exists() == False:
        return False
    return True

def _extract_db_error(repo_path : pathlib.Path, etype = "create") -> str:
    folder = repo_path / "log"
    if folder.exists() == False:
        return f"No log folder found in {folder} to parse error"
    return f"Check logs in log folder : {folder} to parse error"

class CodeQL:    
    # Create Codeql Database for the corresponding repository
    @staticmethod
    def compile_codeql_db(repo_path, output_dir):
        cmd = f"{CODEQL_BIN} database create --language=javascript --mode=brutal --finalize-dataset -s {repo_path} {output_dir}"
        run_cmd(cmd, verbose=True)
        if not _check_if_db_exists(output_dir):
            raise Exception(f"Error Creating DB : {repo_path}", _extract_db_error(repo_path))

    @staticmethod
    def is_valid_codeql_db(repo_path) -> bool:
        if not _check_if_db_exists(repo_path):
            return False
        return True
    
    @staticmethod
    def decode_bqrs(result_file : pathlib.Path, repo_path : pathlib.Path):
        if result_file.exists() == False:
            raise Exception(f"Unable to find ArgToSink  file - {result_file}", _extract_db_error(repo_path, "queries"))  
        
        # Decode the task
        cmd = f"{CODEQL_BIN} bqrs decode --entities=id,url,string --format json {result_file}"
        stdout, stderr = run_cmd(cmd)

        try:
            codeql_res = json.loads(stdout)
        except Exception as e:
            raise Exception(f"Unable to json parse ArgToSink  file - {result_file}", _extract_db_error(repo_path, "queries"))
        return codeql_res
        
    # Run Codeql Query
    @staticmethod
    def run_codeql_query(repo_path : pathlib.Path):
        cmd = f"{CODEQL_BIN} database run-queries --threads=2 {repo_path} {QUERY_PATH}"
        stdout, stderr = run_cmd(cmd, verbose=True)

        # if the query failed, raise an error
        if "A fatal error occurred" in stderr:
            raise Exception(f"Error Running Query : {repo_path} with Error Message on STDERR as : {stderr}", _extract_db_error(repo_path, "queries"))

        # Check if results are present
        folder = repo_path / "results/actions-codeql"
        if folder.exists() == False:
            raise Exception(f"No results folder found for {repo_path}", _extract_db_error(repo_path, "queries"))

    @staticmethod
    def parse_codeql_results(repo_path : pathlib.Path):
        folder = repo_path / "results/actions-codeql"
        if folder.exists() == False:
            raise Exception(f"No results folder found for {repo_path}", _extract_db_error(repo_path, "queries"))

        results = {}

        results["ArgToSink"] = _parse_ArgToSink_results(CodeQL.decode_bqrs(folder / DANGEROUS_SINKS_FILE, repo_path))
        results["ArgToLSink"] = _parse_ArgToSink_results(CodeQL.decode_bqrs(folder / LESS_DANGEROUS_SINKS_FILE, repo_path))
        
        results["EnvtoSink"] = _parse_EnvToSink_results(CodeQL.decode_bqrs(folder / ENV_SINKS_FILE, repo_path))
        results["EnvtoLSink"] = _parse_EnvToSink_results(CodeQL.decode_bqrs(folder / LESS_ENV_SINKS_FILE, repo_path))
        
        results["ArgToOutput"] = _parse_ArgToOutput_results(CodeQL.decode_bqrs(folder / OUTPUT_TAINTING_FILE, repo_path))
        results["EnvtoOutput"] = _parse_EnvToOutput_results(CodeQL.decode_bqrs(folder / ENV_OUTPUT_TAINTING_FILE, repo_path))
        
        results["ContextToSink"] = _parse_ContextToSink_results(CodeQL.decode_bqrs(folder / CONTEXT_SINKS_FILE, repo_path)) 
        results["ContextToLSink"] = _parse_ContextToSink_results(CodeQL.decode_bqrs(folder / LESS_CONTEXT_SINKS_FILE, repo_path))
        results["ContextToOutput"] = _parse_ContextToOutput_results(CodeQL.decode_bqrs(folder / CONTEXT_OUTPUT_FILE, repo_path))
        return results


    @staticmethod
    def query_results_present(repo_path : pathlib.Path) -> bool:
        folder = repo_path / "results/actions-codeql"
        if folder.exists():
            return True
        return False


"""
[{'id': 1370617, 'label': "'repository'", 
'url': {'uri': 'file:/home/r3x/projects/WorkflowAnalyzer/test/actions%23checkout/src/input-helper.ts', 'startLine': 22, 'startColumn': 19, 'endLine': 22, 'endColumn': 30}}, 
{'id': 6, 'label': "ghworkflow.ge ... itory')", 
'url': {'uri': 'file:/home/r3x/projects/WorkflowAnalyzer/test/actions%23checkout/src/input-helper.ts', 'startLine': 22, 'startColumn': 5, 'endLine': 22, 'endColumn': 31}}, 
{'id': 0, 'label': 'args',
'url': {'uri': 'file:/home/r3x/projects/WorkflowAnalyzer/test/actions%23checkout/src/git-command-manager.ts', 'startLine': 426, 'startColumn': 60, 'endLine': 426, 'endColumn': 63}},
 'exec']

Format : | Arg | Source | Sink | Function Name | 

Output:
{[
    {
        "name" : "<ArgName>",
        "source" : "<Source URI>",
        "sinks" : [
            {
                "function" : "<functionName>",
                "sink" : "<Sink URI>"
            },
            ... 
        ]
        "sinkset" : set(<functionNames>)
    },
]
}

"""
def _parse_ArgToSink_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []
    
    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # each row is a tuple
        # This is the label 
        action_arg_name = tuple[0]['label'].strip("'")

        # if the action_arg_name is already present in "name" field, skip it        
        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']), 
                "type" : "input",
                "sinks" : [],
                "sinkset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        })               

        # Add the sink to the list
        curr_arg["sinkset"].add(tuple[3])

    for arg in action_arg_set:
        arg["sinkset"] = list(arg["sinkset"])

    return action_arg_set 

def _parse_EnvToSink_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []
    
    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # each row is a tuple
        # This is the label 
        action_arg_name = tuple[0].strip("'")

        # if the action_arg_name is already present in "name" field, skip it        
        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']), 
                "type" : "env",
                "sinks" : [],
                "sinkset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        })               

        # Add the sink to the list
        curr_arg["sinkset"].add(tuple[3])

    for arg in action_arg_set:
        arg["sinkset"] = list(arg["sinkset"])

    return action_arg_set 

def _parse_ArgToOutput_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []

    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # This is the input argument name
        action_arg_name = tuple[0]['label'].strip("'")

        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']),
                "type" : "input",
                "sinks" : [],
                "outputset" : set(),
                "envset" : set(),
                "saveset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "name" : tuple[4],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        }) 

        if tuple[3] == "setOutput":
            curr_arg["outputset"].add(tuple[4])
        elif tuple[3] == "exportVariable":
            curr_arg["envset"].add(tuple[4])
        elif tuple[3] == "saveState":
            curr_arg["saveset"].add(tuple[4])

    for arg in action_arg_set:
        arg["outputset"] = list(arg["outputset"])
        arg["envset"] = list(arg["envset"])
        arg["saveset"] = list(arg["saveset"])        

    return action_arg_set

def _parse_EnvToOutput_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []

    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # This is the input argument name
        action_arg_name = tuple[0].strip("'")

        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']),
                "type" : "env",
                "sinks" : [],
                "outputset" : set(),
                "envset" : set(),
                "saveset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "name" : tuple[4],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        }) 

        if tuple[3] == "setOutput":
            curr_arg["outputset"].add(tuple[4])
        elif tuple[3] == "exportVariable":
            curr_arg["envset"].add(tuple[4])
        elif tuple[3] == "saveState":
            curr_arg["saveset"].add(tuple[4])

    for arg in action_arg_set:
        arg["outputset"] = list(arg["outputset"])
        arg["envset"] = list(arg["envset"])
        arg["saveset"] = list(arg["saveset"])        

    return action_arg_set

def _parse_ContextToSink_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []
    
    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # each row is a tuple
        # This is the label 
        action_arg_name = tuple[0]['label'].strip("'")

        # if the action_arg_name is already present in "name" field, skip it        
        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']), 
                "type" : "context",
                "sinks" : [],
                "sinkset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        })               

        # Add the sink to the list
        curr_arg["sinkset"].add(tuple[3])

    for arg in action_arg_set:
        arg["sinkset"] = list(arg["sinkset"])

    return action_arg_set 

def _parse_ContextToOutput_results(json_data : dict) -> list:
    if "#select" not in json_data:
        return []

    tuples = json_data["#select"]['tuples']

    if len(tuples) == 0:
        return []

    # Array of dicts to store the results
    action_arg_set = []
    action_name_set = []

    for tuple in tuples:
        # This is the input argument name
        action_arg_name = tuple[0]

        if action_arg_name in action_name_set:
            curr_arg = action_arg_set[action_name_set.index(action_arg_name)]
        else:
            action_name_set.append(action_arg_name)
            curr_arg = {
                "name" : action_arg_name,
                "source" : parse_url(tuple[1]['url']['uri']) + ":" + str(tuple[1]['url']['startLine']) + ":" + str(tuple[1]['url']['startColumn']),
                "type" : "context",
                "sinks" : [],
                "outputset" : set(),
                "envset" : set(),
                "saveset" : set()
            }
            action_arg_set.append(curr_arg)

        # Add the details of the sink to the arg_set
        curr_arg["sinks"].append({
            "function" : tuple[3],
            "name" : tuple[4],
            "sink" : parse_url(tuple[2]['url']['uri']) + ":" + str(tuple[2]['url']['startLine']) + ":" + str(tuple[2]['url']['startColumn'])
        }) 

        if tuple[3] == "setOutput":
            curr_arg["outputset"].add(tuple[4])
        elif tuple[3] == "exportVariable":
            curr_arg["envset"].add(tuple[4])
        elif tuple[3] == "saveState":
            curr_arg["saveset"].add(tuple[4])

    for arg in action_arg_set:
        arg["outputset"] = list(arg["outputset"])
        arg["envset"] = list(arg["envset"])
        arg["saveset"] = list(arg["saveset"])        

    return action_arg_set
