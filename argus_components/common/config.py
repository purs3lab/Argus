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
import pathlib
import os

LOCAL_FOLDER : pathlib.Path = pathlib.Path('/tmp')
CODEQL_BIN : pathlib.Path = pathlib.Path('~/codeql_home/codeql/codeql')
QUERY_PATH : pathlib.Path = pathlib.Path(os.path.dirname(__file__)) / "../../qlqueries"
ENABLE_LOW_PRIORITY_REPORTS : bool = True
RESULTS_FOLDER : pathlib.Path = pathlib.Path("/results")

def parse_config(config_file : str):
    # open and read the config json file
    with open(config_file, 'r') as f:
        config = json.load(f)

    # local folder
    global LOCAL_FOLDER, CODEQL_BIN, QUERY_PATH, ENABLE_LOW_PRIORITY_REPORTS, RESULTS_FOLDER
    LOCAL_FOLDER = pathlib.Path(config['local_folder'])
    CODEQL_BIN = pathlib.Path(config['codeql_bin'])
    QUERY_PATH = pathlib.Path(config['query_path'])
    ENABLE_LOW_PRIORITY_REPORTS = config['enable_low_priority_reports']
    RESULTS_FOLDER = pathlib.Path(config['results_folder'])

