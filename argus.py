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

import click
import logging

import argus_components
from argus_components.common.config import parse_config
from argus_components.common.pylogger import set_global_log_level

@click.command()
@click.option("--mode", type=click.Choice(['repo', 'action']), required=True, help="The mode of operation. Choose either 'repo' or 'action'.")
@click.option("--url", required=True, type=str, help="The GitHub URL. use USERNAME:TOKEN@URL for private repos.")
@click.option("--output-folder", required=False, default="/tmp", help="The output folder.", type=click.Path(exists=True))
@click.option("--config", required=False, default=None, help="The config file.", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, default=False, help="Verbose mode.")
@click.option("--branch", default=None, type=str, help="The branch name.")
@click.option("--commit", default=None, type=str, help="The commit hash.")
@click.option("--tag", default=None, type=str, help="The tag.")
@click.option("--action-path", default=None, type=str, help="The (relative) path to the action.")
@click.option("--workflow-path", default=None, type=str, help="The (relative) path to the workflow.")
def main(mode, url, branch, commit, tag, output_folder, config, verbose, action_path, workflow_path):

    if verbose:
        set_global_log_level(logging.DEBUG)
    else:
        set_global_log_level(logging.INFO)

    options = [branch, commit, tag]
    options_names = ['branch', 'commit', 'tag']
    num_of_options_provided = sum(option is not None for option in options)

    if num_of_options_provided > 1:
        raise click.BadParameter("You must provide exactly one of: --branch, --commit, --tag")

    option_provided, option_value = next(((name, value) for name, value in zip(options_names, options) if value is not None), (None, None))

    if config:
        parse_config(config)

    option_dict = {
        "type": option_provided,
        "value": option_value
    } if option_provided and option_value else {}

    if mode == "repo":
        if action_path:
            raise click.BadParameter("You cannot provide --action-path in repo mode.")

        repo = argus_components.Repo(url, option_dict)
        repo.run(workflow_path)
        # repo.print_report()
        repo.save_report_to_file()
    elif mode == "action":
        if workflow_path:
            raise click.BadParameter("You cannot provide --workflow-path in action mode.")
        
        action = argus_components.Action(url, option_dict, action_path)
        action.run()
        # action.print_report()
        action.save_report_to_file()


if __name__ == "__main__":
    main()
