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


import git
import pathlib
from .pylogger  import get_logger

logger = get_logger("git_utils")

def clone_repo(repo_url, folder : pathlib.Path, option_dict):
    if not folder.exists():
        logger.debug(f"Cloning repo {repo_url} to {folder}")
        folder.mkdir(parents=True)
        try:
            git.Repo.clone_from(repo_url, folder)
            git_handle(folder, option_dict)
        except Exception as e:
            logger.error(f"Could not clone action {repo_url} - {e}")
            raise e
    else:
        logger.debug(f"Repo {repo_url} already exists at {folder}! Not cloning again.")
        git_handle(folder, option_dict)
    return folder

def git_handle(folder : pathlib.Path, option_dict):
    repo = git.Repo(folder)
    if option_dict.get("type") == "branch":
        git_switch_to_branch(folder, option_dict.get("value"))
    elif option_dict.get("type") == "tag":
        git_switch_to_tag(folder, option_dict.get("value"))
    elif option_dict.get("type") == "commit":
        git_switch_to_commit(folder, option_dict.get("value"))

def get_current_HEAD(repo : git.repo):
    try:
        return repo.active_branch.name
    except TypeError:
        return repo.head.commit.hexsha

# Open the given repository and check if the given branch is used, if not switch to it.
def git_switch_to_branch(repo_path, branch_name):
    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        logger.error("Error creating repo object %s: %s" % (repo_path, e))
        return False
    
    logger.info(f"Repo : {repo_path} | Branch : {branch_name} | Current branch : {get_current_HEAD(repo)}")

    try: 
        # git stash
        repo.git.stash()
    except Exception as e:
        logger.error("Error stashing changes %s: %s" % (repo_path, e))

    try:
        if get_current_HEAD(repo) != branch_name:
            repo.git.checkout(branch_name)
    except Exception as e:
        logger.error("Error switching to branch %s: %s" % (branch_name, e))
        return False
    return True

# Open the given repository and check if the given tag exists, if not switch to it.
def git_switch_to_tag(repo_path, tag_name):
    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        logger.error("Error creating repo object %s: %s" % (repo_path, e))
        return False

    logger.info(f"Repo : {repo_path} | Tag : {tag_name} | Current branch : {get_current_HEAD(repo)}")
    try: 
        # git stash
        repo.git.stash()
    except Exception as e:
        logger.error("Error stashing changes %s: %s" % (repo_path, e))
    
    try: 
        repo.git.checkout(tag_name)
    except Exception as e:
        logger.error("Error switching to tag %s: %s" % (tag_name, e))
        return False
    return True

# Open the given repository and check if the given commit exists, if not switch to it.
def git_switch_to_commit(repo_path, commit_hash):
    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        logger.error("Error creating repo object %s: %s" % (repo_path, e))
        return False

    logger.info(f"Repo : {repo_path} | Commit : {commit_hash} | Current branch : {get_current_HEAD(repo)}")
    try: 
        # git stash
        repo.git.stash()
    except Exception as e:
        logger.error("Error stashing changes %s: %s" % (repo_path, e))

    try: 
        repo.git.checkout(commit_hash)
    except Exception as e:
        logger.error("Error switching to commit %s: %s" % (commit_hash, e))
        return False
    return True

# Open the given repository and revert the last checkout that was made.
def git_revert_checkout(repo_path):
    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        logger.error("Error creating repo object %s: %s" % (repo_path, e))
        return False

    logger.info(f"Repo : {repo_path} | Current branch : {get_current_HEAD(repo)}")
    try: 
        # git stash
        repo.git.stash()
    except Exception as e:
        logger.error("Error stashing changes %s: %s" % (repo_path, e))

    try: 
        repo.git.checkout("-")
    except Exception as e:
        logger.error("Error reverting checkout: %s" % e)
        return False
    return True
