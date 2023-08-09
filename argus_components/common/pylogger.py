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

import os
import logging
from colorlog import ColoredFormatter

log_level = logging.INFO
module_log_levels = {}
saved_logs = {}

def set_global_log_level(level):
    global log_level
    log_level = level

    for name, log in saved_logs.items():
        log.setLevel(level)

def set_module_log_level(module, level):
    global module_log_levels
    module_log_levels[module] = level

def get_logger(name, level = None):
    global log_level, saved_logs

    if name in saved_logs:
        return saved_logs[name]

    l = logging.getLogger(name)

    if level is None:
        l.setLevel(log_level)
    else:
        l.setLevel(level)

    logs_path = os.path.join(os.getcwd(), "logs")
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
        
    stream_h = logging.StreamHandler()
    #file_h = logging.FileHandler('logs/%s.log' % name)

    formatter = ColoredFormatter(
        "%(asctime)-s %(name)s [%(levelname)s] %(log_color)s%(message)s%(reset)s",
        datefmt=None, reset=True,
        log_colors={
            "DEBUG": "purple",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red",
        }
    )
    stream_h.setFormatter(formatter)
    l.addHandler(stream_h)
    
    # file_h.setFormatter(formatter)
    # l.addHandler(file_h)

    saved_logs[name] = l
    return l