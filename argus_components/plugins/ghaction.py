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

class GHAction:
    target_classes = []
    
    def __init__(self, action_url, options_dict):
        self.action_url = action_url
        self.options_dict = options_dict
        self.parsed_inputs = []
        self.parsed_outputs = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)
    
    @staticmethod    
    def identify_action(action_name, action_path, action_folder, action):
        action_yml_path = GHAction.find_action_yml(action_folder, action_name, action_path)
        if action_name == None:
            raise Exception("Invalid action url")
        for cls in GHAction.target_classes:
            if cls.detect_type(GHAction.get_yaml_type(action_yml_path)):
                return cls(action_name, action_path, action_folder, action_yml_path, action)
        raise NotImplementedError

    @staticmethod
    def find_action_yml(action_folder, action_name, action_path):
        if action_path == None:
            action_yml_path = action_folder / "action.yml"
        else:
            action_yml_path = action_folder / action_path / "action.yml"
        if not action_yml_path.exists():
            if action_path != None:
                action_yml_path = action_folder / action_path / "action.yaml"
            else:
                action_yml_path = action_folder / "action.yaml"
            if not action_yml_path.exists():
                if action_path == None:
                    raise Exception("Invalid action! action.yml not found at " + str(action_folder))
                else:
                    raise Exception("Invalid action! action.yml not found at " + str(action_folder / action_path))
        return action_yml_path

    @staticmethod
    def get_yaml_type(action_yml_path):
        with open(action_yml_path, 'r') as stream:
            try:
                action_yml = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                raise Exception("Invalid action.yml")

        try:
            return action_yml["runs"]["using"]
        except KeyError:
            # This should be plugin, but I am lazy to add it anyways
            return "docker"


