# -*- coding: utf-8 -*-
# Copyright 2023 Anders Håål
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Dict, List


class UserDTO:
    def __init__(self, login_name: str):
        self.login: str = login_name
        self.email: str = login_name
        self.name: str = login_name
        # The role for the user in the organisation
        self.role: str = 'Viewer'
        self.password: str = ''
        self.grafana_admin: bool = False


class TeamDTO:
    def __init__(self, name: str):
        # Name of the team
        self.name: str = name
        self.email: str = ''
        self.avatar_url: str = ''
        # member list of user login_name's
        self.members: List[str] = []
        # Todo Enterprise options
        # self.access_control: List[str] = []
        # self.sync_groups_id: List[str] = []


class OrganizationDTO:
    def __init__(self, name: str):
        # Organisation name
        self.name: str = name
        # List of users
        self.users: Dict[str, UserDTO] = {}
        # List of teams
        self.teams: Dict[str, TeamDTO] = {}
