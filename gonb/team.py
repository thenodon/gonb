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

from typing import List, Dict, Any, Set

from gonb.folder import Folder

default_team_roles = [
    'fixed:datasources:reader',
    'fixed:datasources:explorer',
    'fixed:alerting.rules:reader',
    'fixed:alerting.rules:writer',
    'fixed:alerting.notifications:reader'
]


class AccessControl:
    """
    AccessControl is just for enterprise
    """
    def __init__(self):
        self.name: str = ''
        self.description: str = ''
        self.display_name: str = ''
        self.global_global: bool = False
        self.group: str = ''
        self.uid: str = ''


def access_control_factory(access_control_data: Dict[str, Any]) -> AccessControl:
    access_control = AccessControl()
    access_control.name = access_control_data['name']
    access_control.description = access_control_data['description']
    access_control.display_name = access_control_data['displayName']
    access_control.global_global = access_control_data['global']
    access_control.group = access_control_data['group']
    access_control.uid = access_control_data['uid']
    return access_control


class Team:
    def __init__(self):
        self.org_id: int = None
        self.team_id: int = None
        self.name: str = ''
        self.email: str = ''
        self.avatar_url: str = ''
        self.folder: Folder = None
        # A set of username - these user must exist in the organisation
        self.members: Set[str] = set()

        # Enterprise
        self.access_control: Dict[str, AccessControl] = {}
        self.sync_groups_id: List[str] = []

    def valid_members(self, organization_users: Set[str]) -> bool:
        return self.members.issubset(organization_users)


def team_factory(team_data: Dict[str, Any]) -> Team:
    team = Team()
    team.team_id = team_data['id']
    team.org_id = team_data['orgId']
    team.name = team_data['name']
    team.email = team_data['email']
    team.avatar_url = team_data['avatarUrl']
    team.folder_permission = team_data['permission']

    if 'accessControl' in team_data and team_data['accessControl']:
        team.access_control = team_data['accessControl']
    if 'syncGroupsId' in team_data and team_data['syncGroupsId'] and issubclass(team_data['syncGroupsId'], list):
        team.sync_groups_id = team_data['syncGroupsId']

    return team

