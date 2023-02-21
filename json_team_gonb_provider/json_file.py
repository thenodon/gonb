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

import json
import logging as log
import os
from typing import Dict

from gonb.grafana import provision
from gonb.provider import Provider, ProviderException
from gonb.organisation_transfer import TeamDTO, UserDTO, OrganizationDTO

GONB_JSON_FILE = 'GONB_JSON_FILE'


env_vars = {GONB_JSON_FILE: 'The json file name'}


class JSONFileException(Exception):
    def __init__(self, message):
        super().__init__(message)


class JSONFile(Provider):
    def __init__(self):
        if not os.getenv(GONB_JSON_FILE):
            log.error("Missing  mandatory environment variables", extra=env_vars)
            raise ProviderException('Missing mandatory environment variables')

    def mandatory_env_vars(self) -> Dict[str, str]:
        return env_vars

    def get_organisations(self) -> Dict[str, OrganizationDTO]:
        """
        Get all users in the groups
        :return:
        """

        # Get all customer groups
        orgs: Dict[str, OrganizationDTO] = {}
        with open(os.getenv(GONB_JSON_FILE)) as org_file:
            data = json.load(org_file)
            for org_data in data:
                org = OrganizationDTO(name=org_data['organisation'])
                orgs[org.name] = org

                if 'teams' in org_data:
                    for team_data in org_data['teams']:
                        team = TeamDTO(name=team_data['team'])
                        if 'members' in team_data:
                            for member in team_data['members']:
                                team.members.append(member['name'])
                        org.teams[team.name] = team

                if 'users' in org_data:
                    for user_data in org_data['users']:

                        user = UserDTO(login_name=user_data['email'])
                        if 'password' in user_data and user_data['password']:
                            user.password = user_data['password']
                        user.name = f"{user_data['firstName']} {user_data['lastName']}"
                        user.email = user_data['email']
                        user.role = user_data['role']
                        if 'is_grafana_admin' in user_data:
                            user.grafana_admin = user_data['is_grafana_admin']
                        org.users[user.login] = user
        return orgs


def execute():
    # Get organisations and users from json file
    organisations = JSONFile().get_organisations()
    # Manage organisation and user in Grafana
    provision(organisations)
