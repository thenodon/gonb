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

from gonb.grafana import Organization, GrafanaUser
from gonb.provider import Provider, ProviderException
from gonb.user import User


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

    def get_users(self) -> Dict[str, Organization]:
        """
        Get all users in the groups
        :return:
        """

        # Get all customer groups
        orgs: Dict[str, Organization] = {}
        with open(os.getenv(GONB_JSON_FILE)) as org_file:
            data = json.load(org_file)
            for org_data in data:
                org = Organization(organisation_name=org_data['organisation'], org_id=None)
                orgs[org.organisation_name] = org
                for user_data in org_data['users']:
                    if 'password' in user_data and user_data['password']:
                        user = User(login_name=user_data['email'], password=user_data['password'])
                    else:
                        user = User(login_name=user_data['email'])
                    user.name = f"{user_data['firstName']} {user_data['lastName']}"
                    user.email = user_data['email']
                    user.role = user_data['role']
                    org.users[user.login] = user
        return orgs


def execute():
    # Get organisations and users from json file
    organisations = JSONFile().get_users()
    # Manage organisation and user in Grafana
    GrafanaUser().provision_organizations_users(organisations)
