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

import logging as log
import os
import re
from typing import Dict, Any

import requests

from gonb.organisation_transfer import OrganizationDTO, UserDTO
from gonb.grafana import provision
from gonb.provider import Provider, ProviderException

requests.packages.urllib3.disable_warnings()

GONB_OKTA_DOMAIN = 'GONB_OKTA_DOMAIN'
GONB_OKTA_TOKEN = 'GONB_OKTA_TOKEN'
GNOB_OKTA_GROUP_PATTERN = 'GNOB_OKTA_GROUP_PATTERN'


env_vars = {GONB_OKTA_DOMAIN: 'The name of the okta domain', GONB_OKTA_TOKEN: 'A valid app token for the domain',
            GNOB_OKTA_GROUP_PATTERN: 'The regex to select okta groups, e.g. customer_'}


class OktaException(Exception):
    def __init__(self, message):
        super().__init__(message)


class OktaGroup:
    def __init__(self, group: str, okta_group_id: str):
        self.group = group
        self.id = okta_group_id


class Okta(Provider):
    def __init__(self):
        if not (os.getenv(GONB_OKTA_DOMAIN) and os.getenv(GONB_OKTA_TOKEN) and os.getenv(GNOB_OKTA_GROUP_PATTERN)):
            log.error("Missing  mandatory environment variables", extra=env_vars)
            raise ProviderException('Missing mandatory environment variables')
        self.group_pattern = re.compile(os.getenv(GNOB_OKTA_GROUP_PATTERN))
        self.domain = os.getenv(GONB_OKTA_DOMAIN)
        self.token = os.getenv(GONB_OKTA_TOKEN)
        self.headers = {'Content-Type': 'application/json', 'Authorization': f"SSWS {self.token}"}

    def _get(self, url) -> Dict[str, Any]:
        try:
            r = requests.get(f"https://{self.domain}.okta.com/{url}", headers=self.headers)
            if r.status_code != 200:
                raise OktaException(message=f"Status code for {url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise OktaException(message=err)

    def _fetch_groups(self) -> Dict[str, Any]:
        groups = self._get('api/v1/groups?limit=200')
        return groups

    def _fetch_users_by_group_id(self, group_id: str) -> Dict[str, Any]:
        users = self._get(f"api/v1/groups/{group_id}/users")
        return users

    def _filtered_groups(self) -> Dict[str, OktaGroup]:
        """
        Get groups from okta based on the group name
        :return: list of group ids
        """
        filtered_group_ids: Dict[str, OktaGroup] = {}
        all_groups = self._fetch_groups()
        for group in all_groups:

            if self.group_pattern.match(group['profile']['name']):
                # Find the last part of the group name, 3 position
                group_name = str(group['profile']['name']).split('_')[2]
                okta_group = OktaGroup(group=group_name, okta_group_id=group['id'])
                filtered_group_ids[group_name] = okta_group

        return filtered_group_ids

    def _group_id(self, group_name: str) -> str:
        """
        Get groups from okta based on the group name
        :param group_name:
        :return: list of group ids
        """
        all_groups = self._fetch_groups()
        for group in all_groups:
            if group_name in group['profile']['name']:
                return group['id']
        return ''

    def _get_groups_users_by_name(self, group_name: str, factory) -> Dict[str, Any]:
        """
        Get all users in the group
        :param group_name:
        :param factory: a function to create User object
        :return:
        """
        # Get all groups
        group_id = self._group_id(group_name)

        all_users = self._fetch_users_by_group_id(group_id=group_id)

        # if all_users:
        users: Dict[str, UserDTO] = {}
        for okta_user in all_users:
            user = factory(okta_user_profile=okta_user['profile'])
            users[user.login] = user

        return users

    def mandatory_env_vars(self) -> Dict[str, str]:
        return env_vars

    def get_organisations(self) -> Dict[str, OrganizationDTO]:
        """
        Get all users in the group
        :return:
        """

        # Get all groups
        all_groups = self._filtered_groups()

        orgs: Dict[str, OrganizationDTO] = {}
        users: Dict[str, Dict[str, UserDTO]] = {}
        for okta_group in all_groups.values():

            all_users = self._fetch_users_by_group_id(group_id=okta_group.id)

            # if all_users:
            users[okta_group.group] = {}
            org = OrganizationDTO(name=okta_group.group)
            orgs[okta_group.group] = org
            for okta_user in all_users:
                print(okta_user['profile'])
                user = Okta.user_factory(okta_user_profile=okta_user['profile'])
                org.users[user.login] = user
                log.info("okta user", extra={'group': okta_group.group, 'user': user.login})

            log.info("okta user", extra={'group': okta_group.group, 'group_id': okta_group.id,
                                         'nr_users': len(users[okta_group.group])})
        return orgs

    @staticmethod
    def user_factory(okta_user_profile: Dict[str, Any]) -> UserDTO:
        user = UserDTO(login_name=okta_user_profile['login'])
        user.name = f"{okta_user_profile['firstName']} {okta_user_profile['lastName']}"
        user.email = okta_user_profile['email']
        return user


def execute():
    # Get organisations and users from json file
    organisations = Okta().get_organisations()
    # Manage organisation and user in Grafana

    provision(organisations)
