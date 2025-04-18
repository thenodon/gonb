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
from typing import Dict, Set

from gonb.user import User
from gonb.team import Team
from gonb.folder import Folder


class Organization:
    def __init__(self, organisation_name: str, org_id: int):
        self.organisation_name: str = organisation_name
        self.org_id: int = org_id
        self.api_key: str = ''
        self.users: Dict[str, User] = {}
        self.teams: Dict[str, Team] = {}
        self.folders: Dict[str, Folder] = {}

    def __str__(self):
        return json.dumps(
            {key: value for key, value in self.__dict__.items() if not key.startswith('__') and not callable(key)})


class DiffUsers:
    def __init__(self, iam_orgs: Dict[str, Organization], grafana_orgs: Dict[str, Organization], exclude_user):
        self._iam_orgs = iam_orgs
        self._grafana_orgs = grafana_orgs
        self.exclude_user = exclude_user

        self.iam_users_idx: Dict[str, Set[str]] = DiffUsers._get_user_idx(self._iam_orgs)
        self.grafana_users_idx: Dict[str, Set[str]] = DiffUsers._get_user_idx(self._grafana_orgs)

    def add(self, organisation_name: str) -> Set[str]:
        self._init(organisation_name=organisation_name)
        add_users = self.iam_users_idx[organisation_name] - self.grafana_users_idx[organisation_name]
        if self.exclude_user in add_users:
            add_users.remove(self.exclude_user)
        return add_users

    def delete(self, organisation_name: str, delete_external_sso_users: bool = False) -> Set[str]:
        self._init(organisation_name=organisation_name)
        del_users = self.grafana_users_idx[organisation_name] - self.iam_users_idx[organisation_name]
        if self.exclude_user in del_users:
            del_users.remove(self.exclude_user)
        # Exclude users from grafana that have external auth
        for user_name in del_users.copy():
            if self._grafana_orgs[organisation_name].users[user_name].external_auth and not delete_external_sso_users:
                log.info("exclude delete of user due to external SSO", extra={'organization': organisation_name, 'user': user_name})
                self._grafana_orgs[organisation_name].users.pop(user_name)
                del_users.remove(user_name)
        return del_users

    def update(self, organisation_name: str) -> Set[str]:
        # Get the intersection
        update_users = set()
        self._init(organisation_name=organisation_name)
        for user_name in self.grafana_users_idx[organisation_name] & self.iam_users_idx[organisation_name]:
            if self._grafana_orgs[organisation_name].users[user_name] != \
                    self._iam_orgs[organisation_name].users[user_name]:
                update_users.add(user_name)
        if self.exclude_user in update_users:
            update_users.remove(self.exclude_user)
        return update_users

    def _init(self, organisation_name: str):
        if organisation_name not in self.iam_users_idx.keys():
            self.iam_users_idx[organisation_name] = set()
        if organisation_name not in self.grafana_users_idx.keys():
            self.grafana_users_idx[organisation_name] = set()

    def add_organisations(self):
        return set(self._iam_orgs.keys()) - set(self._grafana_orgs.keys())

    @staticmethod
    def _get_user_idx(orgs: Dict[str, Organization]) -> Dict[str, Set[str]]:
        source_users_idx = {}
        source_users = {}
        for org in orgs.values():
            source_users[org.organisation_name] = org.users
            source_users_idx[org.organisation_name] = set()
            if org.users:
                for user_name in source_users[org.organisation_name].keys():
                    source_users_idx[org.organisation_name].add(user_name)

        return source_users_idx
