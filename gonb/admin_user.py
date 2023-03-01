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

from typing import Dict, Set, Tuple
from gonb.organization import Organization


class AdminUser:
    def __init__(self, login_name: str, user_id: int = 0, is_admin: bool = False):
        self.login: str = login_name
        # The 0 id is an indication that the AdminUser is not created based on Grafana
        # content
        self.id: int = user_id
        self.is_admin = is_admin


class AdminUsers:
    def __init__(self, exclude_user: str):
        self.exclude_user = exclude_user
        self._admin_users: Dict[str, AdminUser] = {}

    def add(self, admin_user: AdminUser):
        """
        Add an admin user but only if is_admin is True
        :param admin_user:
        :return:
        """
        if 'admin' != admin_user.login and admin_user.login not in self._admin_users.keys() \
                and admin_user.is_admin:
            self._admin_users[admin_user.login] = admin_user

    def get_user(self) -> Set[str]:
        return set(self._admin_users.keys())

    def get(self) -> Dict[str, AdminUser]:
        return self._admin_users

    def diff(self, other, organization: Organization) -> Tuple[Set[str], Set[str]]:
        add: Set[str] = set()
        delete: Set[str] = set()
        if isinstance(other, AdminUsers):

            # Only delete admin if the that are part of the organization
            all_in_org = set(organization.users.keys()) - set(other._admin_users.keys())
            delete = all_in_org & set(self._admin_users.keys())
            if self.exclude_user in delete:
                delete.remove(self.exclude_user)
            add = set(other._admin_users.keys()) - set(self._admin_users.keys())

        return add, delete
