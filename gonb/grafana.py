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
from typing import Dict, Set, List, Any

import requests

from gonb.organization import Organization, DiffUsers
from gonb.user import User

requests.packages.urllib3.disable_warnings()

ADDED = 'added'
REMOVED = 'removed'
UPDATED = 'updated'

GONB_APIKEY = 'gonb'
GONB_GRAFANA_URL = 'GONB_GRAFANA_URL'
GONB_GRAFANA_USER = 'GONB_GRAFANA_USER'
GONB_GRAFANA_PASSWORD = 'GONB_GRAFANA_PASSWORD'
GONB_GRAFANA_CREATE_ORGS = 'GONB_GRAFANA_CREATE_ORGS'

env_vars = {GONB_GRAFANA_URL: 'The grafana server url',
            GONB_GRAFANA_USER: 'A grafana user with admin permission',
            GONB_GRAFANA_PASSWORD: 'Password for the grafana user'}


def strtobool(val) -> bool:
    """Convert a string representation of truth to true (1) or false (0).
    Raises ValueError if 'val' is anything else than defined.
    """
    val = val.lower()
    if val in ('yes', 'true'):
        return True
    elif val in ('no', 'false'):
        return False
    else:
        raise ValueError("invalid truth value %r" % (val,))


class GrafanaException(Exception):
    def __init__(self, message, status: int = 500):
        super().__init__(message)
        self._status = status

    def status(self) -> int:
        return self._status


class GrafanaConnection:
    def __init__(self):
        if not (os.getenv(GONB_GRAFANA_PASSWORD) and os.getenv(GONB_GRAFANA_URL) and os.getenv(GONB_GRAFANA_USER)):
            log.error("Missing  mandatory environment variables", extra=env_vars)
            raise GrafanaException('Missing mandatory environment variables')

        self.base_url = os.getenv(GONB_GRAFANA_URL)
        self.username = os.getenv(GONB_GRAFANA_USER)
        self.password = os.getenv(GONB_GRAFANA_PASSWORD)
        self.headers = {'Content-Type': 'application/json'}
        self.create_orgs: bool = strtobool(os.getenv(GONB_GRAFANA_CREATE_ORGS, 'FALSE'))

    def _get_by_admin(self, url):
        """
        Do a GET with basic auth
        :param url:
        :return:
        """
        try:
            r = requests.get(f"{self.base_url}/{url}", headers=self.headers, auth=(self.username, self.password),
                             verify=False)
            if r.status_code != 200:
                raise GrafanaException(message=f"GET - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _get_by_admin_using_orgid(self, url: str, org_id: int):
        """
        Do a GET with basic auth
        :param url:
        :param org_id:
        :return:
        """

        self._post_by_admin(url=f"api/user/using/{org_id}")
        return self._get_by_admin(url=url)

    def _post_by_admin(self, url: str, body=None):
        """
        Do a POST with basic auth
        :param url:
        :param body:
        :return:
        """
        if body is None:
            body = {}
        try:
            r = requests.post(f"{self.base_url}/{url}", headers=self.headers, auth=(self.username, self.password),
                              verify=False, data=json.dumps(body))
            if r.status_code != 200:
                raise GrafanaException(message=f"POST - Status code for {self.base_url}/{url} was {r.status_code}",
                                       status=r.status_code)
            return r.json()
        except GrafanaException as err:
            raise err
        except Exception as err:
            raise GrafanaException(message=err)

    def _post_by_admin_using_orgid(self, url: str, org_id: int, body=None):
        """
        Do a POST with basic auth and using org_id
        :param url:
        :param body:
        :return:
        """

        self._post_by_admin(url=f"api/user/using/{org_id}")
        return self._post_by_admin(url=url, body=body)

    def _patch_by_admin(self, url, body=None):
        """
        Do a PATCH with basic auth
        :param url:
        :param body:
        :return:
        """
        if body is None:
            body = {}
        try:
            r = requests.patch(f"{self.base_url}/{url}", headers=self.headers, auth=(self.username, self.password),
                               verify=False, data=json.dumps(body))
            if r.status_code != 200:
                raise GrafanaException(message=f"PATCH - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _patch_by_admin_using_orgid(self, url: str, org_id: int, body=None):
        """
        Do a PATCH with basic auth and using org_id
        :param url:
        :param body:
        :return:
        """

        self._post_by_admin(url=f"api/user/using/{org_id}")
        return self._patch_by_admin(url=url, body=body)

    def _delete_by_admin(self, url):
        """
        Do a DELETE with basic auth
        :param url:
        :return:
        """
        try:
            r = requests.delete(f"{self.base_url}/{url}", headers=self.headers, auth=(self.username, self.password),
                                verify=False)
            if r.status_code != 200:
                raise GrafanaException(message=f"DELETE - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _delete_by_admin_using_orgid(self, url: str, org_id: int):
        """
        Do a DELETE with basic auth and using org_id
        :param url:
        :return:
        """

        self._post_by_admin(url=f"api/user/using/{org_id}")
        return self._delete_by_admin(url=url)

    def _get_by_api_key(self, url, api_key):
        """
        Do a GET with apikey
        :param url:
        :param api_key:
        :return:
        """
        headers = dict(self.headers)
        headers['Authorization'] = f"Bearer {api_key}"

        try:
            r = requests.get(f"{self.base_url}/{url}", headers=headers, verify=False)
            if r.status_code != 200:
                raise GrafanaException(
                    message=f"GET apikey - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _post_by_api_key(self, url, api_key, body=None):
        """
        Do a GET with apikey
        :param url:
        :param api_key:
        :return:
        """
        headers = dict(self.headers)
        headers['Authorization'] = f"Bearer {api_key}"

        try:
            r = requests.post(f"{self.base_url}/{url}", headers=headers, verify=False, data=json.dumps(body))
            if r.status_code != 200:
                raise GrafanaException(
                    message=f"POST apikey - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _patch_by_api_key(self, url, api_key, body=None):
        """
        Do a GET with apikey
        :param url:
        :param api_key:
        :return:
        """
        headers = dict(self.headers)
        headers['Authorization'] = f"Bearer {api_key}"

        try:
            r = requests.patch(f"{self.base_url}/{url}", headers=headers, verify=False, data=json.dumps(body))
            if r.status_code != 200:
                raise GrafanaException(
                    message=f"PATCH apikey - Status code for {self.base_url}/{url} was {r.status_code}")
            return r.json()
        except Exception as err:
            raise GrafanaException(message=err)

    def _create_apikey(self, orgid: int):
        """
        Create an apikey for an organisation. If the apikey, name, exists, it
        will be deleted prior to a new with the same name is created
        :param orgid:
        :return:
        """
        # Activate org_id
        self._post_by_admin(url=f"api/user/using/{orgid}")
        # Get all existing
        existing_api_keys = self._get_by_admin(url=f"api/auth/keys")
        key_id = GrafanaConnection._find_api_key_id_by_name(existing_api_keys, GONB_APIKEY)
        if key_id:
            # Delete it first
            self._delete_by_admin(url=f"api/auth/keys/{key_id}")

        api_key = self._post_by_admin(url=f"api/auth/keys", body={'name': GONB_APIKEY, 'role': 'Admin'})
        return api_key['key']

    def _add_organisation_by_name(self, organisation):
        """
        Add an organisation
        :return:
        """
        body = {
            "name": organisation
        }
        return self._post_by_admin(url=f"api/orgs", body=body)

    def _get_users_by_organisation(self, organisation: Organization):
        """
        Get all users by organisation where the apikey is by organisation

        :return:
        """
        existing_users = self._get_by_api_key(url='api/org/users', api_key=organisation.api_key)
        for exist_user in existing_users:
            if exist_user['userId'] == 1:
                continue
            user = User.factory(exist_user)
            organisation.users[user.login] = user

    def _remove_user_from_organisation(self, user: User, org_id: int):
        """
        Remove a user from an organisation
        :param user:
        :param org_id:
        :return:
        """

        # Delete user
        return self._delete_by_admin_using_orgid(url=f"api/org/users/{user.user_id}", org_id=org_id)

    def _add_user_to_organisation(self, user: User, org_id: int):
        """
        Remove a user from an organisation
        :param user:
        :param org_id:
        :return:
        """
        # Create the user
        user_body = {
            'name': user.name,
            'email': user.email,
            'login': user.login,
            'password': user.password,
            'OrgId': org_id
        }

        try:
            status = self._post_by_admin('api/admin/users', user_body)
            user_id = status['id']
            log.info('user created', extra={'org_id': org_id, 'status': status})
            if user.role and (user.role == 'Editor' or user.role == 'Admin'):
                status = self._patch_by_admin_using_orgid(url=f"api/org/users/{user_id}", org_id=org_id,
                                                          body={'role': user.role})
                log.info('user role', extra={'org_id': org_id, 'role': user.role, 'status': status})

        except GrafanaException as err:
            if err.status() == 412:
                # The user already exist but not in this organisation
                status = self._post_by_admin_using_orgid(url='api/org/users', org_id=org_id,
                                                         body={
                                                             "role": user.role,
                                                             "loginOrEmail": user.login
                                                         })
                log.info('user added to organization', extra={'org_id': org_id, 'role': user.role, 'status': status})
            else:
                raise err
        return status

    def _update_user_to_organisation(self, user: User, org_id: int):
        """
        Remove a user from an organisation
        :param user:
        :param org_id:
        :return:
        """
        # Create the user
        user_body = {
            'name': user.name,
            'email': user.email,
            'role': user.role
        }

        status = self._patch_by_admin_using_orgid(url=f"api/org/users/{user.user_id}", org_id=org_id, body=user_body)
        # self._post_by_admin(f"api/user/using/{org_id}")
        # status = self._patch_by_admin(f"api/org/users/{user.user_id}", user_body)
        log.info('user updated', extra={'org_id': org_id, 'data': user_body, 'status': status})
        return status

    @staticmethod
    def _find_api_key_id_by_name(existing_api_keys: List[Dict[str, Any]], key_name: str) -> int:
        for api_key in existing_api_keys:
            if api_key['name'] == key_name:
                return api_key['id']
        return None


class GrafanaUser(GrafanaConnection):
    def __init__(self):
        super().__init__()

        # This structure include every thing about the organisations
        # Key is the organisation_name
        self.organisations_by_organisation_name: Dict[str, Organization] = {}
        self.organisations_users_idx: Dict[str, Set[str]] = {}

        # Populate data for the organisations
        self._get_organizations()

    def _get_organizations(self):
        """
        Populate with all user data for the organisation except org_id 1, Main org,
        and create fresh apikeys for each organisation.
        :return:
        """
        all_orgs = self._get_by_admin('api/orgs')

        for org in all_orgs:
            if org['id'] == 1:
                # Do not include the Main org, 1
                continue
            # Create organization and add apikey
            organisation = Organization(organisation_name=org['name'], org_id=org['id'])
            organisation.api_key = self._create_apikey(int(organisation.org_id))

            self._get_users_by_organisation(organisation)

            # Save the organisation
            self.organisations_by_organisation_name[organisation.organisation_name] = organisation

            # Create index
            if organisation.organisation_name not in self.organisations_users_idx:
                self.organisations_users_idx[organisation.organisation_name] = set()

            # Populate index
            for user in organisation.users.values():
                self.organisations_users_idx[organisation.organisation_name].add(user.login)

    def provision_organizations_users(self, iam_org: Dict[str, Organization]) -> Dict[str, Dict[str, List[User]]]:
        """
        Add/delete users in the Grafana organisations based on the content in source
        data
        :param iam_org:
        :return:
        """

        diff_users = DiffUsers(iam_org, self.organisations_by_organisation_name)

        added_organisations = self._add_organisations(diff_users.add_organisations())
        for organisation in added_organisations:
            self.organisations_by_organisation_name[organisation.organisation_name] = organisation

        # for organisation_name in set(source_users_idx.keys()).union(set(self.customer_users_idx.keys())):
        # Only manage users that is part of we got from the source
        users_managed = {}
        for organisation_name in set(iam_org.keys()):
            users_managed[organisation_name] = {}
            users_managed[organisation_name][UPDATED] = \
                self._update_users(organisation_name, diff_users.update(organisation_name), iam_org)
            users_managed[organisation_name][REMOVED] = \
                self._remove_users(organisation_name, diff_users.delete(organisation_name))
            users_managed[organisation_name][ADDED] = \
                self._add_users(organisation_name, diff_users.add(organisation_name), iam_org)

        for org, action in users_managed.items():
            log.info("operations", extra={'organisation': org, UPDATED: len(action[UPDATED]),
                                          ADDED: len(action[ADDED]), REMOVED: len(action[REMOVED])})
        return users_managed

    def _add_organisations(self, organisations: Set[str]) -> List[Organization]:
        added = []
        for organisation_name in organisations:
            if self.create_orgs:
                status = self._add_organisation_by_name(organisation=organisation_name)
                added.append(Organization(organisation_name=organisation_name, org_id=status['orgId']))
                log.info("organisation created", extra={'organisation': organisation_name})
            else:
                log.warning("organisation missing in Grafana", extra={'organisation': organisation_name})

        return added

    def _update_users(self, organisation_name: str, user_names: Set[str], iam_orgs: Dict[str, Organization]) \
            -> List[User]:

        update_users = []
        for user_name in user_names:

            if user_name in iam_orgs[organisation_name].users:
                org = self.organisations_by_organisation_name[organisation_name]
                user = iam_orgs[organisation_name].users[user_name]
                user.user_id = self.organisations_by_organisation_name[organisation_name].users[user_name].user_id
                self._update_user_to_organisation(user, org.org_id)
                update_users.append(org.users[user_name])
                log.info('user update', extra={'organisation': organisation_name, 'user': user_name})
        return update_users

    def _remove_users(self, organisation_name: str, user_names: Set[str]) -> List[User]:
        """
        Remove users from an organisation
        :param organisation_name:
        :param user_names:
        :return:
        """
        # Check if there is organisation_name, from source, that do not exist in Grafana
        if organisation_name not in self.organisations_by_organisation_name:
            return []
        org = self.organisations_by_organisation_name[organisation_name]

        removed_users = []
        for user_name in user_names:
            if user_name in org.users:
                self._remove_user_from_organisation(org.users[user_name], org.org_id)
                removed_users.append(org.users[user_name])
                log.info('user removed', extra={'organisation': organisation_name, 'user': user_name})
        return removed_users

    def _add_users(self, organisation_name: str, user_names: Set[str], iam_orgs: Dict[str, Organization]) -> List[User]:
        """
        Add users to an organisation
        :param organisation_name:
        :param user_names:
        :return:
        """
        # Check if there is organisation name, from source, that do not exist in Grafana
        if organisation_name not in self.organisations_by_organisation_name:
            return []

        added_users = []
        org = self.organisations_by_organisation_name[organisation_name]
        for user_name in user_names:
            if user_name not in org.users:
                self._add_user_to_organisation(iam_orgs[organisation_name].users[user_name], org.org_id)
                added_users.append(iam_orgs[organisation_name].users[user_name])
                log.info('user add', extra={'organisation': organisation_name, 'user': user_name})

        return added_users
