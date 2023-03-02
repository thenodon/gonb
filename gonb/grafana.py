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

from gonb.admin_user import AdminUsers, AdminUser
from gonb.exceptions import GrafanaException
from gonb.folder import Folder, folder_factory, permission_factory, PermissionTeam
from gonb.organisation_transfer import OrganizationDTO
from gonb.organization import Organization, DiffUsers
from gonb.team import Team, team_factory, AccessControl, access_control_factory
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
GONB_GRAFANA_ADMINS = 'GONB_GRAFANA_ADMINS'
GONB_SSO_PROVIDER = 'GONB_SSO_PROVIDER'

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


class GrafanaAPI:
    def __init__(self):
        if not (os.getenv(GONB_GRAFANA_PASSWORD) and os.getenv(GONB_GRAFANA_URL) and os.getenv(GONB_GRAFANA_USER)):
            log.error("Missing  mandatory environment variables", extra=env_vars)
            raise GrafanaException('Missing mandatory environment variables')

        self.base_url = os.getenv(GONB_GRAFANA_URL)
        self.username = os.getenv(GONB_GRAFANA_USER)
        self.password = os.getenv(GONB_GRAFANA_PASSWORD)
        self.headers = {'Content-Type': 'application/json'}

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

    def _put_by_admin(self, url: str, body=None):
        """
        Do a PUT with basic auth
        :param url:
        :param body:
        :return:
        """
        if body is None:
            body = {}
        try:
            r = requests.put(f"{self.base_url}/{url}", headers=self.headers, auth=(self.username, self.password),
                             verify=False, data=json.dumps(body))
            if r.status_code != 200:
                raise GrafanaException(message=f"PUT - Status code for {self.base_url}/{url} was {r.status_code}",
                                       status=r.status_code)
            return r.json()
        except GrafanaException as err:
            raise err
        except Exception as err:
            raise GrafanaException(message=err)

    def _put_by_admin_using_orgid(self, url: str, org_id: int, body=None):
        """
        Do a PUT with basic auth and using org_id
        :param url:
        :param body:
        :return:
        """

        self._post_by_admin(url=f"api/user/using/{org_id}")
        return self._put_by_admin(url=url, body=body)

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

    def _create_apikey(self, organization: Organization):
        """
        Create an apikey for an organization. If the apikey, name, exists, it will be deleted prior to a new with the
        same name is created.
        If the grafana admin user is missing from the organization the user is added as an organization admin
        :param organization:
        :return:
        """

        # The user must be an admin member in the organisation - not enough that user just have grafana admin rights
        # If the user is missing add the user

        try:
            status = self._post_by_admin(url=f'api/orgs/{organization.org_id}/users', body={
                "role": 'admin',
                "loginOrEmail": self.username
            })
            log.info('admin user was added to organization',
                     extra={'admin_user': self.username, 'organization': organization.organisation_name,
                            'status': status})
        except GrafanaException:
            # If exception it just means that our admin user existed
            pass

        self._post_by_admin(url=f"api/user/using/{organization.org_id}")
        # Get all existing
        existing_api_keys = self._get_by_admin(url=f"api/auth/keys")
        key_id = GrafanaAPI._find_api_key_id_by_name(existing_api_keys, GONB_APIKEY)
        if key_id:
            # Delete it first
            self._delete_by_admin(url=f"api/auth/keys/{key_id}")

        api_key = self._post_by_admin(url=f"api/auth/keys", body={'name': GONB_APIKEY, 'role': 'Admin'})
        return api_key['key']

    @staticmethod
    def _find_api_key_id_by_name(existing_api_keys: List[Dict[str, Any]], key_name: str) -> int:
        for api_key in existing_api_keys:
            if api_key['name'] == key_name:
                return api_key['id']
        return None


class GrafanaConnection(GrafanaAPI):
    def __init__(self):
        super().__init__()
        self.create_orgs: bool = strtobool(os.getenv(GONB_GRAFANA_CREATE_ORGS, 'FALSE'))
        self.is_sso_provider: bool = strtobool(os.getenv(GONB_SSO_PROVIDER, 'TRUE'))
        # List of all valid access roles - only Enterprise
        self.grafana_access_roles: Dict[str, AccessControl] = {}
        # Set by the _init_organizations
        self.global_users: Dict[str, Dict] = {}
        self.admin_users: AdminUsers = AdminUsers(self.username)
        self.organisations_by_organisation_name: Dict[str, Organization] = {}

        # Read all organisation related data
        self._init_organizations()

    def _using_main(self):
        self._post_by_admin(url=f"api/user/using/1")

    def _is_enterprise(self):
        try:
            response = self._get_by_admin("api/licensing/check")
            # Get all valid access control roles, used to validate at add and update
            access_controls_data = self._get_by_admin('/api/access-control/roles')
            for access_control_data in access_controls_data:
                access_control = access_control_factory(access_control_data)
                self.grafana_access_roles[access_control.name] = access_control

            return True
        except GrafanaException:
            return False

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
            # If user do not exist in the instance add the user
            status = self._post_by_admin('api/admin/users', user_body)
            user_id = status['id']
            log.info('user created', extra={'org_id': org_id, 'status': status})

            if user.role and (user.role == 'Editor' or user.role == 'Admin'):
                # Add the role specific to the organisation
                status = self._patch_by_admin_using_orgid(url=f"api/org/users/{user_id}", org_id=org_id,
                                                          body={'role': user.role})
                log.info('user role', extra={'org_id': org_id, 'role': user.role, 'status': status})

        except GrafanaException as err:
            if err.status() == 412:
                # The user already exist but not in the organisation
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

        if not self.is_sso_provider:
            status = self._put_by_admin_using_orgid(url=f"api/users/{user.user_id}", org_id=org_id, body=user_body)
        status = self._patch_by_admin_using_orgid(url=f"api/org/users/{user.user_id}", org_id=org_id,
                                                  body={'role': user.role})
        log.info('user updated', extra={'org_id': org_id, 'data': user_body, 'status': status})
        return status

    def _add_admin_permissions(self, user_ids: Set[str]):
        body = {'isGrafanaAdmin': True}
        self._update_permission(user_ids=user_ids, body=body)

    def _delete_admin_permissions(self, user_ids: Set[str]):
        body = {'isGrafanaAdmin': False}
        self._update_permission(user_ids=user_ids, body=body)

    def _update_permission(self, user_ids: Set[str], body: Dict[str, Any]):
        for user_id in user_ids:
            if user_id in self.global_users:
                self._put_by_admin(url=f"api/admin/users/{self.global_users[user_id]['id']}/permissions", body=body)
                log.info("user permission", extra={'user': user_id, 'grafana_admin': body['isGrafanaAdmin']})
            else:
                log.warning("user permission failed", extra={'user': user_id, 'grafana_admin': body['isGrafanaAdmin'],
                                                             'error': 'user does not exist'})

    def _init_organizations(self):
        """
        Populate with all user data for the organisation except org_id 1, Main org,
        and create fresh apikeys for each organisation.
        :return:
        """

        # Get all "global user" - need the isAdmin which is the grafana instance admin
        if strtobool(os.getenv(GONB_GRAFANA_ADMINS, 'FALSE')):
            page = 1
            per_page = 1000
            while True:
                result = self._get_by_admin(f"api/users?perpage={per_page}&page={page}")
                for entry in result:
                    self.global_users[entry['login']] = entry
                    if 'isAdmin' in entry and entry['isAdmin']:
                        self.admin_users.add(AdminUser(login_name=entry['login'], user_id=entry['id'], is_admin=True))

                if len(result) < per_page:
                    break
                page = page + 1

        # Get all organisations
        all_orgs = self._get_by_admin('api/orgs')

        for org in all_orgs:
            if org['id'] == 1:
                # Do not include the Main org, 1
                continue
            # Create organization and add apikey
            organisation = Organization(organisation_name=org['name'], org_id=org['id'])

            organisation.api_key = self._create_apikey(organisation)

            self._get_users_by_organisation(organisation)

            # Save the organisation
            self.organisations_by_organisation_name[organisation.organisation_name] = organisation


class GrafanaUser(GrafanaConnection):
    def __init__(self):
        super().__init__()

    def provision(self, iam_organisations: Dict[str, Organization]) \
            -> Dict[str, Dict[str, List[User]]]:
        """
        Add/delete users in the Grafana organisations based on the content in source
        data
        :param iam_organisations:
        :return:
        """

        diff_users = DiffUsers(iam_organisations, self.organisations_by_organisation_name, self.username)

        added_organisations = self._add_organisations(diff_users.add_organisations())
        for organisation in added_organisations:
            self.organisations_by_organisation_name[organisation.organisation_name] = organisation

        # for organisation_name in set(source_users_idx.keys()).union(set(self.customer_users_idx.keys())):
        # Only manage users that is part of we got from the source
        users_managed = {}
        for organisation_name in set(iam_organisations.keys()):
            users_managed[organisation_name] = {}
            users_managed[organisation_name][UPDATED] = \
                self._update_users(organisation_name, diff_users.update(organisation_name), iam_organisations)
            users_managed[organisation_name][REMOVED] = \
                self._remove_users(organisation_name, diff_users.delete(organisation_name))
            users_managed[organisation_name][ADDED] = \
                self._add_users(organisation_name, diff_users.add(organisation_name), iam_organisations)

        for org, action in users_managed.items():
            log.info("user operations", extra={'organization': org, UPDATED: len(action[UPDATED]),
                                               ADDED: len(action[ADDED]), REMOVED: len(action[REMOVED])})
        self._using_main()
        return users_managed

    def _add_organisations(self, organisations: Set[str]) -> List[Organization]:
        added = []
        for organisation_name in organisations:
            if self.create_orgs:
                status = self._add_organisation_by_name(organisation=organisation_name)
                added.append(Organization(organisation_name=organisation_name, org_id=status['orgId']))
                log.info("organization created", extra={'organization': organisation_name})
            else:
                log.warning("organization missing in Grafana", extra={'organization': organisation_name})

        return added

    def _update_users(self, organisation_name: str, user_names: Set[str], iam_organisations: Dict[str, Organization]) \
            -> List[User]:

        update_users = []
        for user_name in user_names:

            if user_name in iam_organisations[organisation_name].users:
                org = self.organisations_by_organisation_name[organisation_name]
                user = iam_organisations[organisation_name].users[user_name]
                user.user_id = self.organisations_by_organisation_name[organisation_name].users[user_name].user_id
                self._update_user_to_organisation(user, org.org_id)
                update_users.append(org.users[user_name])
                log.info('user update', extra={'organization': organisation_name, 'user': user_name})
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
                log.info('user removed', extra={'organization': organisation_name, 'user': user_name})
        return removed_users

    def _add_users(self, organisation_name: str, user_names: Set[str], iam_organisations: Dict[str, Organization]) -> \
            List[User]:
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
                self._add_user_to_organisation(iam_organisations[organisation_name].users[user_name], org.org_id)
                added_users.append(iam_organisations[organisation_name].users[user_name])
                log.info('user add', extra={'organization': organisation_name, 'user': user_name})

        return added_users


class GrafanaTeam(GrafanaConnection):
    def __init__(self):
        super().__init__()

    def provision(self, iam_organisations: Dict[str, Organization]):
        """
        Provision and manage teams include the following logic:
        - Every Team will have a Folder with the same name
        - The Team Folder will always give Team members Editor rights by default
        :param iam_organisations:
        :return:
        """

        # Get all teams by organisation and populate
        folders_by_organisation_name = {}
        for organisation_name, organisation in self.organisations_by_organisation_name.items():
            # {'totalCount': 0, 'teams': [], 'page': 1, 'perPage': 1000}

            folders_by_organisation_name[organisation_name] = self._get_all_folders(organisation)
            self._get_all_teams(organisation, folders_by_organisation_name[organisation_name])

        # Add or update team
        for organisation_name, organisation in iam_organisations.items():
            try:
                for team_name, team in organisation.teams.items():
                    if organisation_name not in self.organisations_by_organisation_name:
                        log.warning('organization do not exist',
                                    extra={'organization': organisation_name, 'team': team_name})
                        continue
                    team.org_id = self.organisations_by_organisation_name[organisation_name].org_id
                    if team_name in self.organisations_by_organisation_name[organisation_name].teams.keys():
                        # Update teams for organisation
                        self._update_team(self.organisations_by_organisation_name[organisation_name], team)
                        log.info('team updated', extra={'organization': organisation_name, 'team': team_name})
                    else:
                        # Add teams for organisation
                        self._create_team(self.organisations_by_organisation_name[organisation_name], team)
                        log.info('team add', extra={'organization': organisation_name, 'team': team_name})
            except GrafanaException as err:
                log.error('team operation failed - continue with next', extra={'organization': organisation_name,
                                                                               'error': str(err)})
                continue
        self._using_main()

    def _create_team(self, organisation: Organization, team: Team):
        team = self._add_team_and_members(organisation, team)

        if self._is_enterprise():
            self._add_team_roles(organisation, team)
            self._add_team_sync_groups(organisation, team)

        self._add_team_folder(organisation, team)

    def _add_team_sync_groups(self, organisation, team):
        # TODO enterprise
        if team.sync_groups_id:
            body = {'groupId': team.sync_groups_id}
            response = self._post_by_admin_using_orgid(f"api/teams/{team.team_id}/groups", body=body,
                                                       org_id=organisation.org_id)

    def _add_team_roles(self, organisation: Organization, team: Team):
        # TODO enterprise
        body = {'roleUids': self._role_name_to_uid(team.access_control.values())}
        self._put_by_admin_using_orgid(f"/api/access-control/teams/{team.team_id}/roles", body=body,
                                       org_id=organisation.org_id)

    def _role_name_to_uid(self, roles: List[str]) -> List[str]:
        uids: List[str] = []
        for role in roles:
            if role in self.grafana_access_roles:
                access_control = self.grafana_access_roles[role]
                uids.append(access_control.uid)
            else:
                raise GrafanaException(f"role={role} error=\"do not exists\"")
        return uids

    def _add_team_and_members(self, organisation: Organization, team: Team) -> Team:
        # Create team
        body = {'name': team.name, 'org_id': team.org_id}
        response = self._post_by_admin_using_orgid('api/teams', body=body, org_id=team.org_id)
        if 'teamId' not in response:
            log.warning('team add failed ', extra={'organization': organisation.organisation_name, 'team': team.name,
                                                   'error': f"{response['message']}"})
            raise GrafanaException(f"operation=create team={team.name} error={response['message']}")

        # Add sync group
        team.team_id = response['teamId']

        self._add_members_in_team(organisation, team)

        return team

    def _update_team(self, organisation: Organization, iam_team: Team):
        self._update_team_members(organisation, iam_team)

        if self._is_enterprise():
            # Manage team roles
            self._update_team_roles(organisation, iam_team)
            # Manage team sync groups
            self._update_team_sync_groups(iam_team, organisation)

        self._update_teams_folder(organisation, iam_team)

    def _update_team_sync_groups(self, iam_team, organisation):
        # TODO enterprise
        if iam_team.sync_groups_id:
            sync_groups_del = set(iam_team.sync_groups_id) - set(organisation.teams[iam_team.name].sync_groups_id)
            sync_groups_add = set(organisation.teams[iam_team.name].sync_groups_id) - set(iam_team.sync_groups_id)
            if sync_groups_add:
                body = {'groupId': [sync_groups_add]}
                response = self._post_by_admin_using_orgid(
                    f"/api/teams/{organisation.teams[iam_team.name].team_id}/groups", body=body,
                    org_id=organisation.org_id)
            if sync_groups_del:
                for sync_group in sync_groups_del:
                    response = self._delete_by_admin_using_orgid(
                        f"/api/teams/{organisation.teams[iam_team.name].team_id}/groups/{sync_group}",
                        org_id=organisation.org_id)

    def _update_team_members(self, organisation: Organization, iam_team: Team):
        # Get existing members
        if self._is_enterprise():
            # TODO enterprise
            pass

        members_to_del = set(organisation.teams[iam_team.name].members) - set(iam_team.members)
        members_to_add = set(iam_team.members) - set(organisation.teams[iam_team.name].members)

        for member in members_to_del:
            self._delete_by_admin_using_orgid(
                f"api/teams/{organisation.teams[iam_team.name].team_id}/members/{organisation.users[member].user_id}",
                org_id=organisation.org_id)
            log.info('team user delete', extra={'organization': organisation.organisation_name,
                                                'team': iam_team.name, 'member': member})
        for member in members_to_add:
            if member in organisation.users.keys():
                body = {'userId': organisation.users[member].user_id}
                self._post_by_admin_using_orgid(
                    f"api/teams/{organisation.teams[iam_team.name].team_id}/members",
                    body=body,
                    org_id=organisation.org_id)
                log.info('team user add', extra={'organization': organisation.organisation_name,
                                                 'team': iam_team.name, 'member': member})
            else:
                log.warning('team user add', extra={'organization': organisation.organisation_name,
                                                    'team': iam_team.name, 'member': member,
                                                    'error': "user do not exist"})

    def _update_team_roles(self, organisation: Organization, team: Team):
        # TODO fix the logic
        pass

    def _add_members_in_team(self, organisation: Organization, team: Team):
        """
        Add existing members/users to a team.
        The member/user must exist in Grafana, which means have logged in at least once
        """

        for member in team.members:
            if member in organisation.users.keys():
                # Add existing members to the team

                body = {'userId': organisation.users[member].user_id}
                self._post_by_admin_using_orgid(f"api/teams/{team.team_id}/members", body=body,
                                                org_id=team.org_id)
                log.info('team user add', extra={'organization': organisation.organisation_name,
                                                 'team': team.name, 'member': member})

            else:
                log.warning('team user add failed', extra={'organization': organisation.organisation_name,
                                                           'team': team.name, 'member': member,
                                                           'error': f"member do not exist as a user"})

    def _add_team_folder(self, organisation: Organization, team: Team):
        folders_data = self._get_by_admin_using_orgid("api/folders", org_id=team.org_id)
        folder_titles = self._list_of_dict_values(folders_data, 'title')

        if team.name not in folder_titles:
            # Create Folder
            body = {'title': team.name}
            response = self._post_by_admin_using_orgid(f"api/folders", body=body, org_id=team.org_id)
            if response['uid']:
                folder_data = self._get_by_admin_using_orgid(f"api/folders/{response['uid']}", org_id=team.org_id)
                folder = folder_factory(folder_data)

                # Get existing permissions before update
                permissions_data = self._get_by_admin(f"api/folders/{folder.uid}/permissions")
                for permission_data in permissions_data:
                    permission = permission_factory(permission_data)
                    folder.permissions.append(permission)

                team_folder_permission = folder.formatted_permissions()
                team_folder_permission.append({'teamId': team.team_id, 'permission': 2})
                body = {'items': team_folder_permission}
                self._post_by_admin_using_orgid(f"api/folders/{folder.uid}/permissions", body=body, org_id=team.org_id)
                log.info('team folder add', extra={'organization': organisation.organisation_name,
                                                   'team': team.name, 'folder': folder.title})

    def _update_teams_folder(self, organisation: Organization, iam_team: Team):
        team = organisation.teams[iam_team.name]

        if not team.folder:
            self._add_team_folder(organisation, organisation.teams[iam_team.name])
        else:
            permissions_team = {}

            for permission in team.folder.permissions:

                if isinstance(permission, PermissionTeam):
                    permissions_team[permission.team_id] = permission

            if team.team_id not in permissions_team or \
                    team.team_id in permissions_team and permissions_team[team.team_id].permission != 2:
                update_permission = team.folder.formatted_permissions()
                update_permission.append({'teamId': team.team_id, 'permission': 2})
                body = {'items': update_permission}
                self._post_by_admin_using_orgid(f"api/folders/{team.folder.uid}/permissions", body=body,
                                                org_id=organisation.org_id)

                log.info('team folder updated permission', extra={'organization': organisation.organisation_name,
                                                                  'team': iam_team.name, 'folder': iam_team.name})

    def _get_all_teams(self, organisation: Organization, folders: Dict[str, Folder]):
        """
        Add Folders to Team's and Team's to Organization
        :param organisation:
        :param folders:
        :return:
        """
        teams_data = self._get_by_api_key(f"api/teams/search", api_key=organisation.api_key)
        if 'teams' not in teams_data:
            return
        for team_data in teams_data['teams']:
            # TODO add enterprise stuff
            team = team_factory(team_data)
            organisation.teams[team.name] = team
            if team.name in folders.keys():
                team.folder = folders[team.name]
            if team_data['memberCount'] != 0:
                member_data = self._get_by_api_key(f"api/teams/{team.team_id}/members", api_key=organisation.api_key)
                for member in member_data:
                    # Always exclude admin
                    if member['login'] != 'admin' and member['login'] != self.username:
                        team.members.add(member['login'])

    def _get_all_folders(self, organisation: Organization) -> Dict[str, Folder]:
        """
        Get all existing folders related to an organisation.
        :param organisation:
        :return:
        """
        folders_by_uid: Dict[str, Folder] = {}
        folders_by_title: Dict[str, Folder] = {}
        # Search in top folder
        folders_data = self._get_by_api_key('api/search?folderIds=0&type=dash-folder', api_key=organisation.api_key)
        for folder_data in folders_data:
            folder = folder_factory(folder_data)
            permissions_data = self._get_by_api_key(f"api/folders/{folder.uid}/permissions",
                                                    api_key=organisation.api_key)
            for permission_data in permissions_data:
                permission = permission_factory(permission_data)
                folder.permissions.append(permission)

            folders_by_uid[folder.uid] = folder

        for folder in folders_by_uid.values():
            if folder.title not in folders_by_title:
                folders_by_title[folder.title] = folder
            else:
                raise GrafanaException(f"Folder title already exists {folder.title}")

        return folders_by_title

    @staticmethod
    def _list_of_dict_values(alist: List[Dict], key: str):
        parsed_list = []
        for entry in alist:
            if key in entry:
                parsed_list.append(entry[key])
        return parsed_list


class GrafanaAdmin(GrafanaConnection):
    def __init__(self):
        super().__init__()

    def provision(self, iam_admins: Dict[str, AdminUsers], iam_organisations: Dict[str, Organization]):
        for org_name, admins in iam_admins.items():
            add, delete = self.admin_users.diff(admins, iam_organisations[org_name])
            self._add_admin_permissions(add)
            # Delete should never be done since we can never know which organisation should have precedence
            self._delete_admin_permissions(delete)
            self._using_main()


def provision(iam_organisations: Dict[str, OrganizationDTO]):
    """
    Execute on the source IAM based organisation
    :param iam_organisations:
    :return:
    """
    # Transform DTO object to Grafana objects
    organisations: Dict[str, Organization] = _dto_to_organisations(iam_organisations)

    # Provision Grafana organisations and organisation users
    grafana_users = GrafanaUser()
    grafana_users.provision(organisations)

    # Provision Grafana Teams
    grafana_teams = GrafanaTeam()
    grafana_teams.provision(organisations)

    # Provision Grafana admin users
    if strtobool(os.getenv(GONB_GRAFANA_ADMINS, 'FALSE')):
        admins: Dict[str, AdminUsers] = _dto_to_admins(iam_organisations)
        # If enabled, provision admin users
        grafana_admins = GrafanaAdmin()
        grafana_admins.provision(admins, organisations)


def _dto_to_admins(iam_organisations) -> Dict[str, AdminUsers]:
    """
    Get all users marked as grafana admins by organization
    :param iam_organisations:
    :return:
    """
    admins_by_org = {}
    for name, organisation_dto in iam_organisations.items():
        admins = AdminUsers(None)
        admins_by_org[name] = admins
        for user_name, user_dto in organisation_dto.users.items():
            if user_dto.grafana_admin:
                admins.add(AdminUser(login_name=user_dto.login, is_admin=True))
    return admins_by_org


def _dto_to_organisations(iam_organisations) -> Dict[str, Organization]:
    """
    Translate DTO organisation to organisation
    :param iam_organisations:
    :return:
    """
    organisations: Dict[str, Organization] = {}
    for name, organisation_dto in iam_organisations.items():
        organisation = Organization(organisation_name=organisation_dto.name, org_id=None)
        organisations[name] = organisation

        for user_name, user_dto in organisation_dto.users.items():
            user = User(login_name=user_dto.login, password=user_dto.password)
            user.role = user_dto.role
            user.email = user_dto.email
            user.name = user_dto.name
            user.grafana_admin = user_dto.grafana_admin
            organisation.users[user.login] = user

        for team_name, team_dto in organisation_dto.teams.items():
            team = Team()
            team.name = team_dto.name
            team.email = team_dto.email
            team.avatar_url = team_dto.avatar_url
            team.members = team_dto.members
            organisation.teams[team.name] = team

    return organisations
