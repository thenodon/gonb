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

from typing import List, Dict, Any

from gonb.exceptions import GrafanaException


class Permission:
    def __init__(self):
        self.uid: str = ''
        self.permission: int = None
        self.permission_name: str = ''
        self.inherited: bool = False


class PermissionUser(Permission):
    def __init__(self):
        super().__init__()
        self.user_id: int = None
        self.user_login: str = ''


class PermissionTeam(Permission):
    def __init__(self):
        super().__init__()
        self.team_id: int = None
        self.team: str = ''


class PermissionByRole(Permission):
    def __init__(self):
        super().__init__()
        self.role: str = ''


def permission_factory(permission_data: Dict[str, Any]) -> Permission:
    if 'role' in permission_data:
        permission = PermissionByRole()
        permission.uid = permission_data['uid']
        permission.permission = permission_data['permission']
        permission.inherited = permission_data['inherited']

        permission.role = permission_data['role']

    elif 'userId' in permission_data and permission_data['userId'] != 0:
        # it's a user permission
        permission = PermissionUser()
        permission.uid = permission_data['uid']
        permission.permission = permission_data['permission']
        permission.inherited = permission_data['inherited']

        permission.user_id = permission_data['userId']
        permission.user_login = permission_data['userLogin']

    elif 'teamId' in permission_data and permission_data['teamId'] != 0:
        # it's a team permission
        permission = PermissionTeam()
        permission.uid = permission_data['uid']
        permission.permission = permission_data['permission']
        permission.inherited = permission_data['inherited']

        permission.team_id = permission_data['teamId']
        permission.team = permission_data['team']
    else:
        raise GrafanaException(f"No such permission model {permission_data}")
    return permission


class Folder:
    def __init__(self):
        self.folder_id: int = None
        self.uid: str = ''
        self.title: str = ''
        self.slug: str = ''
        self.url: str = ''
        # key is uid
        self.permissions: List[Permission] = []

    def formatted_permissions(self) -> List[Dict]:
        permission_list = []
        for permission in self.permissions:
            if isinstance(permission, PermissionByRole):
                permission_list.append({'role': permission.role, 'permission': permission.permission})
            if isinstance(permission, PermissionTeam):
                permission_list.append({'teamId': permission.team_id, 'permission': permission.permission})
            if isinstance(permission, PermissionUser):
                permission_list.append({'userId': permission.user_id, 'permission': permission.permission})
        return permission_list


def folder_factory(folder_data: Dict[str, Any]) -> Folder:
    folder = Folder()
    folder.folder_id = folder_data['id']
    folder.uid = folder_data['uid']
    folder.title = folder_data['title']
    if 'slug' in folder_data:
        folder.slug = folder_data['slug']
    folder.url = folder_data['url']
    return folder
