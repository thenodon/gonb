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
import random
import string
from typing import Dict


def create_random_string(length: int = 30):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password


class User:
    def __init__(self, login_name: str, password: str = ""):
        self.login: str = login_name
        self.email: str = ''
        self.name: str = ''
        self.role: str = 'Viewer'
        self.user_id: int = 0
        self.password = password
        if not self.password:
            self.password = create_random_string()
        self.external_auth: bool = False

    def __str__(self):
        return json.dumps(
            {key: value for key, value in self.__dict__.items() if not key.startswith('__') and not callable(key)})

    def is_valid(self) -> bool:
        if '@' not in self.email:
            return False

        if not (self.role == 'Viewer' or self.role == 'Editor' or self.role == 'Admin'):
            return False

        return True

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        if self.login != other.login:
            return False
        if self.email != other.email:
            return False
        if self.name != other.name:
            return False
        if self.role != other.role:
            return False

        return True

    @staticmethod
    def factory(grafana_user_profile: Dict[str, str]):
        user = User(grafana_user_profile['login'])
        user.name = grafana_user_profile['name']
        user.email = grafana_user_profile['email']
        user.role = grafana_user_profile['role']
        user.user_id = grafana_user_profile['userId']
        if 'authLabels' in grafana_user_profile and grafana_user_profile['authLabels'] is not None:
            user.external_auth = True

        return user
