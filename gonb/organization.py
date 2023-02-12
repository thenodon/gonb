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
from typing import Dict

from gonb.user import User


class Organization:
    def __init__(self, organisation_name: str, org_id: int):
        self.organisation_name: str = organisation_name
        self.org_id: int = org_id
        self.api_key: str = ''
        self.users: Dict[str, User] = {}

    def __str__(self):
        return json.dumps(
            {key: value for key, value in self.__dict__.items() if not key.startswith('__') and not callable(key)})
