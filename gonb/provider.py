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

import inspect
import logging as log
import os
from typing import Dict

from gonb.organisation_transfer import OrganizationDTO


class ProviderException(Exception):
    def __init__(self, message):
        super().__init__(message)


class Provider:
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'get_groups') and
                callable(subclass.get_organisations) and
                hasattr(subclass, 'mandatory_env_vars') and
                callable(subclass.mandatory_env_vars))

    def get_organisations(self) -> Dict[str, OrganizationDTO]:
        raise NotImplementedError

    def mandatory_env_vars(self) -> Dict[str, str]:
        raise NotImplementedError


GONB_PROVIDER_CLASS_PATH = 'GONB_PROVIDER_CLASS_PATH'

env_vars = {GONB_PROVIDER_CLASS_PATH: 'The package path to the provider class'}


class ProviderInit:
    def __init__(self):
        if not os.getenv(GONB_PROVIDER_CLASS_PATH):
            log.error("Missing  mandatory environment variables", extra=env_vars)
            raise ProviderException('Missing mandatory environment variables')
        self.class_path = os.getenv(GONB_PROVIDER_CLASS_PATH)

    def register_provider(self) -> Provider:
        class_path = self.class_path.split('.')
        class_name = class_path[-1]
        package = '.'.join(class_path[0:-1])

        module = __import__(package)

        class_module = [_obj for _name, _obj in inspect.getmembers(module) if inspect.ismodule(_obj)]
        for name, obj in inspect.getmembers(class_module[0]):
            # if class and class name match input
            if inspect.isclass(obj) and name == f"{class_name}":
                provider = obj()
                if isinstance(provider, Provider):
                    log.info("Use provider", extra={'provider': name})
                    return provider

        raise ProviderException("No valid Provider class exists")
