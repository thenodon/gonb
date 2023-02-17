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

from gonb.grafana import provision
from gonb.provider import ProviderInit


if __name__ == "__main__":

    # Instantiate the Provider and get organisations and users
    iam_organisations = ProviderInit().register_provider().get_organisations()
    # Manage organisation and user in Grafana
    provision(iam_organisations)

