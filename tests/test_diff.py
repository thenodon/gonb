import unittest
from typing import Dict

#from gonb.diff_users import DiffUsers
from gonb.organization import Organization, DiffUsers
from gonb.user import User


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

class DiffTest(unittest.TestCase):

    def test_diff(self):
        orgs_grafana: Dict[str, Organization] = {}
        org = Organization(organisation_name='foo_org', org_id=100)
        orgs_grafana[org.organisation_name] = org

        orgs_iam: Dict[str, Organization] = {}
        org = Organization(organisation_name='foo_org', org_id=None)
        orgs_iam[org.organisation_name] = org

        # Two empty organisations
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 0)
        self.assertEqual(len(diff.add('foo_org')), 0)
        self.assertEqual(len(diff.delete('foo_org')), 0)

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        orgs_iam['foo_org'].users[user.login] = user

        # One user in the iam org
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 0)
        self.assertEqual(len(diff.add('foo_org')), 1)
        self.assertEqual(len(diff.delete('foo_org')), 0)

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        user.user_id = 200
        orgs_grafana['foo_org'].users[user.login] = user

        # "Same" user in both orgs
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 0)
        self.assertEqual(len(diff.add('foo_org')), 0)
        self.assertEqual(len(diff.delete('foo_org')), 0)

        user = orgs_iam['foo_org'].users[user.login]
        user.role = 'Editor'

        # "Same" user in both orgs but different roles
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 1)
        self.assertEqual(len(diff.add('foo_org')), 0)
        self.assertEqual(len(diff.delete('foo_org')), 0)

        # User do not exist in iam org, should be removed
        del orgs_iam['foo_org'].users[user.login]
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 0)
        self.assertEqual(len(diff.add('foo_org')), 0)
        self.assertEqual(len(diff.delete('foo_org')), 1)

    def test_diff_external_auth(self):
        orgs_grafana: Dict[str, Organization] = {}
        org = Organization(organisation_name='foo_org', org_id=100)
        orgs_grafana[org.organisation_name] = org

        orgs_iam: Dict[str, Organization] = {}
        org = Organization(organisation_name='foo_org', org_id=None)
        orgs_iam[org.organisation_name] = org

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        orgs_iam['foo_org'].users[user.login] = user

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        user.user_id = 200
        orgs_grafana['foo_org'].users[user.login] = user

        user = User(login_name="bull@foo.com")
        user.name = "Bull Borg"
        user.email = user.login
        user.role = 'Viewer'
        user.user_id = 201
        user.external_auth = True
        orgs_grafana['foo_org'].users[user.login] = user

        # "Same" user in both orgs
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        self.assertEqual(len(diff.update('foo_org')), 0)
        self.assertEqual(len(diff.add('foo_org')), 0)
        # External auth user is not deleted
        self.assertEqual(len(diff.delete('foo_org')), 0)

        # Need to add it again since it was pop'ed in the previous delete
        user = User(login_name="bull@foo.com")
        user.name = "Bull Borg"
        user.email = user.login
        user.role = 'Viewer'
        user.user_id = 201
        user.external_auth = True
        orgs_grafana['foo_org'].users[user.login] = user
        diff = DiffUsers(iam_orgs=orgs_iam, grafana_orgs=orgs_grafana, exclude_user="foobar_admin")
        # External auth user is deleted
        self.assertEqual(len(diff.delete('foo_org', True)), 1)


if __name__ == '__main__':
    unittest.main()
