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

import unittest

from gonb.admin_user import AdminUsers, AdminUser
from gonb.organization import Organization
from gonb.user import User


class AdminUserTest(unittest.TestCase):

    def test_admin_user(self):
        organization = Organization(organisation_name='foo', org_id=None)

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        organization.users[user.login] = user

        user = User(login_name="boo@foo.com")
        user.name = "Bo Borg"
        user.email = user.login
        user.role = 'Admin'
        organization.users[user.login] = user

        iam_admins = AdminUsers(None)
        user = AdminUser(login_name="andy@foo.com", is_admin=True)
        iam_admins.add(user)
        user = AdminUser(login_name="boo@foo.com", is_admin=True)
        iam_admins.add(user)
        self.assertTrue(len(iam_admins.get()) == 2)

        admins = AdminUsers("foobar_admin")

        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 2)
        self.assertTrue("andy@foo.com" in add and "boo@foo.com" in add)

        user = AdminUser(login_name="andy@foo.com", is_admin=False)
        admins.add(user)

        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 2)
        self.assertTrue(len(delete) == 0)
        # Since user already exists
        self.assertTrue("andy@foo.com" in add and "boo@foo.com" in add)

        user = AdminUser(login_name="andy@foo.com", is_admin=True)
        admins.add(user)
        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 0)
        # andy@foo.com already admin
        self.assertTrue("boo@foo.com" in add)

        # Add a user that is grafana admin but not in any organizations
        user = AdminUser(login_name="roger@foo.com", is_admin=True)
        admins.add(user)
        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 0)
        # Since roger@foo not in iam_org
        self.assertTrue("boo@foo.com" in add)

        # Add user to the organization but not a grafana admin
        user = User(login_name="roger@foo.com")
        user.name = "Roger Borg"
        user.email = user.login
        user.role = 'Admin'
        organization.users[user.login] = user

        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 1)
        self.assertTrue("boo@foo.com" in add)
        self.assertTrue("roger@foo.com" in delete)

        user = AdminUser(login_name="roger@foo.com", is_admin=True)
        iam_admins.add(user)
        add, delete = admins.diff(iam_admins, organization)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 0)
        self.assertTrue("boo@foo.com" in add)


if __name__ == '__main__':
    unittest.main()
