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


class AdminUserTest(unittest.TestCase):

    def test_admin_user(self):
        iam_admins = AdminUsers()
        user = AdminUser(login_name="andy@foo.com", is_admin=True)
        iam_admins.add(user)
        user = AdminUser(login_name="boo@foo.com", is_admin=True)
        iam_admins.add(user)
        self.assertTrue(len(iam_admins.get()) == 2)

        admins = AdminUsers()

        add, delete = admins.diff(iam_admins)
        self.assertTrue(len(add) == 2)

        user = AdminUser(login_name="andy@foo.com", is_admin=False)
        admins.add(user)

        add, delete = admins.diff(iam_admins)
        self.assertTrue(len(add) == 2)
        self.assertTrue(len(delete) == 0)

        user = AdminUser(login_name="andy@foo.com", is_admin=True)
        admins.add(user)
        add, delete = admins.diff(iam_admins)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 0)

        user = AdminUser(login_name="roger@foo.com", is_admin=True)
        admins.add(user)
        add, delete = admins.diff(iam_admins)
        self.assertTrue(len(add) == 1)
        self.assertTrue(len(delete) == 1)


if __name__ == '__main__':
    unittest.main()
