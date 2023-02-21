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

from gonb.user import User


class UserTest(unittest.TestCase):

    def test_user_valid(self):

        user = User(login_name="andy@foo.com")
        user.name = "Andy Borg"
        user.email = user.login
        user.role = 'Viewer'
        self.assertTrue(user.is_valid())

        user.email = "andy"
        self.assertFalse(user.is_valid())

        user.email = user.login
        user.role = 'NotValid'
        self.assertFalse(user.is_valid())

    def test_user_equal(self):

        user1 = User(login_name="andy@foo.com")
        user1.name = "Andy Borg"
        user1.email = user1.login
        user1.role = 'Viewer'

        user2 = User(login_name="andy@foo.com")
        user2.name = "Andy Borg"
        user2.email = user2.login
        user2.role = 'Viewer'
        self.assertTrue(user1 == user2)

        user2.role = 'Editor'
        self.assertFalse(user1 == user2)

        user2.email = user2.login
        user2.role = 'Viewer'
        user2.name = "Andy Borgson"
        self.assertFalse(user1 == user2)

        user2.name = "Andy Borg"
        self.assertTrue(user1 == user2)

        # password is not part of the equal
        user2.password = 'xyz'
        self.assertTrue(user1 == user2)

        self.assertFalse(user1 == "just a string")


if __name__ == '__main__':
    unittest.main()
