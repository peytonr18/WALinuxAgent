# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.4+ and Openssl 1.0+
#

import os

from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import OSUtilError
from azurelinuxagent.common.osutil.default import DefaultOSUtil
from azurelinuxagent.common.osutil.gaia import GaiaOSUtil
from azurelinuxagent.common.osutil.nsbsd import NSBSDOSUtil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.utils.cryptutil import CryptUtil
from tests.lib.tools import AgentTestCase, Mock, load_data, patch


class DefaultOsUtilTestCase(AgentTestCase):
    def test_default_service_name(self):
        self.assertEqual(DefaultOSUtil().get_service_name(), "waagent")


class TestSSHKeyPath(AgentTestCase):
    def setUp(self):
        super(TestSSHKeyPath, self).setUp()
        self.home = os.path.join(self.tmp_dir, "alice")
        os.mkdir(self.home)
        self.account = Mock(pw_name="alice", pw_dir=self.home, pw_uid=os.getuid(), pw_gid=os.getgid())
        self.util = DefaultOSUtil()
        self.util.selinux = False
        self.util.get_userentry = Mock(return_value=self.account)
        self.chowner_patch = patch.object(fileutil, "chowner")
        self.chowner = self.chowner_patch.start()

    def tearDown(self):
        self.chowner_patch.stop()
        super(TestSSHKeyPath, self).tearDown()

    def test_public_key_requires_an_absolute_file_path_under_the_accounts_ssh_directory(self):
        other_key = os.path.join(self.tmp_dir, "bob", ".ssh", "key")
        os.makedirs(os.path.dirname(other_key))
        for path in ("", "\0", os.path.relpath(self.home + "/.ssh/key"), self.home + "/.ssh",
                     self.home + "/.ssh/key/", self.home + "/.ssh/.", self.home + "/.ssh/..",
                     self.home + "/.ssh/../key", self.home + "/key", self.home + "/.ssh-old/key", other_key):
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
        self.assertEqual([], os.listdir(self.home))
        self.assertFalse(os.path.exists(other_key))
        self.chowner.assert_not_called()

    def test_missing_account_and_invalid_account_homes_are_rejected(self):
        path = self.home + "/.ssh/authorized_keys"
        for home in ("", "\0", "relative", "/", "/tmp/.."):
            self.account.pw_dir = home
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
        self.util.get_userentry.return_value = None
        with self.assertRaises(OSUtilError):
            self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
        self.assertEqual([], os.listdir(self.home))
        self.chowner.assert_not_called()

    def test_public_key_creates_ssh_directory_and_appends_to_existing_keys(self):
        path = self.home + "/.ssh/authorized_keys"
        self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa first"))
        inode = os.stat(path).st_ino
        self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa second"))
        self.assertEqual("ssh-rsa first\nssh-rsa second\n", fileutil.read_file(path))
        self.assertEqual(inode, os.stat(path).st_ino)
        self.assertEqual(0o700, os.stat(self.home + "/.ssh").st_mode & 0o777)
        self.assertEqual(0o644, os.stat(path).st_mode & 0o777)

    def test_legacy_home_path_appends_in_place_and_labeling_is_best_effort(self):
        directory = os.path.join(self.home, ".ssh")
        os.mkdir(directory)
        path = os.path.join(directory, "custom_keys")
        fileutil.write_file(path, "existing\n")
        inode = os.stat(path).st_ino
        home_alias = os.path.join(self.tmp_dir, "home-base")
        os.symlink(self.tmp_dir, home_alias)
        with patch.object(conf, "get_home_dir", return_value=home_alias):
            with patch.object(self.util, "set_selinux_context", return_value=1):
                self.util.deploy_ssh_pubkey("alice", ("$HOME/alice/.ssh/custom_keys", None, "ssh-rsa test"))
                self.account.pw_dir = home_alias + "/alice"
                self.util.deploy_ssh_pubkey("alice", (home_alias + "/alice/.ssh/custom_keys", None, "ssh-rsa alias"))
        self.assertEqual(inode, os.stat(path).st_ino)
        self.assertEqual("existing\nssh-rsa test\nssh-rsa alias\n", fileutil.read_file(path))

    def test_home_and_ssh_directory_symlinks_leave_the_target_untouched(self):
        target = os.path.join(self.tmp_dir, "outside")
        os.mkdir(target)
        fileutil.write_file(target + "/authorized_keys", "unchanged")
        mode = os.stat(target).st_mode
        for directory in (self.home + "/.ssh", self.home):
            if directory == self.home:
                os.rmdir(self.home)
            os.symlink(target, directory)
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (self.home + "/.ssh/authorized_keys", None, "ssh-rsa test"))
            self.assertEqual(["authorized_keys"], os.listdir(target))
            self.assertEqual("unchanged", fileutil.read_file(target + "/authorized_keys"))
            self.assertEqual(mode, os.stat(target).st_mode)
            os.unlink(directory)
        self.chowner.assert_not_called()

    def test_public_key_rejects_unsafe_existing_destinations(self):
        os.mkdir(self.home + "/.ssh")
        target = self.tmp_dir + "/outside"
        os.mkdir(target)
        fileutil.write_file(target + "/key", "unchanged")
        for name, destination, suffix in (("nested", target, "/key"),
                                          ("key", target + "/key", ""),
                                          ("key", target + "/missing", "")):
            link = self.home + "/.ssh/" + name
            os.symlink(destination, link)
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (link + suffix, None, "ssh-rsa test"))
            self.assertEqual(["key"], os.listdir(target))
            self.assertEqual("unchanged", fileutil.read_file(target + "/key"))
            os.unlink(link)
        for create, remove in ((os.mkdir, os.rmdir), (os.mkfifo, os.unlink)):
            path = self.home + "/.ssh/key"
            create(path)
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
            remove(path)
        self.chowner.assert_not_called()

    def test_keypair_only_overwrites_keys_when_both_destinations_are_safe(self):
        path = self.home + "/.ssh/key"
        fingerprint = "A" * 40
        source = os.path.join(self.tmp_dir, fingerprint + ".prv")
        fileutil.write_file(source, "original private key")
        with patch("azurelinuxagent.common.osutil.default.CryptUtil.get_pubkey_from_prv", return_value="public"):
            self.util.deploy_ssh_keypair("alice", (path, fingerprint))
            self.assertEqual("public", fileutil.read_file(path + ".pub"))

            fileutil.write_file(source, "replacement private key")
            self.chowner.reset_mock()
            with self.assertRaises(OSUtilError):
                self.util.deploy_ssh_keypair("alice", (self.home + "/.ssh/../outside_key", fingerprint))
            target = self.tmp_dir + "/outside-key"
            fileutil.write_file(target, "unchanged")
            for destination, companion, expected in ((path + ".pub", path, "original private key"),
                                                      (path, path + ".pub", "public")):
                original = fileutil.read_file(destination)
                os.unlink(destination)
                os.symlink(target, destination)
                with self.assertRaises(OSUtilError):
                    self.util.deploy_ssh_keypair("alice", (path, fingerprint))
                self.assertEqual(expected, fileutil.read_file(companion))
                self.assertEqual("unchanged", fileutil.read_file(target))
                os.unlink(destination)
                fileutil.write_file(destination, original)
            self.chowner.assert_not_called()
        self.assertEqual([".ssh"], os.listdir(self.home))
        self.assertEqual("original private key", fileutil.read_file(path))

    def test_default_appends_certificate_keys_while_gaia_replaces_them(self):
        gaia = GaiaOSUtil()
        gaia.selinux = False
        self.account.pw_name = "admin"
        gaia.get_userentry = self.util.get_userentry
        os.mkdir(self.home + "/.ssh")
        path = self.home + "/.ssh/authorized_keys"
        fingerprint = "A" * 40
        fileutil.write_file(os.path.join(self.tmp_dir, fingerprint + ".crt"), load_data("wire/trans_cert"))
        expected = CryptUtil(conf.get_openssl_cmd()).asn1_to_ssh(load_data("wire/trans_pub"))
        for util, prefix in ((self.util, "old key\n"), (gaia, "")):
            fileutil.write_file(path, "old key\n")
            inode = os.stat(path).st_ino
            with patch.object(gaia, "_replace_user", return_value=path):
                util.deploy_ssh_pubkey("alice", (path, fingerprint, None))
                util.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa inline"))
            self.assertEqual(prefix + expected + "ssh-rsa inline\n", fileutil.read_file(path))
            self.assertEqual(inode, os.stat(path).st_ino)

    def test_gaia_rejects_malformed_paths_before_rewriting_the_username(self):
        gaia = GaiaOSUtil()
        for path in (None, "", "relative", "/home"):
            with self.assertRaises(OSUtilError):
                gaia.deploy_ssh_pubkey("alice", (path, None, "ssh-rsa test"))
            with self.assertRaises(OSUtilError):
                gaia.deploy_ssh_keypair("alice", (path, "A" * 40))

    def test_nsbsd_uses_its_fixed_home_for_admin_public_keys_only(self):
        with patch.object(NSBSDOSUtil, "resolver"):
            nsbsd = NSBSDOSUtil()
        self.account.pw_name = "admin"
        nsbsd.get_userentry = Mock(return_value=self.account)
        self.assertEqual("/usr/Firewall", nsbsd._ssh_key_home(self.account, public_key=True))
        self.assertEqual(self.home, nsbsd._ssh_key_home(self.account))
        with patch.object(nsbsd, "_norm_path", side_effect=OSUtilError("stop before write")) as normalize:
            with self.assertRaises(OSUtilError):
                nsbsd.deploy_ssh_pubkey("ovf-user", ("/ignored", None, "ssh-rsa test"))
            normalize.assert_called_once_with("/usr/Firewall/.ssh/authorized_keys", "admin", public_key=True)
            normalize.reset_mock()
            with self.assertRaises(OSUtilError):
                nsbsd.deploy_ssh_keypair("admin", (self.home + "/.ssh/key", "A" * 40))
            normalize.assert_called_once_with(self.home + "/.ssh/key", "admin")
