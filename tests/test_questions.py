import unittest

import mock
import os
import sys

from microstack_init.questions import NovaHypervisor

sys.path.append(os.getcwd())  # noqa


class TestNovaHypervisor(unittest.TestCase):

    @mock.patch('os.path.exists', return_value=False)
    def test_is_kvm_api_available_no_kvm_char_file(self, mock_exists):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('os.access', side_effect=(
        lambda p, m: False if p == '/dev/kvm' else True))
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_inaccessible_kvm_char_file(
            self, mock_exists, mock_access):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('stat.S_ISCHR', side_effect=lambda m: False)
    @mock.patch('os.stat')
    @mock.patch('os.access', return_value=True)
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_kvm_file_is_not_char_file(
            self, mock_exists, mock_access, mock_stat, mock_ischr):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('os.minor')
    @mock.patch('os.major')
    @mock.patch('stat.S_ISCHR', return_value=True)
    @mock.patch('os.stat')
    @mock.patch('os.access', return_value=True)
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_kvm_file_invalid_major_minor(
        self, mock_exists, mock_access, mock_stat, mock_ischr,
            invalid_major, invalid_minor):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('os.minor')
    @mock.patch('os.major', return_value=42)
    @mock.patch('stat.S_ISCHR', return_value=True)
    @mock.patch('os.stat')
    @mock.patch('os.access', return_value=True)
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_kvm_file_invalid_major(
        self, mock_exists, mock_access, mock_stat, mock_ischr,
            invalid_major, invalid_minor):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('os.minor', return_value=42)
    @mock.patch('os.major', return_value=10)
    @mock.patch('stat.S_ISCHR', return_value=True)
    @mock.patch('os.stat')
    @mock.patch('os.access', return_value=True)
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_kvm_file_invalid_minor(
        self, mock_exists, mock_access, mock_stat, mock_ischr,
            invalid_major, invalid_minor):
        self.assertFalse(NovaHypervisor._is_kvm_api_available())

    @mock.patch('os.minor', return_value=232)
    @mock.patch('os.major', return_value=10)
    @mock.patch('stat.S_ISCHR', return_value=True)
    @mock.patch('os.stat')
    @mock.patch('os.access', return_value=True)
    @mock.patch('os.path.exists', return_value=True)
    def test_is_kvm_api_available_ok(
        self, mock_exists, mock_access, mock_stat, mock_ischr,
            invalid_major, invalid_minor):
        self.assertTrue(NovaHypervisor._is_kvm_api_available())


if __name__ == '__main__':
    unittest.main()
