import datetime
import os
import subprocess
import typing as t

import yaml


class DateRange:
    start: t.Optional[datetime.date]
    end: t.Optional[datetime.date]

    def __init__(self, start: t.Optional[datetime.date]=None, end: t.Optional[datetime.date]=None):
        self.start = start
        self.end = end

    def inside(self, when: t.Union[datetime.datetime, datetime.date]):
        if isinstance(when, datetime.datetime):
            when = when.date()
        if self.start is not None and when < self.start:
            return False
        if self.end is not None and when > self.end:
            return False
        return True


class SensitiveConfig:
    imap_password: t.Optional[str]

    def __init__(self, data: t.Any):
        self.imap_password = data.get('imap_password')


def decrypt_sops_file(path: str) -> t.Mapping[str, t.Any]:
    command = ["sops", "--decrypt", path]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise Exception(
            'Error while executing "{0}": status code {1}, stderr:\n{2}'.format(' '.join(command), process.returncode, stderr))
    return yaml.safe_load(stdout)


class Configuration:
    config_directory: str

    own_ips: t.Dict[str, DateRange]
    identify_own_ips_from_dkim_and_spf: bool

    imap_server: t.Optional[str]
    imap_folder: t.Optional[str]
    imap_user: t.Optional[str]

    _sensitive_config: t.Optional[SensitiveConfig]

    def __init__(self, config_directory: str, data: t.Any):
        self.config_directory = config_directory
        self._sensitive_config = None

        self.own_ips = {}
        if 'own_ips' in data:
            for ip, ip_data in data['own_ips'].items():
                self.own_ips[ip] = DateRange(start=ip_data.get('from'), end=ip_data.get('until'))
        self.identify_own_ips_from_dkim_and_spf = data.get('identify_own_ips_from_dkim_and_spf', False)

        self.imap_server = data.get('imap_server')
        self.imap_folder = data.get('imap_folder')
        self.imap_user = data.get('imap_user')

    def _load_sensitive_config(self):
        path = os.path.join(self.config_directory, 'config.sops.yaml')
        data = decrypt_sops_file(path)
        self._sensitive_config = SensitiveConfig(data)

    def is_own_ip(self, ip: str, when: t.Union[datetime.datetime, datetime.date]):
        date_range = self.own_ips.get(ip)
        if date_range is None:
            return False
        return date_range.inside(when)

    def get_imap_password(self) -> t.Optional[str]:
        if self._sensitive_config is None:
            self._load_sensitive_config()

        return self._sensitive_config.imap_password


def load_config(path='config.yaml') -> Configuration:
    with open(path, 'rb') as f:
        data = yaml.safe_load(f)
    return Configuration(os.path.dirname(path), data)
