import re
import ipaddress

from pymisp import PyMISP
import plyara

class IOCValidator:
    def validate(self, ioc):
        return False


class IPValidator(IOCValidator):
    def validate(self, ioc):
        try:
            if ioc.endswith(".0"):
                return False
            ip = ipaddress.ip_address(ioc)
            return ip.is_global
        except ValueError:
            return False


class DomainValidator(IOCValidator):
    regex = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')

    def validate(self, ioc):
        if DomainValidator.regex.match(ioc) is None:
            return False
        return True


class AlwaysOKValidator(IOCValidator):
    def validate(self, ioc):
        return True

class YaraValidator(IOCValidator):
    parser = plyara.Plyara()
    def validate(self, ioc):
        try:
            YaraValidator.parser.parse_string(ioc)
            return True
        except plyara.exceptions.ParseError:
            return False


class ValidatorFactory:
    ip_validator = None
    domain_validator = None
    always_ok_validator = None

    @staticmethod
    def get(ioc_type):
        if ioc_type in ["ip-src", "ip-dst"]:
            if ValidatorFactory.ip_validator is None:
                ValidatorFactory.ip_validator = IPValidator()
            return ValidatorFactory.ip_validator
        elif ioc_type in ["domain", "hostname"]:
            if ValidatorFactory.domain_validator is None:
                ValidatorFactory.domain_validator = DomainValidator()
            return ValidatorFactory.domain_validator
        else:
            if ValidatorFactory.always_ok_validator is None:
                ValidatorFactory.always_ok_validator = AlwaysOKValidator()
            return ValidatorFactory.always_ok_validator


class MISPBuilder:
    def __init__(self):
        self._url = ""
        self._key = ""
        self._verify = False
        self._cert = None
        self._debug = False

    def url(self, v):
        if v:
            self._url = v
        return self

    def authkey(self, v):
        if v:
            self._key = v
        return self

    def tls_cert(self, v):
        if v:
            self._cert = v
        return self

    def tls_verify(self, v):
        if v:
            self._verify = v
        return self

    def debug(self, v):
        if v:
            self._debug = v
        return self

    def build(self):
        return PyMISP(self._url, self._key, ssl=self._verify, debug=self._debug, cert=self._cert, tool="misp2falco")


