#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP

import argparse
import os
import json
import datetime
import yaml
import logging
import ipaddress
import re
import sys


misp_logger = logging.getLogger('pymisp')
misp_logger.setLevel(logging.ERROR)


class FalcoRules:
    @staticmethod
    def macro(name, condition):
        return {"macro": name, "condition": condition}

    @staticmethod
    def list(name, items):
        return {"list": name, "items": list(map(lambda item: "\"%s\"" % item, items))}

    @staticmethod
    def rule(name, desc, condition, output, prio, tags):
        return {"rule": name, "desc": desc, "condition": condition, "enabled": True, "output": output, "priority": prio, "tags": tags}


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


def misp2falco(result):
    falcoRules = []
    iocsByType = {k: set([]) for k in supported_attributes}

    for ioc in result['Attribute']:
        if "value" in ioc and ioc['value']:
            v = ioc['value']
            if ValidatorFactory.get(ioc['type']).validate(v):
                iocsByType[ioc['type']].add(ioc['value'].strip())

    falcoRules.extend([FalcoRules.list("misp_mal_domains", list(iocsByType["domain"].union(iocsByType["hostname"]))),
                       FalcoRules.list(
                           "misp_mal_ips", list(iocsByType["ip-src"].union(iocsByType["ip-dst"]))),
                       FalcoRules.macro("misp_mal_domain",
                                        "(fd.sip.name in (misp_mal_domains))"),
                       FalcoRules.macro("misp_mal_ip",
                                        "(fd.rip in (misp_mal_ips))"),
                       FalcoRules.macro(
                           "misp_mal_event_ip", "(evt.type in (connect, sendmsg, sendto) and evt.dir=< and (fd.net != \"127.0.0.0/8\" and not fd.snet in (rfc_1918_addresses)) and (misp_mal_ip))"),
                       FalcoRules.macro(
                           "misp_mal_event_domain", "(evt.type in (connect, sendmsg, sendto) and evt.dir=< and (fd.net != \"127.0.0.0/8\" and not fd.snet in (rfc_1918_addresses)) and (misp_mal_domain_connect))"),
                       FalcoRules.rule("Detect known malicious IPs based on MISP feeds", "Suspicious network connection", "misp_mal_event_ip",
                                       "Suspicious connection based on MISP threat intel (command=%proc.cmdline port=%fd.rport ip=%fd.rip)", "CRITICAL", ["misp", "network", "ioc_ip"]),
                       FalcoRules.rule("Detect known malicious domains based on MISP feeds", "Suspicious network connection", "misp_mal_event_domain",
                                       "Suspicious connection based on MISP threat intel (command=%proc.cmdline port=%fd.rport ip=%fd.rip)", "CRITICAL", ["misp", "network", "ioc_domain"])
                       ])

    return falcoRules


if __name__ == '__main__':
    misp_url = os.environ.get("MISP_URL", "")
    misp_key = os.environ.get("MISP_AUTHKEY", "")
    misp_verify = os.environ.get("MISP_VERIFY_CERT", "")
    misp_client_cert_path = os.environ.get("MISP_CLIENT_CERT", "")

    if not misp_url or not misp_key:
        print("Please provide both MISP_URL and MISP_AUTHKEY environment variables.", file=sys.stderr)
        sys.exit(1)

    misp = MISPBuilder()\
        .url(misp_url)\
        .authkey(misp_key)\
        .tls_verify(misp_verify.lower().strip() == "true")\
        .tls_cert(misp_client_cert_path)\
        .build()

    supported_attributes = ["ip-src", "ip-dst", "domain", "hostname"]
    crit = {"category": ["Payload delivery", "Network activity"],
            "to_ids": True,
            "deleted": False,
            "published": True,
            "type_attribute": supported_attributes,
            "event_timestamp": (datetime.datetime.now() - datetime.timedelta(days=30)).timestamp()}
    result = misp.search('attributes', **crit)
    print(yaml.dump(misp2falco(result), width=float("inf")))
    sys.exit(0)
