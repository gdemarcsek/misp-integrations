#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import json
import datetime
import yaml
import logging
import sys

from common import *

misp_logger = logging.getLogger('pymisp')
misp_logger.setLevel(logging.ERROR)

SUPPORTED_ATTRIBUTES = ["ip-src", "ip-dst", "domain", "hostname"]
TRUSTED_ORGS = ["CIRCL", "ESET"]


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


def misp2falco(result):
    falcoRules = []
    iocsByType = {k: set([]) for k in SUPPORTED_ATTRIBUTES}

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
                           "misp_mal_event_ip", "(evt.type in (sendmsg, sendto) and evt.dir=< and (fd.net != \"127.0.0.0/8\" and not fd.snet in (rfc_1918_addresses)) and (misp_mal_ip))"),
                       FalcoRules.macro(
                           "misp_mal_event_domain", "(evt.type in (sendmsg, sendto) and evt.dir=< and (fd.net != \"127.0.0.0/8\" and not fd.snet in (rfc_1918_addresses)) and (misp_mal_domain))"),
                       FalcoRules.rule("Detect known malicious IPs based on MISP feeds", "Suspicious network connection", "misp_mal_event_ip",
                                       "Suspicious connection based on MISP threat intel (IP) (type=%evt.type command=%proc.cmdline port=%fd.rport ip=%fd.rip)", "WARNING", ["misp", "network", "ioc_ip"]),
                       FalcoRules.rule("Detect known malicious domains based on MISP feeds", "Suspicious network connection", "misp_mal_event_domain",
                                       "Suspicious connection based on MISP threat intel (Hostname) (type=%evt.type command=%proc.cmdline port=%fd.rport ip=%fd.sip domain=%fd.sip.name)", "WARNING", ["misp", "network", "ioc_domain"])
                       ])

    return falcoRules


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Convert MISP feeds to Sysdig Falco rules. Currently supported: %s" % SUPPORTED_ATTRIBUTES)
    parser.add_argument('--extra-org', metavar='org', nargs='+',
                        default=[], help='Additional organization to use')
    parser.add_argument('--no-published-only', action='store_true',
                        default=False, help='Include non-puublished attributes')
    parser.add_argument('--max-days-old', type=int, default=30,
                        help='Consider feeds updated in <= N days')
    parser.add_argument('--limit', type=int, default=None,
                        required=False, help='Limit result set from MISP')
    args = parser.parse_args()

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

    crit = {"category": ["Payload delivery", "Network activity"],
            "to_ids": True,
            "include_context": False,
            "deleted": False,
            "type_attribute": SUPPORTED_ATTRIBUTES,
            "org": set(TRUSTED_ORGS).union(set(args.extra_org)),
            "event_timestamp": (datetime.datetime.now() - datetime.timedelta(days=args.max_days_old)).timestamp()}

    if not args.no_published_only:
        crit["published"] = True

    if args.limit:
        crit["limit"] = args.limit

    result = misp.search('attributes', **crit)
    print(yaml.dump(misp2falco(result), width=float("inf")))
    sys.exit(0)
