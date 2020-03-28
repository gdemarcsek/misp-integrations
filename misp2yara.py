#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import json
import datetime
import logging
import sys
import pathlib

from common import *

misp_logger = logging.getLogger('pymisp')
misp_logger.setLevel(logging.ERROR)

TRUSTED_ORGS = ["CIRCL", "ESET", "CiviCERT", "INCIBE", "CthulhuSPRL.be"]


def misp2yara(result, target_dir):
    for ioc in result['Attribute']:
        path = pathlib.Path(target_dir).expanduser().joinpath(
            "%s.sig" % ioc["uuid"])
        if not path.is_file() or path.stat().st_mtime < int(ioc['timestamp']):
            path.write_text(ioc['value'], encoding='utf8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Update Yara rules from MISP feeds")
    parser.add_argument('--extra-org', metavar='org', nargs='+',
                        default=[], help='Additional organization to use')
    parser.add_argument('--no-published-only', action='store_true',
                        default=False, help='Include non-puublished attributes')
    parser.add_argument('--max-days-old', type=int, default=365 *
                        5, help='Consider feeds updated in <= N days')
    parser.add_argument('--limit', type=int, default=None,
                        required=False, help='Limit result set from MISP')
    parser.add_argument('--target_dir', type=str, required=True,
                        help='Path to directory where Yara files should be downloaded to')
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

    crit = {"to_ids": True,
            "deleted": False,
            "type_attribute": "yara",
            "org": set(TRUSTED_ORGS).union(set(args.extra_org)),
            "event_timestamp": (datetime.datetime.now() - datetime.timedelta(days=args.max_days_old)).timestamp()}

    if not args.no_published_only:
        crit["published"] = True

    if args.limit:
        crit["limit"] = args.limit

    result = misp.search('attributes', **crit)
    misp2yara(result, args.target_dir)
    sys.exit(0)
