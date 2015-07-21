__author__ = 'wartortell'

import os
import json
import time
import argparse
import requests


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--report',
                        action='store',
                        required='true',
                        help='Path to the file or directory of report(s) to parse')

    parser.add_argument('-rf', '--report_format',
                        action='store',
                        choices=['pdf', 'txt', 'html'],
                        default='pdf',
                        help='The format of the report(s) to parse (pdf|txt|html)')

    parser.add_argument('-v', '--verify',
                        action='store_true',
                        help='Request the user to verify the type and use of each indicator')

    parser.add_argument('-s', '--server',
                        action='store',
                        help='The MISP server address')

    parser.add_argument('-a', '--auth',
                        action='store',
                        help='Your authentication key to access the MISP server API')

    parser.add_argument('-p', '--page',
                        action='store',
                        help='The page to begin looking for indicators on (used for reports with an indicator appendix)')

    parser.add_argument('--ssl',
                        action='store_true',
                        help='Use SSL for accessing the MISP server')

    return parser


def get_misp_event_json(args, attributes):
    event_json = {"Event": {
                      "info": "MISP Event generated from report %s" % args.report,
                      "timestamp": "1",
                      "attribute_count": 0,
                      "analysis": "0",
                      "date": time.strftime("%Y-%m-%d"),
                      "org": "",
                      "distribution": "0",
                      "Attribute": [],
                      "proposal_email_lock": False,
                      "threat_level_id": "0"
                      }
                  }

    event_json["Event"]["Attribute"] = attributes

    return event_json


def create_attribute(category, at_type, value, page, file_name):
    at = {"category": category,
          "type": at_type,
          "value": value,
          "timestamp": "0",
          "to_ids": "1",
          "distribution": "0",
          "comment": "Attribute found on page %d of %s" % (page, file_name)
          }

    return at


def get_option(options, at):
    print("\nInclude %s %s in MISP as:\n-------------------------" % (at["type"], at["match"]))
    for key in sorted(options.keys()):
        print("%d: %s" % (key, options[key]))

    while True:
        option = raw_input("Enter an option: ")

        if option in ["0", "1", "2", "3"]:
            if option == "0":
                return {}

            sp = options[int(option)].split(":")

            return create_attribute(sp[0].strip(), sp[1].strip(), at["match"], at["page"], at["file"])

        print("%d is not a valid option!" % option)


def create_url(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Network activity : url",
                   2: "Payload delivery : url",
                   3: "External analysis : url"}

        return get_option(options, at)
    else:
        return create_attribute("Network activity", "url", at["match"], at["page"], at["file"])


def create_host(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Network activity : hostname",
                   2: "Payload delivery : hostname",
                   3: "External analysis : hostname"}

        return get_option(options, at)
    else:
        return create_attribute("Network activity", "hostname", at["match"], at["page"], at["file"])


def create_ip(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Network activity : ip-dst",
                   2: "Network activity : ip-src",
                   3: "Payload delivery : ip-dst",
                   4: "Payload delivery : ip-src",
                   5: "External analysis : ip-dst",
                   6: "External analysis : ip-src"}

        return get_option(options, at)
    else:
        return create_attribute("Network activity", "ip-dst", at["match"], at["page"], at["file"])


def create_email(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Network activity : email-dst",
                   2: "Payload delivery : email-src",
                   3: "Payload delivery : email-dst",
                   4: "Targeting data : target-email"}

        return get_option(options, at)
    else:
        return create_attribute("Payload delivery", "email-src", at["match"], at["page"], at["file"])


def create_md5(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Artifacts dropped : md5",
                   2: "Payload delivery : md5",
                   3: "Payload installation : md5",
                   4: "External analysis : md5"}

        return get_option(options, at)
    else:
        return create_attribute("Artifacts dropped", "md5", at["match"], at["page"], at["file"])


def create_sha1(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Artifacts dropped : sha1",
                   2: "Payload delivery : sha1",
                   3: "Payload installation : sha1",
                   4: "External analysis : sha1"}

        return get_option(options, at)
    else:
        return create_attribute("Artifacts dropped", "sha1", at["match"], at["page"], at["file"])


def create_sha256(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Artifacts dropped : sha256",
                   2: "Payload delivery : sha256",
                   3: "Payload installation : sha256",
                   4: "External analysis : sha256"}

        return get_option(options, at)
    else:
        return create_attribute("Artifacts dropped", "sha256", at["match"], at["page"], at["file"])


def create_cve(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Payload delivery : vulnerability",
                   2: "Payload installation : vulnerability",
                   3: "External analysis : vulnerability"}

        return get_option(options, at)
    else:
        return create_attribute("Payload delivery", "vulnerability", at["match"], at["page"], at["file"])


def create_registry(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Artifacts dropped : regkey",
                   2: "Artifacts dropped : regkey|value",
                   3: "Persistance mechanism : regkey",
                   4: "Persistance mechanism : regkey|value",
                   5: "External analysis : regkey",
                   6: "External analysis : regkey|value"}

        return get_option(options, at)
    else:
        return create_attribute("Artifacts dropped", "regkey", at["match"], at["page"], at["file"])


def create_filepath(args, at):
    if args.verify:
        options = {0: "Do not include",
                   1: "Artifacts dropped : filename",
                   2: "Persistance mechanism : filename",
                   3: "External analysis : filename"}

        return get_option(options, at)
    else:
        return create_attribute("Artifacts dropped", "filename", at["match"], at["page"], at["file"])


def get_misp_attributes_json(args, reports_json):
    attributes = []

    for at in reports_json:

        if args.page and (int(at["page"]) < int(args.page)):
            print("Ignored %s %s on page %s!" % (at["type"], at["match"], at["page"]))
            continue

        at_json = {}

        if at["type"] == "URL":
            at_json = create_url(args, at)

        elif at["type"] == "Host":
            at_json = create_host(args, at)

        elif at["type"] == "IP":
            at_json = create_ip(args, at)

        elif at["type"] == "Email":
            at_json = create_email(args, at)

        elif at["type"] == "MD5":
            at_json = create_md5(args, at)

        elif at["type"] == "SHA1":
            at_json = create_sha1(args, at)

        elif at["type"] == "SHA256":
            at_json = create_sha256(args, at)

        elif at["type"] == "CVE":
            at_json = create_cve(args, at)

        elif at["type"] == "Registry":
            at_json = create_registry(args, at)

        elif at["type"] in ["Filename", "Filepath"]:
            at_json = create_filepath(args, at)

        if len(at_json.keys()) > 0:
            attributes.append(at_json)

    return attributes


def create_misp_event(args, events_json):

    url = "%s/events" % args.server
    headers = {"Authorization": args.auth,
               "Accept": "application/json",
               "Content-Type": "application/json"}

    return requests.post(url, data=json.dumps(events_json), headers=headers, verify=False)


def print_usage(message, args, parser):
    args.logger.debug(message)
    parser.print_help()
    exit(-1)


def main():
    parser = parse_arguments()

    args = parser.parse_args()

    ioc_python_path = os.path.join("ioc_parser", "iocp.py")

    print("Parsing report(s) at %s..." % args.report)
    os.system("python %s \"%s\" -d -i %s -o json > temp.json" % (ioc_python_path, args.report, args.report_format))

    print("Reading in results...")
    with open("temp.json", "r") as f:
        s = "[%s]" % f.read().replace("\n", ",\n")[:-2]

    print("Creating MISP event...")
    reports_json = json.loads(s)
    misp_attribute_json = get_misp_attributes_json(args, reports_json)
    misp_event_json = get_misp_event_json(args, misp_attribute_json)
    print("Attributes found in report: %d" % len(misp_event_json["Event"]["Attribute"]))

    with open("misp_%s.json" % args.report, "w") as f:
        f.write(json.dumps(misp_event_json, indent=4))

    r = create_misp_event(args, misp_event_json)

    print "MISP API add request response: %s" % str(r)


if __name__ == "__main__":
    main()