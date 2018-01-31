#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "@t33m"
__license__ = "MIT"


import re
import json
import censys
from censys import *
import shodan
import argparse
from netaddr import *
from gevent import spawn, monkey
from gevent.queue import JoinableQueue
from collections import OrderedDict
from termcolor import colored
import config

monkey.patch_all(thread=False)


class PassiveScan(object):
    def __init__(self, args):
        self.__ip = args.ip
        self.__threads = args.threads
        self.__json = args.json
        self.__errors = args.errors
        self.__ports = args.ports
        self.__apis = []
        if args.shodan:
            self.__apis.append(shodan.Shodan(config.SHODAN_API_KEY))
        if args.censys:
            self.__apis.append(censys.ipv4.CensysIPv4(config.CENSYS_API_ID,
                                                      config.CENSYS_SECRET))

    def start(self):
        if not self.__threads:
            self.__threads = len(IPNetwork(self.__ip)) if len(IPNetwork(self.__ip)) <= 10 else 10
        if len(IPNetwork(self.__ip)) < int(self.__threads):
            print("Please decrease number of threads to number of hosts <= %s" % len(IPNetwork(self.__ip)))
            exit()

        queue = JoinableQueue()
        [queue.put(str(ip)) for ip in IPNetwork(self.__ip)]

        for t in range(int(self.__threads)):
            spawn(self.get_ip_info, queue, self.__apis)

        queue.join()

    def get_ip_info(self, queue, apis):
        while not queue.empty():
            data = OrderedDict()
            data["ip"] = queue.get()

            for api in apis:
                if api.__class__.__name__ == "Shodan":
                    data["shodan"] = self.search_shodan(data["ip"], api)
                    if not self.__errors:
                        if "error" in data["shodan"]:
                            data.pop("shodan", None)
                elif api.__class__.__name__ == "CensysIPv4":
                    data["censys"] = self.search_censys(data["ip"], api)
                    if not self.__errors:
                        if "error" in data["censys"]:
                            data.pop("censys", None)

            if not self.__errors:
                if data not in ["shodan", "censys"]:
                    data = None

            if data:
                self.output(data)

            queue.task_done()

    def search_shodan(self, ip, api):
        data = OrderedDict()

        try:
            result = api.host(ip)
        except shodan.APIError as e:
            data["error"] = str(e)
        else:
            if isinstance(result, dict):
                if "ip_str" in result:
                    if "last_update" in result:
                        data["last_update"] = result["last_update"]
                    if "asn" in result:
                        data["asn"] = int(re.findall("\d+", result["asn"])[0])
                    if "isp" in result:
                        data["isp"] = result["isp"]
                    if "org" in result:
                        data["org"] = result["org"]
                    if "country_code" in result:
                        data["country_code"] = result["country_code"]
                    if "hostnames" in result and result["hostnames"]:
                        data["hostnames"] = result["hostnames"]
                    if "ports" in result:
                        data["ports"] = result["ports"]
        finally:
            return data

    def search_censys(self, ip, api):
        data = OrderedDict()

        try:
            result = api.view(ip)
        except censys.base.CensysException as e:
            data["error"] = str(e)
        else:
            if isinstance(result, dict):
                if "ip" in result:
                    if "updated_at" in result:
                        data["last_update"] = result["updated_at"]
                    if "autonomous_system" in result:
                        if "asn" in result["autonomous_system"]:
                            data["asn"] = result["autonomous_system"]["asn"]
                        if "description" in result["autonomous_system"]:
                            data["as_name"] = result["autonomous_system"]["name"]
                    if "location" in result:
                        if "country_code" in result["location"]:
                            data["country_code"] = result["location"]["country_code"]
                    if "protocols" in result:
                        data["ports"] = [int(port.split("/")[0]) for port in result["protocols"]]
        finally:
            return data

    def output(self, data):
        if self.__json:
            print(json.dumps(data, indent=4, sort_keys=False))

        else:
            for key, value in data.iteritems():
                if key is "ip":
                    print(colored(key, 'yellow'), colored(value, 'green'))

                if key in ['shodan', 'censys']:
                    print("  %s:" % (colored(key, 'yellow')))

                if isinstance(value, dict):
                    for key, value in value.iteritems():
                        if key == "ports":
                            if self.__ports:
                                if key == "ports":
                                    print("    %s: %s" % (colored(key, 'yellow'), " ".join([colored(port, 'red') if port in self.__ports else colored(port, 'green') for port in value])))
                                else:
                                    print("    %s: %s" % (colored(key, 'yellow'), colored(value, 'green')))
                        else:
                            print("    %s: %s" % (colored(key, 'yellow'), colored(value, 'green')))


def main():
    help = "Passive scan"
    parser = argparse.ArgumentParser(description=help, epilog="Author: %s" % __author__)
    parser.add_argument("-ip", help="target ip or net", required=False)
    parser.add_argument("--shodan", "-s", help="use shodan", required=False, action='store_true')
    parser.add_argument("--censys", "-c", help="use censys", required=False, action='store_true')
    parser.add_argument("--threads", "-t", help="number of threads", required=False, type=int)
    parser.add_argument("--json", help='json output', required=False, action='store_true')
    parser.add_argument("--errors", "-e", help='show APIs errors', required=False, action='store_true')
    parser.add_argument("--ports", "-p", type=int, nargs='*', help='specify intersting ports', required=False)
    args = parser.parse_args()

    PassiveScan(args).start()


if __name__ == '__main__':
    main()
