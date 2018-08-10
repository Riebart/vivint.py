#!/usr/bin/env python3
"""
Demonstrats a long-lived polling thread that checks the state of all thermostats and writes them to stdout.
"""

from __future__ import print_function
import os
import sys
import json
import time
import argparse

import vivint

running = True


def __log(s, v):
    if v:
        print(s, file=sys.stderr)


def periodic_update(interval, out_file, verbose):
    if out_file is None:
        fp = sys.stdout
    else:
        # Open the file for appending
        fp = open(out_file, "a")

    __log("Establishing session", verbose)
    session = vivint.VivintCloudSession(os.environ["USERNAME"],
                                        os.environ["PASSWORD"])
    __log("Listing panels", verbose)
    panels = session.get_panels()
    while running:
        for panel in panels:
            __log("Updating panel %d" % panel.id(), verbose)
            panel.update_devices()
            __log("Listing thermosats", verbose)
            thermostats = panel.get_devices(device_type_set=[
                vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_THERMOSTAT
            ])
            for thermostat in thermostats:
                __log(
                    "Getting state of thermostat %d on panel %d" %
                    (thermostat.id(), panel.id()), verbose)
                state = thermostat.current_state()

                # Now bolt the other context to the state, and write it out.
                state["panel_arm_state"] = panel.get_armed_state()
                state["panel_id"] = panel.id()
                state["thermostat_id"] = thermostat.id()
                state["timestamp"] = time.time()
                __log("Logging state", verbose)
                fp.write(json.dumps(state, sort_keys=True) + "\n")
                fp.flush()
        __log("Sleeping", verbose)
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--interval",
        "-i",
        help="Delay, in seconds, between polling",
        type=float,
        required=False,
        default=60.0)
    parser.add_argument(
        "--output",
        "-o",
        help="Output file name, otherwise it goes to stdout",
        required=False,
        default=None)
    parser.add_argument(
        "--verbose",
        "-v",
        help="Display log messages on stderr",
        required=False,
        default=False,
        action="store_true")

    pargs = parser.parse_args()

    periodic_update(pargs.interval, pargs.output, pargs.verbose)
