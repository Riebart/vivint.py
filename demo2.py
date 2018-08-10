#!/usr/bin/env python3
"""
Demonstrats a long-lived polling thread that checks the state of all thermostats and writes them to stdout.
"""

import os
import sys
import json
import time
import vivint

running = True


def periodic_update(interval):
    session = vivint.VivintCloudSession(os.environ["USERNAME"],
                                        os.environ["PASSWORD"])
    panels = session.get_panels()
    while running:
        for panel in panels:
            panel.update_devices()
            thermostats = panel.get_devices(device_type_set=[
                vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_THERMOSTAT
            ])
            for thermostat in thermostats:
                state = thermostat.current_state()
                state["panel_id"] = panel.id()
                state["thermostat_id"] = thermostat.id()
                state["timestamp"] = time.time()
                print(json.dumps(state))
        time.sleep(interval)


periodic_update(float(sys.argv[1]) if len(sys.argv) > 1 else 60)
