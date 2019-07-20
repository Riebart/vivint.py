#!/usr/bin/env python

import os
import argparse
import time

import vivint

import waflibs

parser = argparse.ArgumentParser()
waflibs.arg_parse.enable_verbose_logging(parser)
waflibs.arg_parse.use_config(parser, "{}/.config/vivint.yml".format(os.environ["HOME"]))
args = parser.parse_args()

logger = waflibs.log.create_logger(args)

config = waflibs.config.parse_config_file(args.config)

# Set up the connection to the cloud session
session = vivint.VivintCloudSession(config["username"], config["password"])

# List all panels (sites) that this user account has access to
panels = session.get_panels()
logger.debug("panels: {}".format(panels))

for panel in panels:
    print(panel.get_devices())
# In this case, get the first thermostat from the first site
door = panels[0].get_devices(device_type_set=[
    vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_DOOR_LOCK
])[0]
logger.debug("door: {}".format(door))

# Let the change propagate for a bit
time.sleep(2)

for panel in panels:
    print("panel: {}, armed state: {}".format(panel, panel.get_armed_state()))
    # Update every panel. Doing this also updates devices that
    # were spawned from those panels in-place, unless you set
    # devices' receive_updates property is set to False.
    panel.update_devices()

# This will likely now reflect the current state of the thermostat
print(door.current_state())
