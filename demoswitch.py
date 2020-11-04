#!/usr/bin/env python3

import time
import os
import vivint
from datetime import datetime

# Set up the connection to the cloud session
session = vivint.VivintCloudSession(os.environ["USERNAME"],
                                    os.environ["PASSWORD"])

# Sensors and Switches
# switch_one_name = "Living Room Main Lights"
# switch_two_name = "Dining Room Lights"

# sensor_one_name = "Living Room Motion Detector"
# sensor_two_name = "Dining Room Motion Detector"

# List all panels (sites) that this user account has access to
panels = session.get_panels()


multiswitches = panels[0].get_devices(device_type_set=[
    vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_LIGHT_MODULE
])

sensors = panels[0].get_devices(device_type_set=[
    vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_WIRELESS_SENSOR
])

# Let the change propagate for a bit
time.sleep(2)
for panel in panels:
    # Update every panel. Doing this also updates devices that
    # were spawned from those panels in-place, unless you set
    # devices' receive_updates property is set to False.
    panel.update_devices()

    for multiswitch in multiswitches:
        state = multiswitch.current_state()
        print("Multiswitch:", state)

        # if state.get("name") == switch_one_name:
        #     switch_one_state = state.get("val")
        #     switch_one = multiswitch
        # if state.get("name") == switch_two_name:
        #     switch_two_state = state.get("val")
        #     switch_two = multiswitch

    for sensor in sensors:
        state = sensor.current_state()
        print("Sensor:", state)

        # #use proximity sensors to detect movement in a room, then turn on lights
        # if state.get("name") == sensor_one_name:
        #     #just a fun light turn on and off sequence
        #     switch_one.set_switch(100)
        #     switch_one.set_switch(80)
        #     switch_one.set_switch(40)
        #     switch_one.set_switch(0)

        # if state.get("name") == sensor_two_name:
        #     switch_two.set_switch(100)
        #     switch_two.set_switch(80)
        #     switch_two.set_switch(40)
        #     switch_two.set_switch(0)