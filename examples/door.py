#!/usr/bin/env python3

import time
import vivint

# Set up the connection to the cloud session
session = vivint.VivintCloudSession("john.smith@example.com",
                                    "SuperSecretPassword")

# List all panels (sites) that this user account has access to
panels = session.get_panels()

for panel in panels:
    logger.debug("devices in panel {}: {}".format(panel, panel.get_devices()))

# In this case, get the first door from the first site
door = panels[0].get_devices(device_type_set=[
    vivint.VivintCloudSession.VivintDevice.DEVICE_TYPE_DOOR_LOCK
])[0]

# Get the current state and print it out
print("Door state:", door.current_state())

# Let the change propagate for a bit
time.sleep(2)
for panel in panels:
    # Update every panel. Doing this also updates devices that
    # were spawned from those panels in-place, unless you set
    # devices' receive_updates property is set to False.
    panel.update_devices()

# This will likely now reflect the current state of the door
print(door.current_state())
