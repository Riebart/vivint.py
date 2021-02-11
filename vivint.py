#!/usr/bin/env python3
"""
Provides an interface to the Vivint cloud service by authenticating to the API with the
account's username and password.
"""

import os
import re
import sys
import time
import json
import base64
import urllib3
import argparse
import threading

from datetime import datetime

try:
    import certifi
except:
    pass

from http.cookies import SimpleCookie

# pylint: disable=E0611,E0401
from urllib.parse import urlencode, unquote, quote, quote_plus

VIVINT_API_ENDPOINT = "https://www.vivintsky.com"


def _flip_dict(d):
    """
    Flip a dictionary to map values to keys
    """
    return dict([(v, k) for k, v in d.items()])


def _urllib_pool():
    if "certifi" not in sys.modules:
        return urllib3.PoolManager()
    else:
        return urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
                                   ca_certs=certifi.where())


class VivintCloudSession(object):
    """
    Implements the surrounding components for authenticating, retrieving a session token,
    and refreshing the token as necessary. This is required for all other cloud-related
    operations.
    """
    class VivintDevice(object):
        """
        A top level abstract type that represents all types of Vivint devices.
        """
        # This one applies to a variety of sensors:
        # - Heat detectors
        # - Freeze detectors
        # - Smoke detectors
        # - Door/window sensors
        # - Glass break sensors
        DEVICE_TYPE_WIRELESS_SENSOR = "wireless_sensor"

        # This may only represent newer touch panels, not the older style
        DEVICE_TYPE_TOUCH_PANEL = "primary_touch_link_device"

        DEVICE_TYPE_DOOR_LOCK = "door_lock_device"

        # Doorbells appear as cameras too, you can tell just by the name.
        DEVICE_CAMERA = "camera_device"

        # This may only apply to Element thermostats?
        DEVICE_TYPE_THERMOSTAT = "thermostat_device"

        # This is likely separate from other kinds of switches
        # This specifically is the multi-level light module.
        DEVICE_TYPE_LIGHT_MODULE = "multilevel_switch_device"

        # Represents wireless sensors like door sensors but also hard wired motion detectors
        DEVICE_TYPE_MOTION_SENSOR = "wireless_sensor"

        def __init__(self, body, panel_root):
            self._body = body
            self.__panel_root = panel_root
            self._pool = _urllib_pool()

            # When set to False, this device will not be updated when the panel root's
            # update_devices() method is called.
            self.receive_updates = True

        def get_authorization_headers(self):
            return self.__panel_root.get_authorization_headers()

        def get_panel_root(self):
            """
            Returns the root panel for this device.
            """
            return self.__panel_root

        def get_body(self):
            """
            Return the bare dictionary that describes this object, as returned by the
            Vivint API, and was used to construct this initially.
            """
            return self._body

        def update_body(self, body, panel_update=False):
            """
            Abstracts updating the body components of the device.
            """
            # Don't apply updates from the parent panel if the receive_updates
            if panel_update and not self.receive_updates:
                pass
            else:
                self._body = body

        def id(self):
            return self._body["_id"]

        @staticmethod
        def get_class(type_string):
            mapping = {
                VivintCloudSession.VivintDevice.DEVICE_TYPE_THERMOSTAT:
                VivintCloudSession.Thermostat,
                VivintCloudSession.VivintDevice.DEVICE_TYPE_LIGHT_MODULE:
                VivintCloudSession.MultiSwitch,
                VivintCloudSession.VivintDevice.DEVICE_TYPE_MOTION_SENSOR:
                VivintCloudSession.MotionSensor,
                VivintCloudSession.VivintDevice.DEVICE_TYPE_WIRELESS_SENSOR:
                VivintCloudSession.WirelessSensor,
                VivintCloudSession.VivintDevice.DEVICE_TYPE_DOOR_LOCK:
                VivintCloudSession.DoorLock,
                VivintCloudSession.VivintDevice.DEVICE_CAMERA:
                VivintCloudSession.Camera
            }
            return mapping.get(type_string, VivintCloudSession.UnknownDevice)

    class PanelRoot(VivintDevice):
        """
        Represents the top-level device that is a panel at a Vivint enabled location.
        """

        ARM_STATE_DISARMED = 0
        ARM_STATE_ARMED_STAY = 3
        ARM_STATE_ARMED_AWAY = 4
        __ARM_STATES = {
            ARM_STATE_DISARMED: "disarmed",
            ARM_STATE_ARMED_STAY: "armed_stay",
            ARM_STATE_ARMED_AWAY: "armed_away"
        }

        def __init__(self, session, panel_descriptor):
            super().__init__(panel_descriptor, self)
            self.__session = session
            self.__pool = _urllib_pool()
            self.__description = panel_descriptor
            self.__system = self.__get_system()
            self.__child_devices = []
            self.__active_partition = 1
            self.get_devices()

        def __get_system(self):
            resp = self.__pool.request(
                method="GET",
                url="%s/api/systems/%d" %
                (VIVINT_API_ENDPOINT, self.__description["panid"]),
                headers=self.get_authorization_headers())

            return json.loads(resp.data.decode())

        def get_active_partition(self):
            return self.__active_partition

        def get_authorization_headers(self):
            return self.__session.get_authorization_headers()

        def partition_count(self):
            return len(self.__system["system"]["par"])

        def set_active_partition(self, partition_id):
            if not (isinstance(partition_id, int) and partition_id <= 0
                    and partition_id > self.partition_count()):
                raise ValueError(
                    "Partition ID must be a positive integer less than or equal to the number of partitions",
                    self.partition_count())

            self.__active_partition = int(partition_id)
            self.update_devices()

        def update_devices(self, device_list=None):
            """
            Re-poll the systems endpoint, and update all devices, unless a list of
            devices is specified, then only update those in the list (as long as those
            specified are children of this root).
            """
            # Update the system body
            self.__system = self.__get_system()

            if device_list is None:
                device_list = self.__child_devices

            device_list = [
                d for d in self.__child_devices
                if d.receive_updates and d.get_panel_root() == self
            ]

            device_dict = dict([
                (d["_id"], d)
                for d in self.__system["system"]["par"][self.__active_partition
                                                        - 1]["d"]
            ])

            for device in device_list:
                device.update_body(device_dict[device.id()])

        def get_rtsp_credentials(self):
            resp = self.__pool.request(
                method="GET",
                url="%s/api/panel-login/%d" %
                (VIVINT_API_ENDPOINT, self.__description["panid"]),
                headers=self.get_authorization_headers())

            if resp.status != 200:
                raise Exception("Unable to fetch RTSP credentials", resp)

            resp_json = json.loads(resp.data.decode())
            username = resp_json["n"]
            password = resp_json["pswd"]

            return {"username": username, "password": password}

        def id(self):
            """
            Return the panel's ID
            """
            return self.__description["panid"]

        def get_armed_state(self):
            """
            Return the panel's arm state
            """
            return self.__ARM_STATES[self.__system["system"]["par"][
                self.__active_partition - 1]["proph"]["s"][0]["val"]]

        def set_armed_state(self, state):
            """
            Arming the panel involves PUTing against the /api/${PanelId}/${PartitionId}/armedstates endpoint
            """
            if isinstance(state,
                          int) and state not in self.__ARM_STATES.keys():
                raise ValueError(
                    "When using numeric arming state, value must be one of the provided constants"
                )
            elif isinstance(state,
                            str) and state not in self.__ARM_STATES.values():
                raise ValueError(
                    "When using string values for arming states, value must be one of allowed values",
                    list(self.__ARM_STATES.values()))

            resp = self.__pool.request(
                method="PUT",
                url="%s/api/%d/%d/armedstates" %
                (VIVINT_API_ENDPOINT, self.__description["panid"],
                 self.__active_partition),
                body=json.dumps({
                    "systemId":
                    self.__description["panid"],
                    "partitionId":
                    self.__active_partition,
                    "forceArm":
                    False,
                    "armState":
                    _flip_dict(self.__ARM_STATES)[state] if isinstance(
                        state, str) else state
                }).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })

            if resp.status != 200:
                raise Exception(
                    "Expected 200 response when setting armed state", resp)

            return

        def address(self):
            """
            Return the panel's address
            """
            return self.__description["add"]

        def climate_state(self):
            """
            Return the climate state of the panel
            """
            return self.__system["system"]["csce"]

        def get_devices(self, device_type_set=None, include_unknown=False):
            """
            Return a list of all devices where the class is, optionally, in the set
            of device types provided.
            """
            # ASSUMPTION
            # This assumes that there's only one item in the "par" key, which corresponds to
            # only one partition.
            devices = [
                VivintCloudSession.VivintDevice.get_class(device["t"])(device,
                                                                       self)
                for device in self.__system["system"]["par"][
                    self.__active_partition - 1]["d"]
                if device_type_set is None or device["t"] in device_type_set
            ]

            if not include_unknown:
                devices = [
                    d for d in devices
                    if type(d) != VivintCloudSession.UnknownDevice
                ]

            self.__child_devices += devices
            return devices

    class UnknownDevice(VivintDevice):
        """
        Represents a device that does not have a model associated with the type.
        """
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

    class Camera(VivintDevice):
        """
        Represents a basic camera able to expose a few pieces of information.

        This is primarily here to be able to expose the public and private RTSP endpoints.
        """
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def name(self):
            return self._body["n"]

        def private_rtsp_endpoint(self):
            return {
                "hd_video": self._body["ciu"][0],
                "sd_video": self._body["cius"][0],
                "audio_only": self._body["cea"][0]
            }

        def hd_video_resolution(self):
            return [int(dim) for dim in self._body["hdr"].split("x")]

        def public_rtsp_endpoint(self):
            return {
                "hd_video": self._body["cetu"][0],
                "sd_video": self._body["cetus"][0],
                "audio_only": self._body["cea"][0]
            }

        def rtsp_authentication_url(self, url):
            return "%s://%s:%s@%s" % (
                "rtsps" if ":443/" in url else "rtsp",
                self.get_panel_root().get_rtsp_credentials()["username"],
                self.get_panel_root().get_rtsp_credentials()["password"],
                url[7:])

    class MotionSensor(VivintDevice):
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def current_state(self):
            active = self._body["ts"]
            time = datetime.strptime(active, '%Y-%m-%dT%H:%M:%S.%f')
            name = self._body["n"]
            return {"activitytime": time, "name": name}

    class WirelessSensor(VivintDevice):
        # I'm just guessing at state=1 here...
        # Legit not feeling like walking all the way downstairs to open a door and test. 😅
        states = {0: "enabled-closed", 1: "enabled-open", 2: "bypassed"}

        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def current_state(self):
            # The current state is stored in the "b" parameter, and that's what's updated by a PUT
            # as well.
            active = self._body["ts"]
            time = datetime.strptime(active, '%Y-%m-%dT%H:%M:%S.%f')
            name = self._body["n"]
            state = self.states[self._body["b"]]
            return {
                "id": self.id(),
                "activitytime": time,
                "name": name,
                "state": state,
                "battery_level_percent": self._body.get("bl", None)
            }

        def __set(self, val):
            # To bypass the sensor, you set "b" to True, and to re-enable you set it to false
            # This manifests as either 0 or 2 in the value when it gets updated. It's weird.
            request_body = {"_id": self.id(), "b": val}

            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/%d/sensors/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                 self.get_panel_root().get_active_partition(), self.id()),
                body=json.dumps(request_body).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception("Unable to set multiswitch state", (
                    resp.status, "%s/api/%d/%d/switches/%d" %
                    (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                     self.get_panel_root().get_active_partition(), self.id())))
            else:
                self._body["b"] = 2 if val else 0

        def bypass(self):
            self.__set(True)

        def enable(self):
            self.__set(False)

    class MultiSwitch(VivintDevice):
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def set_switch(self, val):
            request_body = {"_id": self.id(), "val": val}

            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/%d/switches/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                 self.get_panel_root().get_active_partition(), self.id()),
                body=json.dumps(request_body).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception("Unable to set multiswitch state", (
                    resp.status, "%s/api/%d/%d/switches/%d" %
                    (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                     self.get_panel_root().get_active_partition(), self.id())))
            else:
                self._body["val"] = val

        def current_state(self):
            current = self._body["val"]
            name = self._body["n"]
            return {"val": current, "name": name}

    class DoorLock(VivintDevice):
        """
        Represents a door lock.
        """
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def current_state(self):
            return self._body["isl"]

    class Thermostat(VivintDevice):
        """
        Represents a Vivint thermostat generic device, supporting generic thermostat
        controls and functionality.
        """

        OPERATION_MODES = {0: "off", 1: "heat", 2: "cool", 3: "heat-cool"}
        FAN_MODES = {0: "off", 1: "always", 99: "15m", 100: "30m", 101: "60m"}
        CLIMATE_STATES = ["home", "away", "sleep", "vacation"]

        # Some general notes:
        #
        # The restore-estimates endpoint provides estimates of the time, in seconds, to
        # heat or cool to the listed temperature.
        #
        # An example URL for that is:
        #  Request URL: https://vivintsky.com/api/restore-estimates/${PanelId}/${ThermostatId}

        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def set_state(self, state):
            """
            Set the state of the panel location to one of the Smart Assistant states.

            This is a bit of a semantic oddity, as the change is made to the panel
            object, but it only ever makes sense in the context of a thermostat in the
            apps, except in the rules section.
            """
            if state not in self.CLIMATE_STATES:
                raise ValueError("State must be one of %s" %
                                 repr(self.CLIMATE_STATES))

            request_kwargs = dict(
                method="PUT",
                url="%s/api/systems/%d?includerules=false" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id()),
                body=json.dumps({
                    "csce": state
                }).encode(("utf-8")),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception("Setting state resulted in non-200 response",
                                resp)

        def set_operation_mode(self, mode):
            """
            Changes the mode of operation.
            """
            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/%d/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                 self.get_panel_root().get_active_partition(), self.id()),
                body=json.dumps({
                    "_id": self.id(),
                    "om": _flip_dict(self.OPERATION_MODES)[mode]
                }).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception(
                    "Setting operation mode resulted in non-200 response")

        def set_fan_mode(self, mode):
            """
            Changes the mode of fan operation.
            """
            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/%d/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                 self.get_panel_root().get_active_partition(), self.id()),
                body=json.dumps({
                    "_id": self.id(),
                    "fm": _flip_dict(self.FAN_MODES)[mode]
                }).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception(
                    "Setting fan mode resulted in non-200 response")

        def set_temperature(self,
                            setpoint=None,
                            cool_setpoint=None,
                            heat_setpoint=None):
            """
            Set the setpoint temperature for cooling and heating.
            """
            mode = self._body["om"]
            request_body = {
                "_id": self.id(),
                "currentAutoMode": 2  # NOTE No clue what this is. :D
            }

            # By deafult, if there are explicit values, set them
            if heat_setpoint is not None:
                request_body["hsp"] = heat_setpoint
            if cool_setpoint is not None:
                request_body["csp"] = cool_setpoint

            # Heat not explicitly set, heating mode, setpoint set
            if mode == 1 and "hsp" not in request_body and setpoint is not None:
                request_body["hsp"] = setpoint
            # Cool not explicitly set, cooling mode, setpoint set
            elif mode == 2 and "csp" not in request_body and setpoint is not None:
                request_body["csp"] = setpoint
            # Heat/Cool
            elif mode == 3:
                # Heat explicitly set, cold not explicitly set, setpoint set
                if heat_setpoint is not None and "csp" not in request_body and \
                    setpoint is not None:
                    request_body["csp"] = setpoint
                # Heat explicitly set, cold not explicitly set, setpoint set
                if cool_setpoint is not None and "hsp" not in request_body and \
                    setpoint is not None:
                    request_body["hsp"] = setpoint

            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/%d/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(),
                 self.get_panel_root().get_active_partition(), self.id()),
                body=json.dumps(request_body).encode("utf-8"),
                headers={
                    **{
                        "Content-Type": "application/json;charset=utf-8"
                    },
                    **self.get_authorization_headers()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception(
                    "Setting temperature resulted in non-200 response")

            # NOTE
            # This response may contain some suggestions, and a reasonable body.
            # Here's an example;
            #
            # {
            #   "awareness_message": {
            #     "pans": [
            #       {
            #         "l": "Yes",
            #         "val": "yes"
            #       },
            #       {
            #         "l": "No",
            #         "val": "no"
            #       }
            #     ],
            #     "stat": null,
            #     "igt": "2018-05-27 17:16:16.739727",
            #     "uid": "edf467e797842913f97b11bb",
            #     "dest": "thermostats",
            #     "ts": "2018-05-27 17:11:16.776699",
            #     "plctx": {
            #       "ctxid": "edf467e797842913f97b11bb",
            #       "ctxt": 10,
            #       "mid": "585c79932593243672c5d8a8",
            #       "ts": "2018-05-27 17:11:16.778789+00:00",
            #       "ctxd": {
            #         "currentAutoMode": 2,
            #         "_id": 33,
            #         "csp": 23.5
            #       }
            #     },
            #     "q": "Would you like to switch to Away mode?",
            #     "did": 33,
            #     "t": null,
            #     "in": true,
            #     "amtid": 4,
            #     "_id": "585c79932593243672c5d8a8",
            #     "panid": 42138025481253
            #   }
            # }

        def current_state(self):
            """
            Poll the thermostat endpoint to retrieve the temperature setpoints and
            other information.
            """
            mode_id = self._body["om"]
            current = self._body["val"]
            hsp = self._body["hsp"]
            csp = self._body["csp"]

            if mode_id == 0:
                setpoint = None
            elif mode_id == 1:
                setpoint = hsp
            elif mode_id == 2:
                setpoint = csp
            elif mode_id == 3:
                # For the heat/cool situation, the setpoint is whichever one is active,
                # and if neither are active, then it is whichever we are closer to (if
                # the current temperature is between the two setpoints).
                if current <= hsp:
                    setpoint = hsp
                elif current >= csp:
                    setpoint = csp
                else:
                    cdelta = abs(csp - current)
                    hdelta = abs(hsp - current)
                    if cdelta == hdelta:
                        setpoint = float('nan')
                    else:
                        setpoint = min([csp, cdelta], [hsp, hdelta],
                                       key=lambda i: i[1])[0]

            return {
                "climate_state": self.get_panel_root().climate_state(),
                "fan_mode": self.FAN_MODES[self._body["fm"]],
                "humidity": self._body["hmdt"],
                "temperature": current,
                "mode": self.OPERATION_MODES[mode_id],
                "active_setpoint": setpoint,
                "cooling_setpoint": csp,
                "heating_setpoint": hsp
            }

    def __init__(self,
                 username=None,
                 password=None,
                 state=None,
                 nonce=None,
                 pf_token=None):
        self.__pool = _urllib_pool()

        # Prefer username/password authentication if both are provided.
        if username is not None and password is not None:
            self.__login(username, password)
            # TODO Obfuscate the username and password here
            self.__username = username
            self.__password = password
        elif state is not None and nonce is not None and pf_token is not None:
            self.__username = None
            self.__password = None

            self.__auth_elements = {"headers": None}
            self.__refresh_token()
        else:
            raise ValueError(
                "Must supply either a username/password pair or a authorization cookie"
            )

        self.__auth_user_data = self.__authuser()

        self.__run_threads = True
        self.__refresh_thread = self.__make_refresh_thread()

    def __refresh_handler(self):
        """
        Keep track of a cloud session's id tokens, and whenever one is nearing expiry, refresh it.
        """
        # TODO Make this exception-safe
        while self.__run_threads:
            if self.__parse_credential_expiry() - time.time() < 60:
                self.__refresh_token()
            time.sleep(60)

    def __make_refresh_thread(self):
        """
        Build a refresh thread that runs in the background and refreshes the token before it expires.
        """
        thread = threading.Thread(target=self.__refresh_handler)
        thread.daemon = True
        thread.start()
        return thread

    def __parse_credential_expiry(self):
        return time.time() + 120

    def __refresh_token(self):
        self.__auth_elements = self.__auth_elements
        authuser_resp = self.__pool.request(
            method="GET",
            url="%s/api/authuser" % VIVINT_API_ENDPOINT,
            headers=self.get_authorization_headers())

        ### TODO Error handling here in case the set-cookie header is missing.
        self.__auth_elements["headers"] = {
            "Cookie": authuser_resp.headers["Set-Cookie"]
        }

    def __login(self, username, password):
        """
        Login into the Vivint Sky platform with the given username and password

        Returns an object that includes the appropriate OpenID components.
        """

        login_resp = self.__pool.request(method="POST",
                                         url="%s/api/login" %
                                         (VIVINT_API_ENDPOINT),
                                         body=json.dumps({
                                             "username": username,
                                             "password": password
                                         }).encode("utf-8"))

        if login_resp.headers.get("Set-Cookie", None) is None:
            raise Exception("Unable to get Set-Cookie header from response")

        self.__auth_elements = dict(
            headers={"Cookie": login_resp.headers["Set-Cookie"]})

    def get_authorization_headers(self):
        return self.__auth_elements["headers"]

    def __authuser(self):
        """
        Poll the Vivint authuser API endpoint resource to gather user-related data including
        enumeration of the systems that user has access to.
        """
        resp = self.__pool.request(method="GET",
                                   url="%s/api/authuser" % VIVINT_API_ENDPOINT,
                                   headers=self.get_authorization_headers())

        return json.loads(resp.data.decode())

    def get_panels(self):
        """
        Return object for each panel that this logged in user has access to
        """
        return [
            self.PanelRoot(self, panel)
            for panel in self.__auth_user_data["u"]["system"]
        ]
