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

VIVINT_AUTH_ENDPOINT = "https://id.vivint.com"
VIVINT_API_ENDPOINT = "https://www.vivintsky.com"

BASE62_TABLE = [chr(ord('a') + i) for i in range(26)] + [
    chr(ord('A') + i) for i in range(26)
] + [chr(ord('0') + i) for i in range(10)]


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
    Implements the surrounding components for authenticating, retrieving a bearer token,
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

        ARM_STATES = {0: "disarmed", 3: "armed_stay", 4: "armed_away"}

        def __init__(self, session, panel_descriptor):
            super().__init__(panel_descriptor, self)
            self.__session = session
            self.__pool = _urllib_pool()
            self.__description = panel_descriptor
            self.__system = self.__get_system()
            self.__child_devices = []

        def __get_system(self):
            resp = self.__pool.request(
                method="GET",
                url="%s/api/systems/%d" %
                (VIVINT_API_ENDPOINT, self.__description["panid"]),
                headers={
                    "Authorization": "Bearer %s" % self.get_bearer_token()
                })

            return json.loads(resp.data.decode())

        def get_bearer_token(self):
            return self.__session.get_bearer_token()

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
                (d["_id"], d) for d in self.__system["system"]["par"][0]["d"]
            ])

            for device in device_list:
                device.update_body(device_dict[device.id()])

        def get_rtsp_credentials(self):
            resp = self.__pool.request(
                method="GET",
                url="%s/api/panel-login/%d" %
                (VIVINT_API_ENDPOINT, self.__description["panid"]),
                headers={
                    "Authorization": "Bearer %s" % self.get_bearer_token()
                })

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
            return self.ARM_STATES[self.__description["par"][0]["s"]]

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
            # This assumes that there's only one item in the "par" key
            devices = [
                VivintCloudSession.VivintDevice.get_class(device["t"])(device,
                                                                       self)
                for device in self.__system["system"]["par"][0]["d"]
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

    class MultiSwitch(VivintDevice):
        def __init__(self, body, panel_root):
            super().__init__(body, panel_root)

        def set_switch(self, val):
            request_body = {"_id": self.id(), "val": val}

            request_kwargs = dict(
                method="PUT",
                url="%s/api/%d/1/switches/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(), self.id()),
                body=json.dumps(request_body).encode("utf-8"),
                headers={
                    "Content-Type":
                    "application/json;charset=utf-8",
                    "Authorization":
                    "Bearer %s" % self.get_panel_root().get_bearer_token()
                })
            resp = self._pool.request(**request_kwargs)

            if resp.status != 200:
                raise Exception("Unable to set multiswitch state",
                                (resp.status, "%s/api/%d/1/switches/%d" %
                                 (VIVINT_API_ENDPOINT,
                                  self.get_panel_root().id(), self.id())))
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
                    "Content-Type":
                    "application/json;charset=utf-8",
                    "Authorization":
                    "Bearer %s" % self.get_panel_root().get_bearer_token()
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
                url="%s/api/%d/1/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(), self.id()),
                body=json.dumps({
                    "_id": self.id(),
                    "om": _flip_dict(self.OPERATION_MODES)[mode]
                }).encode("utf-8"),
                headers={
                    "Content-Type":
                    "application/json;charset=utf-8",
                    "Authorization":
                    "Bearer %s" % self.get_panel_root().get_bearer_token()
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
                url="%s/api/%d/1/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(), self.id()),
                body=json.dumps({
                    "_id": self.id(),
                    "fm": _flip_dict(self.FAN_MODES)[mode]
                }).encode("utf-8"),
                headers={
                    "Content-Type":
                    "application/json;charset=utf-8",
                    "Authorization":
                    "Bearer %s" % self.get_panel_root().get_bearer_token()
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
                url="%s/api/%d/1/thermostats/%d" %
                (VIVINT_API_ENDPOINT, self.get_panel_root().id(), self.id()),
                body=json.dumps(request_body).encode("utf-8"),
                headers={
                    "Content-Type":
                    "application/json;charset=utf-8",
                    "Authorization":
                    "Bearer %s" % self.get_panel_root().get_bearer_token()
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
        self.__openid_config = self.__get_openid_config()

        # Prefer username/password authentication if both are provided.
        if username is not None and password is not None:
            self.__auth_elements = self.__login(username, password)
            # TODO Obfuscate the username and password here
            self.__username = username
            self.__password = password
        elif state is not None and nonce is not None and pf_token is not None:
            self.__username = None
            self.__password = None

            self.__auth_elements = {
                "nonce": [nonce],
                "state": [state],
                "pf_token": {
                    # TODO This isn't right
                    # It's probably a fixed number of urlsafe b64 encoded bytes.
                    # "short": [pf_token[:24]],
                    "long": [pf_token]
                },
                # "client_id": self.__get_client_id(),
                # # This is unnecessary, and only used for password logins.
                # "api_id": None,
                "id_token": []
            }
            self.__refresh_token()
        else:
            raise ValueError(
                "Must supply either a username/password pair or a nonce/state/PF triple"
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
            if self.__parse_id_token()["payload"]["exp"] - time.time() < 60:
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

    def get_bearer_token(self):
        """
        Return a token suitable for inclusion into an Authorization header as
        a bearer token, refreshing the existing one if necessary.
        """
        id_token = self.__auth_elements["id_token"][-1]
        if time.time() > self.__parse_id_token(id_token)["payload"]["exp"]:
            self.__refresh_token()

        return id_token

    def __refresh_token(self):
        """
        Ping the token-delegate endpoint for a refresh token, geting the token-delegate
        endpoint from the OID configuration.
        """
        nonce = "".join([BASE62_TABLE[i % 62] for i in os.urandom(32)])
        state = "".join([BASE62_TABLE[i % 62] for i in os.urandom(32)])

        # When requesting a new token from the delegate, the following must be true:
        # - The original state and nonce must be in the Cookies header
        # - The new state and nonce must be in the query string
        #  > These don't appear to ever be used.
        # - The PF token supplied in the Cookies header must match that provided back
        #   in the Set-Cookie header from the original response to the auth ping
        #  > That is, not the "short" one, the "long" one.
        #
        # The response satisfies the following:
        # - The body is a JSON document with two keys: id_token, state
        # - The state value is as usual, "replay:%s"
        # - The new nonce to use is in the ID token returned.
        #  > Neither the new state or nonce need to be used anywhere.

        resp = self.__pool.request(
            method="GET",
            url=self.__openid_config["token_delegate_endpoint"],
            fields={
                "nonce": nonce,
                "state": "replay:%s" % state,
                "response_type": "id_token",
                "client_id": self.__get_client_id(),
                "redirect_uri": "https://www.vivintsky.com/app/",
                "scope": "openid email",
                "pfidpadapterid": "vivintidp1"
            },
            headers={
                "Cookie":
                "oidc_nonce=%s; oauth_state=%s; PF=%s;" %
                (self.__auth_elements["nonce"][-1],
                 self.__auth_elements["state"][-1],
                 self.__auth_elements["pf_token"]["long"][-1])
            })

        if resp.status == 200:
            resp_body = json.loads(resp.data.decode())
            token_parts = self.__parse_id_token(resp_body["id_token"])
            self.__auth_elements["id_token"].append(resp_body["id_token"])

            # It is the last valid value that we care about, because the new ones
            # generated aren't used for anything... oddly enough. So append the one
            # we used to get the new token to the end, so we keep using it.
            self.__auth_elements["state"] += [
                unquote(resp_body["state"]).split(":", 1)[1],
                self.__auth_elements["state"][-2]
            ]
            self.__auth_elements["nonce"] += [
                token_parts["payload"]["nonce"],
                self.__auth_elements["nonce"][-2]
            ]
        if resp.status != 200:
            # Attempt to re-login if there is a username and password
            if self.__username is not None and self.__password is not None:
                new_auth_elements = self.__login(self.__username,
                                                 self.__password)
                self.__auth_elements["id_token"] += new_auth_elements[
                    "id_token"]
                self.__auth_elements["pf_token"]["long"] += new_auth_elements[
                    "pf_token"]["long"]
                self.__auth_elements["state"] += new_auth_elements["state"]
                self.__auth_elements["nonce"] += new_auth_elements["nonce"]
            else:
                raise Exception(
                    "Unable to refresh token with non-200 error, and no username/password available"
                )

    def __parse_id_token(self, id_token=None):
        """
        Parse out the components of the ID token.
        """
        if id_token is None:
            id_token = self.get_bearer_token()
        header_raw, payload_raw, data = [
            base64.urlsafe_b64decode(p + "=" * ((4 - (len(p) % 4)) % 4))
            for p in id_token.split(".")
        ]

        return {
            "header": json.loads(header_raw.decode()),
            "payload": json.loads(payload_raw.decode()),
            "data": base64.b64encode(data).decode()
        }

    def __get_openid_config(self):
        """
        Fetch the OpenID Connect configuration data from the Vivint webservice
        """
        resp = self.__pool.request(
            "GET", "%s/api/openid-configuration" % VIVINT_API_ENDPOINT)
        return json.loads(resp.data.decode()) if resp.status == 200 else None

    def __get_client_id(self):
        # When we ask Vivint's authuser API endpoint without credentials or a token
        # it tells us to authenticate, and kindly gives us the client ID in the
        # process.
        resp = self.__pool.request(method="GET",
                                   url="%s/api/authuser" % VIVINT_API_ENDPOINT,
                                   headers={"User-Agent": "vivint.py"})

        if resp.status != 401:
            raise Exception(
                "Expected UNAUTHORIZED when fetching clientid, got otherwise",
                resp)

        response_headers = {
            a: b[1:-1]
            for a, b in [
                p.split("=")
                for p in resp.headers["WWW-Authenticate"].split(",")
            ]
        }

        client_id = response_headers["client_id"]

        return client_id

    def __login(self, username, password):
        """
        Login into the Vivint Sky platform with the given username and password

        Returns an object that includes the appropriate OpenID components.
        """
        # As per the app.js, this is just random garbage
        nonce = "".join([BASE62_TABLE[i % 62] for i in os.urandom(32)])
        state = "".join([BASE62_TABLE[i % 62] for i in os.urandom(32)])

        client_id = self.__get_client_id()

        login_form_resp = self.__pool.request(
            method="GET",
            url="%s/as/authorization.oauth2?%s" %
            (VIVINT_AUTH_ENDPOINT,
             urlencode(
                 {
                     "nonce": nonce,
                     "state": "replay:%s" % state,
                     "response_type": "id_token",
                     "client_id": client_id,
                     "redirect_uri": "%s/app/" % VIVINT_AUTH_ENDPOINT,
                     "scope": "openid email",
                     "pfidpadapterid": "vivintidp1"
                 },
                 quote_via=quote)),
            headers={
                "Referer": "%s/app/" % VIVINT_AUTH_ENDPOINT,
                "User-Agent": "pyvint"
            })

        if login_form_resp.headers.get("Set-Cookie", None) is None:
            raise Exception("Unable to get Set-Cookie header from response")

        # The cookies returned by urllib3 when multiple Set-Cookie headers do NOT
        # work with the SimpleCookie class, without some preprocessing.
        #
        # So clean this up by fixing a couple of the weird spots.
        cookie_split = re.split(r', *([^;]*=)',
                                login_form_resp.headers["Set-Cookie"])
        login_form_return_cookies = SimpleCookie(
            "".join([cookie_split[0] + ";"] + [
                cookie_split[i] + cookie_split[i + 1] + ";"
                for i in range(1, len(cookie_split), 2)
            ]))

        pf_token = login_form_return_cookies["PF"].value

        if pf_token is None:
            raise Exception("Unable to get PF token from Set-Cookie header")

        match = re.search(r'"/as/([^/]*)/resume/as/authorization.ping"',
                          login_form_resp.data.decode())

        if match is None:
            raise Exception("Unable to find api ID from login form HTML")

        api_id = match.group(1)

        login_url = "%s/as/%s/resume/as/authorization.ping" % (
            VIVINT_AUTH_ENDPOINT, api_id)

        # NOTABLE NOTE
        #
        # There's a weird thing with the Vivint API here on this call, where if there
        # are nonce and state values in the cookies and the query string, the cookies
        # take precedence. This is odd since there's a weird behaviour with their web
        # JavaScript code that will provide both, with the code inheriting the cookies
        # from somewhere as well as generating its own values for the query string.
        #
        # The webapp will use the generated values (supplied in the query string) for
        # further API calls, despite being unnecessary given the bearer token is
        # provided. But thankfully the correct values, being kept in the tokens, are
        # still used for all token refreshes to the delegate endpoint.

        login_resp = self.__pool.request(
            method="POST",
            url=login_url,
            headers={
                "Referrer":
                "%s/app/" % VIVINT_AUTH_ENDPOINT,
                "User-Agent":
                "pyvint",
                "Accept":
                "*/*",
                "Accept-Encoding":
                "gzip, deflate",
                "Content-Type":
                "application/x-www-form-urlencoded",
                "Cookie":
                "oauth_state=%s; oidc_nonce=%s; PF=%s;" %
                (state, nonce, pf_token)
            },
            body=urlencode({
                "pf.username": username,
                "pf.pass": password
            }),
            redirect=False)

        cookie_split = re.split(r', *([^;]*=)',
                                login_resp.headers["Set-Cookie"])
        login_resp_return_cookies = SimpleCookie(
            "".join([cookie_split[0] + ";"] + [
                cookie_split[i] + cookie_split[i + 1] + ";"
                for i in range(1, len(cookie_split), 2)
            ]))

        pf_token_long = login_resp_return_cookies["PF"].value

        if pf_token_long is None:
            raise Exception("Unable to get PF token from Set-Cookie header")

        location_hdr = login_resp.headers.get("Location", None)

        if location_hdr is None:
            raise Exception(
                "Unable to retrieve Location header from login response")

        location_params = dict([
            kv.split("=", 1) for kv in re.search(
                r'/#(.*)$', location_hdr).group(0)[2:].split("&")
        ])

        if "id_token" not in location_params:
            raise Exception(
                "id_token not provided in Location header of login attempt")

        if "state" not in location_params:
            raise Exception(
                "New state value not present in Location header of login attempt"
            )

        id_token_parts = self.__parse_id_token(location_params["id_token"])

        return {
            "nonce": [nonce, id_token_parts["payload"]["nonce"]],
            "state":
            [state, unquote(location_params["state"]).split(":", 1)[1]],
            # "client_id": client_id,
            "pf_token": {
                # "short": [pf_token],
                "long": [pf_token_long]
            },
            # "api_id": api_id,
            "id_token": [location_params["id_token"]]
        }

    def __authuser(self):
        """
        Poll the Vivint authuser API endpoint resource to gather user-related data including
        enumeration of the systems that user has access to.
        """
        resp = self.__pool.request(
            method="GET",
            url="%s/api/authuser" % VIVINT_API_ENDPOINT,
            headers={"Authorization": "Bearer %s" % self.get_bearer_token()})

        return json.loads(resp.data.decode())

    def get_panels(self):
        """
        Return object for each panel that this logged in user has access to
        """
        return [
            self.PanelRoot(self, panel)
            for panel in self.__auth_user_data["u"]["system"]
        ]
