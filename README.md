# Vivint.py: Reverse Engineered Python Access to Vivint's Cloud API

This is a simple Python file that can be imported into projects, and provides access to some of Vivint's cloud API through a Python object model.

Feature support right now is minimal and limited to what I personally need, but PRs are welcome, as well as issues that request new features.

In terms of overall code quality, this is very proof-of-concept.

## Features currently in place

### Authentication

Authentication is handled in one of two ways:

- By taking in a username and password, and obtaining an OpenID bearer token
- By taking an existing valid oauth state and oidc nonce pair, and requesting a new bearer token

As long as the process is running and state is maintained (think as a systemd process, script, long-lived container, or lambda function that doesn't 'time out'), the bearer token is automatically refreshed regularly, or when it expires (if regular refreshes were not successful).

### Thermostats

Thermostat functionality was the main driver for this project, as currently you cannot have both the Smart Assistant control the thermostat, as well as a schedule for temperature setpoints. Rules can control the fan (on/off/toggle) based on time of day and duration, but not temperature.

- The ability to set the mode of operation for heating/cooling as well as the fan mode of operation.
- The ability to set the setpoint for the thermostat. This includes setting the cooling and heating setpoints separately.

Note that temperature units are in whatever your account/panel are set to.

### Not yet implemented devices

Any unimplemented device types are optionally just exposed as base JSON documents for you to poke at. In general you can PUT to the API endpoint and set any of the values in the device body to set it.

### PubNub Updates (NOT IMPLEMENTED)

The actual Vivint web interface and probably the mobile applications use pubnub to receive updates on the status of the system. They use long HTTP polling (determined by the remote endpoint, so ensuring the client timeout is long) between a few seconds and several minutes, and receive a complicated body back.

Because this isn't updated, to get updates on the state of system elements, you need to run the panel object's `update_devices()` function which will update all devices attached or generated from that panel. Because of the likely distributed nature of the server side, it can take a few seconds before either the systems API endpoint, or the PubNub notification, reflects any state changes you've made.

An example PubNub message is included for information, resulting from changing the thermostat state from `sleep` to `home`.

```json
GET @ "https://ps18.pubnub.com/subscribe/sub-c-638b7dcf-84f3-442b-8eca-f3efa4bd057c/PlatformChannel"

[
  [ // If the 
    {
      "_id": 42138025481253,
      "da": {
        "csce": "home",
        "plctx": {
          "ctxd": null,
          "ctxid": "edf467e797842913f97b11bb",
          "ctxt": 10,
          "mid": "585c79932593243672c5d8a8",
          "ts": "2018-05-27T22:23:05.049000"
        },
        "proph.csce": [ // Note the .notation to index into a document in the object it cares about
          {
              "val": "sleep"
          },
          {
              "val": "home"
          }
        ]
      },
      "dseq": 4795401,
      "op": "u",
      "panid": 42138025481253,
      "t": "account_system"
    }
  ],
  "15274606422065826" // Timestamp in 100ns units
]
```

## General Notes

It appears that timestamps are in Unix epoch time, but some are in the units of us, or 100ns, ns, or other funky units. Just use caution.
