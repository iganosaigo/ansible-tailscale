from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
import time
from enum import Enum

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.urls import fetch_url

DEFAULT_ROUTES = {"0.0.0.0/0", "::/0"}


class State(str, Enum):
    UNREGISTERED = "NeedsLogin"
    REGISTERED = "Running"

    def __str__(self):
        return f"{self.value}"

    @classmethod
    def values(cls):
        return list(map(lambda c: c.value, cls))


def convert_to_seconds(time_str):
    match = re.match(r"(\d+)([shd])", time_str)
    if not match:
        raise ValueError(f"Invalid format: {time_str}")

    value, date_format = match.groups()
    value = int(value)

    if date_format == "s":
        return value
    elif date_format == "h":
        return value * 3600
    elif date_format == "d":
        return value * 86400
    else:
        raise ValueError(f"Unknown date format: {time_str}")


def make_result_msg(actions):
    msg = {}
    if actions.get("TS"):
        msg["TS"] = actions["TS"]
    if actions.get("HS"):
        msg["HS"] = actions["HS"]

    if not msg.get("TS") and not msg.get("HS"):
        msg = "No changes."

    return msg


class Tailscale(object):
    def __init__(self, module: AnsibleModule, results):
        self.module = module
        self.results = results
        self.server_url = self.module.params["server_url"]
        self.api_token = self.module.params["api_token"]
        self.timeout = self.module.params["timeout"]
        self.sync_check = self.module.params["sync_check"]
        self.socket = self.module.params["socket"]
        self.state_file = self.module.params["state_file"]
        self.bin = self.get_binary()
        self.check_service()
        self.base_prepare()

    def base_prepare(self):
        status = self.ts_get_status()
        self.init_status = status
        self.init_state = status["BackendState"]
        self.node_id = status["Self"]["ID"]

    def ts_ensure_sync(self, func_list):

        for sec in range(int(self.sync_check) + 1):
            interval = sec**sec
            time.sleep(interval)

            funcs_to_remove = []
            if not func_list:
                return

            # Renew state
            new_state = self.ts_get_status()
            for func in func_list:
                if func(new_state):
                    funcs_to_remove.append(func)

            for func in funcs_to_remove:
                func_list.remove(func)

        self.results["warnings"] = "Mismtach status between HS/TS"

    def _ts_cmd(self, subcommand):
        cmd = [
            self.bin,
            "--socket",
            self.socket,
        ]
        if isinstance(subcommand, list):
            cmd.extend(subcommand)
        elif isinstance(subcommand, str):
            cmd.append(subcommand)

        return cmd

    def ts_get_status(self):
        cmd = self._ts_cmd(
            [
                "status",
                "--self",
                "--json",
            ]
        )

        # When --json flag present then exit code 0 even when not logged in.
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Can't get tailscaled status",
                stdout=stdout,
                stderr=stderr,
            )
        return self.module.from_json(stdout)

    def get_binary(self):
        return self.module.get_bin_path("tailscale", required=True)

    def check_service(self):
        cmd = ["systemctl", "is-active", "tailscaled"]
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            if re.search(r"inactive", stdout):
                self.module.fail_json(msg="Tailscaled(systemd) not running.")
            else:
                self.module.fail_json(
                    "Can't get tailscaled status",
                    stdout=stdout,
                    stderr=stderr,
                )
        if not os.path.exists(self.state_file):
            self.module.fail_json(
                msg=f"Tailscaled state file({self.state_file}) not found."
            )

    def fetch_api(self, api_call, method="GET", payload=None):
        data = None
        if payload:
            data = self.module.jsonify(payload)

        headers = {
            "Authorization": "Bearer " + self.api_token,
            "Content-Type": "application/json",
        }

        resp, info = fetch_url(
            self.module,
            self.server_url + api_call,
            headers=headers,
            data=data,
            method=method,
            timeout=convert_to_seconds(self.timeout),
        )
        if info["status"] not in [200]:
            self.module.fail_json(
                msg=f"Failed API call {api_call}; got unexpected HTTP code {info['status']}: {info.get('msg')}"
            )

        error_msg = ""
        result = None
        try:
            content = resp.read()
        except AttributeError:
            if info["body"]:
                content = info["body"]
            else:
                error_msg += "The API response was empty"

        if content:
            try:
                result = self.module.from_json(
                    to_text(content, errors="surrogate_or_strict")
                )
            except getattr(json, "JSONDecodeError", ValueError) as e:
                err = to_native(e)
                error_msg += (
                    f"; Failed to parse API response with error {err}: {content}",
                )

        if result is None:
            self.module.fail_json(msg=error_msg)

        return result
