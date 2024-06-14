#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: tailscale_login
author:
  - Alexander Grigoriev (@iganosaigo)
short_description: Register the Tailscale in Headscale.
description:
  - Register, unregister and re-register the Tailscale instance.
  - Module consider TAGS and Hostname changes.

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none

options:
  server_url:
    description:
      - The Headscale URL.
    type: str
    aliases:
      - headscale_url
      - headscale_server
      - tailscale_server
      - server
    required: true
  auth_token:
    description:
      - The Headscale Auth Token for node registration.
    type: str
    required: true
  api_token:
    description:
      - The Headscale API Token. Required for configuration on HS side.
    type: str
    required: true
  state:
    description:
      - Control the current state of the Tailscale registration state.
    type: str
    default: "present"
    choices: ["present", "absent"]
    aliases:
      - registration
  nodename:
    description:
      - Nodename used in tailnet MagicDNS.
      - When changing nodename renaming at Headscale also occures.
    type: str
    default: current node hostname
  reregister:
    description:
      - Force re-register TS node.
    type: str
    default: false
  advertise_tags:
    description:
      - Advertise tags from current node.
      - If new specified advertised tags not equal current tags of registered node then re-registration accures automatically.
      - Be aware of ForcedTags since they are not considered for now.
    type: list
    elements: str
    default: []
  accept_routes:
    description:
      - Accept advertised routes from other nodes.
      - Currently there are no changes detection method.
      - So you could also place this opt to 'register_opts'.
    type: bool
    default: false
  accept_dns:
    description:
      - Accept advertised dns configuration from HS.
      - Currently there are no changes detection method.
      - So you could also place this opt to 'register_opts'.
    type: bool
    default: true
  hs_clean:
    description:
      - When state is 'absent' and node is logged-in you can choose whether to just simple logout or in addition also delete node from HS.
      - Note that deletion occures via API and any information about node and it's attributes also removed from Control Plane.
    type: bool
    default: true
  register_opts:
    description:
      - Additional options for Tailscale login command.
      - For now module doesn't track these options changes.
    type: list
    elements: str
    default: []
  timeout:
    description:
      - Optional timout used in tailscale client.
    type: str
    default: "20s"
  socket:
    description:
      - Tailscaled socket path.
    type: path
    default: "/var/run/tailscale/tailscaled.sock"
  state_file:
    description:
      - Tailscaled state file path.
    type: path
    default: "/var/lib/tailscale/tailscaled.state"
"""

RETURN = """
status:
  description:
    - Current Tailscaled BackendState registration status.
  returned: always
  type: str
msg:
  description: Actions that were taken to login.
  returned: always
  type: str or list
"""

import platform
from collections import Counter

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iganosaigo.tailscale.plugins.module_utils.util import (
    State,
    Tailscale,
    make_result_msg,
)


class TailscaleLogin(Tailscale):
    def __init__(self, module: AnsibleModule, results: dict):
        self.module = module
        self.results = results
        self.auth_token = self.module.params["auth_token"]
        self.state = self.module.params["state"]
        self.reregister = self.module.params["reregister"]
        self.advertise_tags = sorted(self.module.params["advertise_tags"])
        self.nodename = self.module.params["nodename"]
        self.accept_routes = self.module.params["accept_routes"]
        self.accept_dns = self.module.params["accept_dns"]
        self.register_opts = self.module.params["register_opts"]
        self.hs_clean = self.module.params["hs_clean"]
        super().__init__(self.module, results)

        self._prepare()

    def _prepare(self):
        self.init_nodename = self.init_status["Self"]["HostName"]

        initial_tags = self.init_status["Self"].get("Tags", [])
        if initial_tags:
            self.init_tags = [tag.split(":")[1] for tag in initial_tags]
        else:
            self.init_tags = initial_tags
        self.init_tags = sorted(self.init_tags)

    def _validate_state(self, state):
        if not state in State.values():
            if self.state == "absent":
                desired_state = State.UNREGISTERED
            else:
                desired_state = State.REGISTERED

            self.module.fail_json(
                msg=f"Unknowsn state. Current: {state}. Desired: {desired_state}"
            )

    def rename_node(self):
        self.ts_set_hostname()
        self.hs_rename_node(self.nodename)

    def hs_rename_node(self, nodename):
        self.fetch_api(
            f"/api/v1/machine/{self.node_id}/rename/{nodename}",
            "POST",
        )

    def hs_delete_node(self):
        self.fetch_api(
            f"/api/v1/machine/{self.node_id}",
            "DELETE",
        )

    def ts_set_hostname(self):
        cmd = self._ts_cmd(["set", "--hostname", self.nodename])
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Set new nodename failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def ts_login(self):
        cmd = self._ts_cmd(
            [
                "login",
                "--login-server",
                self.server_url,
                "--auth-key",
                self.auth_token,
                "--timeout",
                self.timeout,
            ]
        )
        if self.nodename:
            cmd.extend(["--hostname", self.nodename])
        if self.accept_dns:
            cmd.append("--accept-dns=true")
        if self.accept_routes:
            cmd.append("--accept-routes=true")
        if self.register_opts:
            cmd.extend(self.register_opts)
        if self.advertise_tags:
            tags_str = ",".join(f"tag:{tag}" for tag in self.advertise_tags)
            cmd.extend(["--advertise-tags", tags_str])

        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Login failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def is_nodename_changed(self):
        if self.init_nodename == self.nodename:
            return False
        return True

    def is_tag_changed(self):
        if self.init_tags == self.advertise_tags:
            return False
        return True

    def ts_logout(self):
        cmd = self._ts_cmd("logout")
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Logout failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def ts_is_sync(self, status):
        ts_nodename = status["Self"]["HostName"]
        ts_tags = status["Self"].get("Tags", [])
        adv_tags = [f"tag:{tag}" for tag in self.advertise_tags]

        if self.nodename != ts_nodename:
            return False

        if self.advertise_tags:
            if Counter(adv_tags) != Counter(ts_tags):
                return False
        # Ensure that if we pass no TAGs there no TAGs in status
        elif ts_tags:
            return False

        return True

    def present(self):
        # TS result msg part for TAGs
        if self.advertise_tags:
            msg_tags = ",".join(self.advertise_tags)
            msg_tags = f"with TAGs {msg_tags}"
        else:
            msg_tags = "without TAGs"

        if self.init_state == State.UNREGISTERED:
            self.ts_login()
            self.results["changed"] = True
            self.results["actions"]["TS"].append(f"register {msg_tags}")

        elif self.init_state == State.REGISTERED:
            reregister = self.reregister
            tag_changed = self.is_tag_changed()
            if reregister or tag_changed:
                self.ts_login()
                self.results["changed"] = True

                if reregister:
                    self.results["actions"]["TS"].append("force re-register")
                elif tag_changed:
                    self.results["actions"]["TS"].append(f"re-register {msg_tags}")

            elif self.is_nodename_changed():
                self.rename_node()
                self.results["changed"] = True
                self.results["actions"]["TS"].append(f"set hostname to {self.nodename}")
                self.results["actions"]["HS"].append(
                    f"rename from {self.init_nodename} to {self.nodename}"
                )

            else:
                # Already registered
                pass
        else:
            self.module.fail_json(msg=f"Unknow state {self.init_state}")

    def absent(self):
        if self.init_state == State.REGISTERED:
            self.ts_logout()
            self.results["changed"] = True
            self.results["actions"]["TS"].append("un-register")

            if self.hs_clean:
                self.hs_delete_node()
                self.results["actions"]["HS"].append(
                    f"delete node {self.init_nodename}",
                )
        elif self.init_state == State.UNREGISTERED:
            # Already un-registered
            pass
        else:
            self.module.fail_json(msg=f"Unknow state: {self.init_state}")

    def run(self):
        """
        Logic entrypoint.
        """
        self._validate_state(self.init_state)

        if self.state == "present":
            self.present()
        else:
            self.absent()

        self.ts_ensure_sync([self.ts_is_sync])

        status = self.ts_get_status()
        self.results["status"] = status["BackendState"]


def main():
    module = setup_module_object()
    results = dict(
        changed=False,
        actions={"TS": [], "HS": []},
    )
    login = TailscaleLogin(module, results)
    login.run()

    if "actions" in results:
        msg = make_result_msg(results["actions"])
        results["msg"] = msg
        del results["actions"]

    module.exit_json(**results)


def get_hostname():
    return platform.node().split(".")[0]


def make_argument_spec():
    spec = dict(
        server_url=dict(
            required=True,
            type="str",
            aliases=[
                "headscale_server",
                "tailscale_server",
                "server",
                "headscale_url",
            ],
        ),
        auth_token=dict(type="str", required=True, no_log=True),
        api_token=dict(type="str", required=True, no_log=True),
        reregister=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        nodename=dict(type="str", default=get_hostname()),
        advertise_tags=dict(type="list", default=[]),
        register_opts=dict(type="list", default=[]),
        hs_clean=dict(type="bool", default=True),
        accept_routes=dict(type="bool", default=False),
        accept_dns=dict(type="bool", default=True),
        timeout=dict(type="str", default="20s"),
        sync_check=dict(type="int", default=3),
        socket=dict(type="path", default="/var/run/tailscale/tailscaled.sock"),
        state_file=dict(type="path", default="/var/lib/tailscale/tailscaled.state"),
    )

    return spec


def setup_module_object():
    module = AnsibleModule(
        argument_spec=make_argument_spec(),
        supports_check_mode=False,
    )
    return module


if __name__ == "__main__":
    main()
