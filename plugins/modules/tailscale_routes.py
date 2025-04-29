#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: tailscale_routes
author:
  - Alexander Grigoriev (an.grigoriev84@gmail.com)
short_description: Configure routes for Tailscale and Headscale.
description:
  - Configure routes and ExitNode for the Tailscale instance.
  - Delete not specified node routes from Headscale.

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
  legacy:
    description:
      - Turn on legacy mode for releases before 0.23.0
    type: bool
    default: false
  api_token:
    description:
      - The Headscale API Token. Required for configuration on HS side.
    type: str
    required: true
  advertise:
    description:
      - Advertise routes from current node.
      - Be aware that if you specify this parameter is empty list, then any external managed route will be deleted.
    type: list
    elements: str
    default: []
  advertise_opts:
    description:
      - Additional options for Tailscale advertise command.
      - Currently module doesn't track these options changes.
    type: list
    elements: str
    default: []
  exit_node:
    description:
      - Set node as ExitNode.
    type: bool
    default: false
  reconfigure:
    description:
      - Force re-create route advertising. 
      - Could be usefull for options that are not-trackable from TS client or HS.
    type: str
    default: false
  timeout:
    description:
      - Optional timout used in tailscale client.
    type: str
    default: "20s"
  sync_check:
    description:
      - After module run there is a sync check between TS and HS.
      - TS may be out of date about it's configuration on HS side.
      - TS status obtained with 'tailscale status' command.
      - This option represents repeat count with exponential delay of this status check.
    type: int
    default: 3
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
msg:
  description: Actions taken to configure TS and HS.
  returned: always
  type: str or list
"""

EXAMPLES = r"""

- name: Configure Tailscale routes and exit-node
  iganosaigo.tailscale.tailscale_routes:
    headscale_url: {{ headscale_url }}"
    api_token: "{{ headscale_api_token }}"
    advertise:
      - 12.12.12.0/24
      - 34.34.34.34/32
    exit_node: true

- name: Same as above but add custom options
  iganosaigo.tailscale.tailscale_routes:
    headscale_url: "{{ headscale_url }}"
    api_token: "{{ headscale_api_token }}"
    advertise:
      - 12.12.12.0/24
      - 34.34.34.34/32
    exit_node: true
    advertise_opts:
      "--snat-subnet-routes"
      "--exit-node-allow-lan-access"
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.iganosaigo.tailscale.plugins.module_utils.util import (
    DEFAULT_ROUTES,
    State,
    Tailscale,
    make_result_msg,
)


class TailscaleRoutes(Tailscale):
    def __init__(self, module: AnsibleModule, results: dict):
        self.module = module
        self.results = results
        self.reconfigure = self.module.params["reconfigure"]
        self.advertise = sorted(self.module.params["advertise"])
        self.advertise_opts = self.module.params["advertise_opts"]
        self.exit_node = self.module.params["exit_node"]
        self.legacy = self.module.params["legacy"]
        super().__init__(self.module, results)

        self._prepare()

    def _prepare(self):
        self._validate_state()
        if self.init_state != State.REGISTERED:
            self.module.fail_json(
                msg=f"State {State.REGISTERED} required. Current: {self.init_state}"
            )
        status = self.init_status["Self"]

        self.init_ts_routes = status["AllowedIPs"]
        self.init_ts_exit_enabled = status["ExitNodeOption"]

        self.node_uri_part = "node"
        if self.legacy:
          self.node_uri_part = "machine"

        self.init_hs_routes = self.hs_get_node_routes()


    def _validate_state(self):
        if not self.init_state in State.values():
            allowed_states = ", ".join(State.values())
            self.module.fail_json(
                msg=f"Unknowsn state. Current: {self.init_state}. Supported: {allowed_states}"
            )

    def enable_route(self, route):
        r_id = route["id"]
        r_advertised = route["advertised"]

        # Additional check specific route is advertised
        if not r_advertised:
            self.module.fail_json(msg="Routes doesn't advertized on Headscale")

        self.hs_enable_route(r_id)

    def hs_disable_route(self, route_id):
        self.fetch_api(
            f"/api/v1/routes/{route_id}/disable",
            "POST",
        )

    def hs_delete_route(self, route_id):
        self.fetch_api(
            f"/api/v1/routes/{route_id}",
            "DELETE",
        )

    def hs_enable_route(self, route_id):
        self.fetch_api(
            f"/api/v1/routes/{route_id}/enable",
            "POST",
        )

    def hs_get_node_routes(self, node_id=None):
        if not node_id:
            node_id = self.node_id
        resp = self.fetch_api(
            f"/api/v1/{self.node_uri_part}/{node_id}/routes",
        )
        routes = resp["routes"]
        fmt_routes = self._format_routes(routes)
        return fmt_routes

    def hs_get_exit_node_routes(self):
        all_routes = self.hs_get_node_routes()
        result = [route for route in all_routes if route["prefix"] in DEFAULT_ROUTES]
        return result

    def _format_routes(self, routes):
        fmt_routes = {}
        for route in routes:
            r_id = route["id"]
            r_enabled = route["enabled"]
            r_prefix = route["prefix"]
            r_advertised = route["advertised"]
            r_primary = route["isPrimary"]
            fmt_routes.update(
                {
                    r_prefix: {
                        "id": r_id,
                        "enabled": r_enabled,
                        "advertised": r_advertised,
                        "primary": r_primary,
                    }
                }
            )
        return fmt_routes

    def filter_hs_routes(self, routes, exit_node=False):
        if exit_node:
            result = {k: v for k, v in routes.items() if k in DEFAULT_ROUTES}
        else:
            result = {k: v for k, v in routes.items() if k not in DEFAULT_ROUTES}

        return result

    def ts_set_exit_node(self):
        cmd = self._ts_cmd(["set", "--advertise-exit-node"])
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Set ExitNode failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def ts_set_routes(self):
        if self.advertise:
            prefixes = ",".join(self.advertise)
            cmd = self._ts_cmd(["set", f"--advertise-routes={prefixes}"])
        else:
            cmd = self._ts_cmd(["set", f"--advertise-routes="])

        if self.advertise_opts:
            cmd.extend(self.advertise_opts)

        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Set ExitNode failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def ts_unset_exit_node(self):
        cmd = self._ts_cmd(["set", "--advertise-exit-node=false"])
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                "Disabling ExitNode failed.",
                stdout=stdout,
                stderr=stderr,
            )

    def manage_advertise(self):
        hs_routes = self.filter_hs_routes(self.init_hs_routes)

        hs_existing_prefixes = set(hs_routes.keys())
        advertise_prefixes = set(self.advertise)

        if advertise_prefixes or self.reconfigure:
            module_routes_advertised = advertise_prefixes.issubset(hs_existing_prefixes)
            external_routes = hs_existing_prefixes.difference(advertise_prefixes)

            # Make sure that parameter 'advertised' of each existed route is 'true'
            routes_advertised = all(
                [v["advertised"] for k, v in hs_routes.items() if k in self.advertise]
            )

            external_routes_delete = []
            for route in external_routes:
                route_id = hs_routes[route]["id"]
                self.hs_delete_route(route_id)
                self.ts_set_routes()
                self.results["changed"] = True
                external_routes_delete.append(route)
            if external_routes_delete:
                msg = ", ".join(external_routes_delete)
                self.results["actions"]["HS"].append(f"delete routes {msg}")
                self.results["actions"]["TS"].append(f"re-set advertise routes")

            if (
                not module_routes_advertised
                or not routes_advertised
                or self.reconfigure
            ):
                self.ts_set_routes()
                time.sleep(3)
                routes_msg = ", ".join(self.advertise)
                self.results["changed"] = True
                if self.reconfigure:
                    ts_msg = f"force re-configure advertising"
                    if routes_msg:
                        ts_msg = ts_msg + f" with routes {routes_msg}"
                    self.results["actions"]["TS"].append(ts_msg)
                else:
                    self.results["actions"]["TS"].append(
                        f"set advertise routes {routes_msg}"
                    )

                # Renew HS routes
                hs_routes = self.filter_hs_routes(
                    self.hs_get_node_routes(
                        self.node_id,
                    )
                )

            # Enable advertised routes
            enabled_routes = []
            for route, param in hs_routes.items():
                route_id = param["id"]
                if not param["advertised"]:
                    self.module.fail_json(msg=f"HS route not advertised: {route}.")
                if not param["enabled"]:
                    self.hs_enable_route(route_id)
                    self.results["changed"] = True
                    enabled_routes.append(route)
            if enabled_routes:
                self.results["actions"]["HS"].extend(
                    [f"enable route {addr}" for addr in enabled_routes]
                )
        else:
            deleted_routes = []
            if hs_routes:
                self.ts_set_routes()
                self.results["changed"] = True
                self.results["actions"]["TS"].append(f"disable advertise routes")
            for route in hs_routes:
                route_id = hs_routes[route]["id"]
                self.hs_delete_route(route_id)
                self.results["changed"] = True
                deleted_routes.append(route)

            if deleted_routes:
                self.results["actions"]["HS"].extend(
                    [f"delete route {addr}" for addr in deleted_routes]
                )

    def ts_is_exit_node_enabled(self, status):
        adv_ips = status["Self"]["AllowedIPs"]
        adv_status = status["Self"]["ExitNodeOption"]
        if "0.0.0.0/0" not in adv_ips or adv_status == False:
            return False
        return True

    def ts_is_sync_routes(self, status):
        ts_exit_node = status["Self"]["ExitNodeOption"]
        ts_self_ip = status["Self"]["TailscaleIPs"][0]
        ts_self_ip = f"{ts_self_ip}/32"
        ts_advertise = set(status["Self"]["AllowedIPs"])
        advertise = set(self.advertise)
        exclude_routes = DEFAULT_ROUTES.union({ts_self_ip})
        required_routes = ts_advertise.difference(exclude_routes)

        if self.exit_node:
            if not DEFAULT_ROUTES.issubset(ts_advertise) or ts_exit_node == False:
                return False
        else:
            if DEFAULT_ROUTES.issubset(ts_advertise) or ts_exit_node == True:
                return False

        if required_routes != advertise:
            return False

        return True

    def enable_exit_node(self):

        hs_exit_routes = self.filter_hs_routes(self.init_hs_routes, exit_node=True)
        advertised = all([v["advertised"] for v in hs_exit_routes.values()])

        if not hs_exit_routes or not advertised:
            self.ts_set_exit_node()
            self.results["changed"] = True
            self.results["actions"]["TS"].append("enable ExitNode")
            time.sleep(3)

            # Renew HS routes
            renewed_routes = self.hs_get_node_routes()
            hs_exit_routes = self.filter_hs_routes(renewed_routes, exit_node=True)
            # Make check exponential instead of time.sleep
            if not hs_exit_routes:
                self.module.fail_json(
                    msg="HS doesn't get routes after TS enable ExitNode"
                )

        # Enable routes if not enabled
        all_routes_enabled = all([v["enabled"] for v in hs_exit_routes.values()])
        if not all_routes_enabled:
            for route, param in hs_exit_routes.items():
                if not param["enabled"]:
                    self.enable_route(hs_exit_routes[route])
                    self.results["changed"] = True
            self.results["actions"]["HS"].append("enable ExitNode route")

    def disable_exit_node(self):
        clean_flag = False
        hs_exit_routes = self.filter_hs_routes(self.init_hs_routes, exit_node=True)

        if hs_exit_routes:
            advertised = any([v["advertised"] for v in hs_exit_routes.values()])
            if advertised:
                self.ts_unset_exit_node()
                self.results["changed"] = True
                self.results["actions"]["TS"].append("disable ExitNode")
                time.sleep(3)

                renewed_routes = self.hs_get_node_routes()
                hs_exit_routes = self.filter_hs_routes(renewed_routes, exit_node=True)

            for route in hs_exit_routes.values():
                clean_flag = True
                r_id = route["id"]
                self.hs_delete_route(r_id)

                # Run just once. Deletetion one of ExitNode prefixes
                # automatically removes another(ipv4 and ipv6)
                break

        if clean_flag:
            self.results["changed"] = True
            self.results["actions"]["HS"].append("delete ExitNode route")

    def run(self):
        """
        Logic entrypoint.
        """
        if self.exit_node:
            self.enable_exit_node()
        else:
            self.disable_exit_node()

        self.manage_advertise()
        self.ts_ensure_sync([self.ts_is_sync_routes])


def main():
    module = setup_module_object()
    results = dict(
        changed=False,
        actions={"TS": [], "HS": []},
    )
    routes = TailscaleRoutes(module, results)
    routes.run()

    if "actions" in results:
        msg = make_result_msg(results["actions"])
        results["msg"] = msg
        del results["actions"]

    module.exit_json(**results)


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
        api_token=dict(type="str", required=True, no_log=True),
        reconfigure=dict(type="bool", default=False),
        advertise=dict(type="list", default=[]),
        advertise_opts=dict(type="list", default=[]),
        exit_node=dict(type="bool", default=False),
        timeout=dict(type="str", default="20s"),
        sync_check=dict(type="int", default=3),
        socket=dict(type="path", default="/var/run/tailscale/tailscaled.sock"),
        state_file=dict(type="path", default="/var/lib/tailscale/tailscaled.state"),
        legacy=dict(type="bool", default=False),
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
