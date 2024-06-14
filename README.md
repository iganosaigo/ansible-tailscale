# Ansible Collection for Tailscale

**NOTE:** Works with only Headscale

This repository hosts `iganosaigo.tailscale` Ansible Collection.

The collection includes common Tailscale managing tasks, modules, roles, etc...

Collenction provides a simple way to manage Tailscale registration and configuration on a Linux systems. It works with Headscale only and TailscaleCloud API does not considired at moment. The collection provides register, re-register and unregister from a given Tailscale parameters. In addition you can configure network parameters of Tailscale node.

## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.16.0**.

## Python Support

- Collection tested on hosts with Python versions: **>=3.6**
