# Ansible Collection for Tailscale

**NOTE:** Works with only Headscale

This repository hosts `iganosaigo.tailscale` Ansible Collection.

The collection includes common Tailscale managing tasks, modules, roles, etc...

Collenction provides a simple way to manage Tailscale registration and configuration on a Linux systems. It works with Headscale only and TailscaleCloud API does not considired at moment. The collection provides register, re-register and unregister from a given Tailscale parameters. In addition you can configure network parameters of Tailscale node.

## Headscale version compatibility

Has been tested against Headscale version v0.22.3 and v0.25.1 but others should be fine though.
For releases prior v0.23.0 requires to turn on `legacy` mode

## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.16.0**.

## Python Support

- Collection tested on hosts with Python versions: **>=3.6**

## Examples

For using this collection modules you have to create apikey and authkey tokens
at Headscale. You could create long-lived tokens or create temporary tokens at
the begining of your role/playbook. For long lived tokens use the following commands:

```
headscale apikeys create --expiration 30d
headscale preauthkeys create --user admin --expiration 30d
```

For short-lived tokens you could write something like this:

```
- name: Block
  block:
    - name: Command | Headscale auth_key generate
      ansible.builtin.command:
        cmd: >
          headscale
          preauthkeys
          create
          --user {{ headscale_admin_user | d('admin') }}
          --reusable
          --expiration 5m
      register: __preauth_cmd
      changed_when: false
      when: inventory_hostname in groups['headscale']
      no_log: true

    - name: Set_fact | preauth_key
      ansible.builtin.set_fact:
        _auth_token: "{{ hostvars[groups['headscale'][0]]['__preauth_cmd']['stdout'] }}"
      no_log: true

    - name: Tailscale_login | Login to Headscale
      iganosaigo.infra.tailscale_login:
        headscale_url: "{{ headscale_url }}"
        auth_token: "{{ _auth_token }}"
        accept_dns: "{{ tailscale_accept_dns }}"
        accept_routes: "{{ tailscale_accept_routes }}"
        reregister: "{{ tailscale_reregister }}"
        advertise_tags: "{{ tailscale_advertise_tags | d(omit) }}"
        nodename: "{{ tailscale_nodename | d(omit) }}"
        state: "{{ tailscale_register | ternary('present', 'absent') }}"
      when: inventory_hostname in groups['tailscale']

  always:
    - name: Command | Headscale auth_key set expire
      ansible.builtin.command:
        cmd: >
          headscale
          preauthkeys
          expire
          --user {{ headscale_admin_user | d('admin') }}
          {{ _auth_token }}
      changed_when: false
      when: inventory_hostname in groups['headscale']
```

Fine, hust simple login without any options, i.e. use client defaults.

```
- name: Tailscale login
  iganosaigo.tailscale.tailscale_login:
    headscale_url: "https://headscale.example.com:8443"
    auth_token: "your_auth_token"
    api_token: "your_api_token"
```

For creating node with tags add `advertise_tags` list. Note that this parameter
only consider nodes advertised Tags. It doesn't consider Headscale ForcedTags and
you must not use them together with advertised tags. Also changing this option
trigger `tailscale login` once again. Tailscale tags format is `tag:<tag_name>`.
You must specify your tags without `tag:` prefix, only tag name.

```
- name: Tailscale login
  iganosaigo.tailscale.tailscale_login:
    headscale_url: "https://headscale.example.com:8443"
    auth_token: "your_auth_token"
    api_token: "your_api_token"
    accept_dns: false
    accept_routes: false
    advertise_tags:
      - some_tag1
      - some_tag2
```

Options `accept_dns` and `accept_routes` couldn't be checked at Tailscale status.
This means if you want to change those options with ansible then you have to
re-register node. The same apply to `register_opts` - its purpose to add any
tailscale option you like which currently this collection doesn't support.

One more trick is to add options that module 'tailscale_routes' support.
For example you could add those parameters at registration:

```
- name: Tailscale login
  iganosaigo.tailscale.tailscale_login:
    headscale_url: "https://headscale.example.com:8443"
    auth_token: "your_auth_token"
    api_token: "your_api_token"
    register_opts:
      "--advertise-exit-node"
      "--advertise-routes 2.2.2.0/24"
```

This leads to problem that changing those parameters with ansible requires
pass 'reregister' option for re-registration. So, for advertising routes
and exit-node you should use `tailscale_routes` module instead:

```
- name: Tailscale Routes
  iganosaigo.tailscale.tailscale_routes:
    headscale_url: "https://headscale.example.com:8443"
    api_token: "your_api_token"
    advertise:
      - 12.12.12.0/24
      - 34.34.34.34/32
    exit_node: true
    advertise_opts:
      "--snat-subnet-routes"
      "--exit-node-allow-lan-access"
```

When you use route module be aware that any routes managed outside of
ansible will be deleted! The same apply to `exit_node` option. But option
`advertise_opts` doesn't track option changes for now within that list.
Just use this list to add necessary options you required. Changing this
list requires option `reconfigure` to apply.
