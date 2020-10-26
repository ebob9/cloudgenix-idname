# ID -> Name Translator for CloudGenix
ID -> Name translator for the CloudGenix Python SDK

#### Synopsis
CloudGenix's API uses unique ID values for all objects.

This quick module utilizes the CloudGenix Python SDK to create a dictionary object containing most
common object lists, referenced by ID.

##### Simple usage:
```python
idname_dict = cloudgenix_idname.generate_id_name_map(cgx_sess)
# takes 30-40 seconds to generate.

vpn_link_id = '15136303805980148'
print ('My VPN link is "{}".'.format(idname_dict.get(vpn_link_id, vpn_link_id)))
```
```
My VPN link is "SJC Branch ('AT&T' via 'Circuit to AT&T') <-> ('ATT2' via 'Circuit to ATT2') Charlotte DC".
```

##### Efficient usage:
```python
# create constructor to make and cache queries
idname = cloudgenix_idname.CloudGenixIDName(cgx_sess)

# get just VPN id to name maps.
vpnpaths_id_to_name = idname.generate_anynets_map()
# takes < 3 seconds to generate

# query for VPN
vpn_link_id = '15136303805980148'
print ('My VPN link is "{}".'.format(vpnpaths_id_to_name.get(vpn_link_id, vpn_link_id)))
# output: My VPN link is "SJC Branch ('AT&T' via 'Circuit to AT&T') <-> ('ATT2' via 'Circuit to ATT2') Charlotte DC".

# lets query a link that is new since last time.
new_vpn_link_id = '15136303805980182'
print ('My VPN link is "{}".'.format(vpnpaths_id_to_name.get(vpn_link_id, vpn_link_id)))
# output: My VPN link is "15136303805980182".
vpnpaths_id_to_name = idname.generate_anynets_map()
# takes < 0.1 seconds

print ('My VPN link is "{}".'.format(vpnpaths_id_to_name.get(vpn_link_id, vpn_link_id)))
# output: My VPN link is "SJC Branch ('Verizon' via 'Circuit to Verizon') <-> ('ATT2' via 'Circuit to ATT2') Charlotte DC".
```

#### Requirements
* Active CloudGenix Account
* Python >=3.6 (if you still need 2.7 support, `pip install cloudgenix_idname==1.2.3`)
* Python modules:
    * cloudgenix >=5.2.1b1 - <https://github.com/CloudGenix/sdk-python>

#### Code Example
Comes with `test.py` that creates an ID -> Name map and dumps to console.

#### License
MIT

#### Version
Version | Changes
------- | --------
**2.0.2**| Added support for failure of API calls to still generate lookup maps. (Specifically seen with tenant_viewonly on operators API.)
**2.0.1**| Add support for localprefixes, globalprefixes
**2.0.0**| Major rewrite, Deprecate Python2. Now supports a Class object and caching with delta updates (where available.)
**1.2.3**| Fixed minor return issue
**1.2.2**| Add support for Spoke Clusters
**1.2.1**| Add support for SDK >= 5.1.1b1
**1.2.0**| Add reverse lookup support (name -> ID) to all functions. Reverse lookup has limitations as names are not unique.
**1.1.3**| Resolve Issue #6, enhance Site WAN Interface mapping, add shortcut to generate_id_name_map.
**1.1.2**| Fix minor return issue.
**1.1.1**| Fix issue with tenant_viewonly not being able to read operators.
**1.1.0**| Fix various bugs, issue #1, and Python 3 support
**1.0.0**| Initial Release.
