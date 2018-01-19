# ID -> Name Translator for CloudGenix
ID -> Name translator for the CloudGenix Python SDK

#### Synopsis
CloudGenix's API uses unique ID values for all objects.

This quick module utilizes the CloudGenix Python SDK to create a dictionary object containing most
common object lists, referenced by ID.

Once this object is created (ex: `idname_dict`), this allows for quick lookup of names where IDs are present:

```python
idname_dict = cloudgenix_idname.generate_id_name_map(cgx_sess)

vpn_link_id = '15136303805980148'
print ('My VPN link is "{}".'.format(idname_dict.get(vpn_link_id, vpn_link_id)))
```
```
My VPN link is "SJC Branch ('AT&T' via 'Circuit to AT&T') <-> ('ATT2' via 'Circuit to ATT2') Charlotte DC".
```

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * cloudgenix >=4.5.5b3 - <https://github.com/CloudGenix/sdk-python>

#### Code Example
Comes with `test.py` that creates an ID -> Name map and dumps to console.

#### License
MIT

#### Version
Version | Changes
------- | --------
**1.1.0**| Fix various bugs, issue #1, and Python 3 support
**1.0.0**| Initial Release.
