#!/usr/bin/env python
import json
import cloudgenix

# Import ID -> Name for CloudGenix
import cloudgenix_idname

# Create CloudGenix API constructor
cgx_sess = cloudgenix.API()

# Call CloudGenix API login
cgx_sess.interactive.login()

# Generate ID -> Name Dict
idname_dict = cloudgenix_idname.generate_id_name_map(cgx_sess)

# Dump whole ID -> Name dict to console.
print(json.dumps(idname_dict, indent=4))

# Cleanup and logout
cgx_sess.interactive.logout()
