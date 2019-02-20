"""
ID -> Name Map for CloudGenix Python SDK.

This module takes a API() constructor from the Cloudgenix Python SDK
https://github.com/CloudGenix/sdk-python

And builds an ID keyed name dictionary.

"""
import time
import json
import logging

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

role_xlate = {
    'HUB': 'DC',
    'SPOKE': 'Branch'
}


def operators_to_name_dict(sdk):

    xlate_dict = {}
    reverse_xlate_dict = {}

    resp = sdk.get.tenant_operators()
    status = resp.cgx_status
    raw_operators = resp.cgx_content

    operators_list = raw_operators.get('items', None)

    if not status or not operators_list:
        logger.info("ERROR: unable to get operators for account '{0}'.".format(sdk.tenant_name))
        return xlate_dict, reverse_xlate_dict

    # build translation dict
    for operator in operators_list:
        name = operator.get('name')
        o_id = operator.get('id')
        email = operator.get('email')

        if name and o_id:
            xlate_dict[o_id] = name
            reverse_xlate_dict[name] = o_id
        # if no name, use email as secondary option.
        elif email and o_id:
            xlate_dict[o_id] = email
            reverse_xlate_dict[email] = o_id

    return xlate_dict, reverse_xlate_dict


def siteid_to_name_dict(sdk):

    xlate_dict = {}
    reverse_xlate_dict = {}
    id_info_dict = {}
    id_list = []

    resp = sdk.get.sites()
    status = resp.cgx_status
    raw_sites = resp.cgx_content

    sites_list = raw_sites.get('items', None)

    # logger.info(json.dumps(sites_list, indent=4)

    if not status or not sites_list:
        logger.info("ERROR: unable to get sites for account '{0}'.".format(sdk.tenant_name))
        return xlate_dict, reverse_xlate_dict, id_list, id_info_dict

    # build translation dict
    for site in sites_list:
        # logger.info(json.dumps(site, indent=4)
        name = site.get('name')
        s_id = site.get('id')

        if name and s_id:
            xlate_dict[s_id] = name
            reverse_xlate_dict[name] = s_id

        if s_id:
            id_list.append(s_id)
            id_info_dict[s_id] = site

    return xlate_dict, reverse_xlate_dict, id_list, id_info_dict


def elements_to_name_dict(sdk):

    name_xlate_dict = {}
    reverse_xlate_dict = {}
    site_xlate_dict = {}
    id_list = []

    resp = sdk.get.elements()
    status = resp.cgx_status
    raw_elements = resp.cgx_content

    elements_list = raw_elements.get('items', None)

    # logger.info(json.dumps(elements_list, indent=4)

    if not status or not elements_list:
        logger.info("ERROR: unable to get elements for account '{0}'.".format(sdk.tenant_name))
        return name_xlate_dict, reverse_xlate_dict, site_xlate_dict, id_list

    # build translation dict
    for element in elements_list:
        name = element.get('name')
        e_id = element.get('id')
        site = element.get('site_id', None)

        if name and e_id:
            name_xlate_dict[e_id] = name
            reverse_xlate_dict[name] = e_id

        if site and e_id:
            site_xlate_dict[e_id] = site

        if e_id:
            id_list.append(e_id)

    return name_xlate_dict, reverse_xlate_dict, site_xlate_dict, id_list


def securityzone_to_name_dict(sdk):

    name_xlate_dict = {}
    reverse_xlate_dict = {}
    id_list = []

    resp = sdk.get.securityzones()
    status = resp.cgx_status
    raw_securityzones = resp.cgx_content

    securityzones_list = raw_securityzones.get('items', None)

    # logger.info(json.dumps(securityzones_list, indent=4)

    if not status or not securityzones_list:
        logger.info("ERROR: unable to get securityzones for account '{0}'.".format(sdk.tenant_name))
        return name_xlate_dict, reverse_xlate_dict, id_list

    # build translation dict
    for securityzone in securityzones_list:
        name = securityzone.get('name')
        sz_id = securityzone.get('id')

        if name and sz_id:
            name_xlate_dict[sz_id] = name
            reverse_xlate_dict[name] = sz_id

        if sz_id:
            id_list.append(sz_id)

    return name_xlate_dict, reverse_xlate_dict, id_list


def interface_query(site_id, element_id, sdk):

    interface_return = []
    pretty_if_id_to_name_return = {}
    pretty_if_name_to_id_return = {}
    if_id_to_name_return = {}
    if_name_to_id_return = {}
    if_id_data = {}

    resp = sdk.get.interfaces(site_id, element_id)
    status = resp.cgx_status
    raw_interfaces = resp.cgx_content

    interfaces_list = raw_interfaces.get('items', None)

    # logger.info(json.dumps(interfaces_list, indent=4)

    if not status or not interfaces_list:
        logger.info("ERROR: unable to get interfaces for element '{0}' at site '{1}'."
                    "".format(element_id, site_id))
        return interface_return, pretty_if_id_to_name_return, pretty_if_name_to_id_return, \
            if_id_to_name_return, if_name_to_id_return, if_id_data

    # build translation dict

    for interface in interfaces_list:
        name = interface.get('name', "")
        if_id = interface.get('id', None)
        interface_return.append(interface)

        if name and if_id:
            pretty_if_id_to_name_return[if_id] = "Interface " + str(name)
            if_id_to_name_return[if_id] = name
            pretty_if_name_to_id_return["Interface " + str(name)] = if_id
            if_name_to_id_return[name] = if_id

        if if_id:
            if_id_data[if_id] = interface

    return interface_return, pretty_if_id_to_name_return, pretty_if_name_to_id_return, \
        if_id_to_name_return, if_name_to_id_return, if_id_data


def wan_network_dicts(sdk):

    id_xlate_dict = {}
    name_xlate_dict = {}
    wan_network_id_list = []
    wan_network_id_type = {}

    resp = sdk.get.wannetworks()
    status = resp.cgx_status
    raw_wan_networks = resp.cgx_content

    wan_networks_list = raw_wan_networks.get('items', None)

    if not status or not wan_networks_list:
        logger.info("ERROR: unable to get wan networks for account '{0}'.".format(sdk.tenant_name))
        return id_xlate_dict, name_xlate_dict, wan_network_id_list, wan_network_id_type

    # build translation dict
    for wan_network in wan_networks_list:
        name = wan_network.get('name')
        wan_network_id = wan_network.get('id')
        wn_type = wan_network.get('type')

        if name and wan_network_id:
            id_xlate_dict[wan_network_id] = "{0} ({1})".format(name, wn_type)
            name_xlate_dict["{0} ({1})".format(name, wn_type)] = wan_network_id
            wan_network_id_list.append(wan_network_id)

        if wan_network_id and wn_type:
            wan_network_id_type[wan_network_id] = wn_type

    return id_xlate_dict, name_xlate_dict, wan_network_id_list, wan_network_id_type


def circuit_categories_dicts(sdk):

    id_xlate_dict = {}
    reverse_xlate_dict = {}

    resp = sdk.get.waninterfacelabels()
    status = resp.cgx_status
    raw_wan_labels = resp.cgx_content

    wan_labels_list = raw_wan_labels.get('items', None)

    if not status or not wan_labels_list:
        logger.info("ERROR: unable to get circuit categories for account '{0}'.".format(sdk.tenant_name))
        return id_xlate_dict, reverse_xlate_dict

    # build translation dict
    for wan_label in wan_labels_list:
        name = wan_label.get('name')
        wan_label_id = wan_label.get('id')

        if name and wan_label_id:
            id_xlate_dict[wan_label_id] = name
            reverse_xlate_dict[name] = wan_label_id

    return id_xlate_dict, reverse_xlate_dict


def network_context_dicts(sdk):

    id_xlate_dict = {}
    reverse_xlate_dict = {}

    resp = sdk.get.networkcontexts()
    status = resp.cgx_status
    raw_network_contexts = resp.cgx_content

    network_contexts_list = raw_network_contexts.get('items', None)

    if not status or not network_contexts_list:
        logger.info("ERROR: unable to get network contexts for account '{0}'.".format(sdk.tenant_name))
        return id_xlate_dict, reverse_xlate_dict

    # build translation dict
    for network_context in network_contexts_list:
        name = network_context.get('name')
        network_context_id = network_context.get('id')

        if name and network_context_id:
            id_xlate_dict[network_context_id] = name
            reverse_xlate_dict[name] = network_context_id

    return id_xlate_dict, reverse_xlate_dict


def appdefs_to_name_dict(sdk):

    xlate_dict = {}
    reverse_xlate_dict = {}
    id_list = []

    resp = sdk.get.appdefs()
    status = resp.cgx_status
    raw_appdefs = resp.cgx_content

    appdefs_list = raw_appdefs.get('items', None)

    if not status or not appdefs_list:
        logger.info("ERROR: unable to get appdefs for account '{0}'.".format(sdk.tenant_name))
        return xlate_dict, reverse_xlate_dict, id_list

    # build translation dict
    for appdef in appdefs_list:
        name = appdef.get('display_name')
        a_id = appdef.get('id')

        if name and a_id:
            xlate_dict[a_id] = name
            reverse_xlate_dict[name] = a_id

        if a_id:
            id_list.append(a_id)

    return xlate_dict, reverse_xlate_dict, id_list


def policyset_to_name_dict(sdk):

    xlate_dict = {}
    reverse_xlate_dict = {}
    id_list = []

    resp = sdk.get.policysets()
    status = resp.cgx_status
    raw_policyset = resp.cgx_content

    policyset_list = raw_policyset.get('items', None)

    if not status or not policyset_list:
        logger.info("ERROR: unable to get policysets for account '{0}'.".format(sdk.tenant_name))
        return xlate_dict, reverse_xlate_dict, id_list

    # build translation dict
    for policyset in policyset_list:
        name = policyset.get('name')
        p_id = policyset.get('id')

        if name and p_id:
            xlate_dict[p_id] = name
            reverse_xlate_dict[name] = p_id

        if p_id:
            id_list.append(p_id)

    return xlate_dict, reverse_xlate_dict, id_list


def securitypolicyset_to_name_dict(sdk):

    xlate_dict = {}
    reverse_xlate_dict = {}
    id_list = []

    resp = sdk.get.securitypolicysets()
    status = resp.cgx_status
    raw_securitypolicyset = resp.cgx_content

    securitypolicyset_list = raw_securitypolicyset.get('items', None)

    if not status or not securitypolicyset_list:
        logger.info("ERROR: unable to get securitypolicysets for account '{0}'.".format(sdk.tenant_name))
        return xlate_dict, id_list

    # build translation dict
    for securitypolicyset in securitypolicyset_list:
        name = securitypolicyset.get('name')
        securitypolicyset_id = securitypolicyset.get('id')

        if name and securitypolicyset_id:
            xlate_dict[securitypolicyset_id] = name
            reverse_xlate_dict[name] = securitypolicyset_id

        if securitypolicyset_id:
            id_list.append(securitypolicyset_id)

    return xlate_dict, reverse_xlate_dict, id_list


def generate_id_name_map(sdk, reverse=False):
    """
    Generate the ID-NAME map dict
    :param sdk: CloudGenix API constructor
    :param reverse: Generate reverse name-> ID map as well, return tuple with both.
    :return: ID Name dictionary
    """

    global_id_name_dict = {}
    global_name_id_dict = {}

    # system struct
    system_list = []

    # Global lookup dictionary for sub items
    if_id_to_name = {}
    global_swi_id = {}
    global_ln_id = {}

    swi_to_wan_network_dict = {}
    swi_to_site_dict = {}
    wan_network_to_swi_dict = {}
    all_anynets = {}
    all_vpns = {}
    swi_id_name_dict = {}
    site_swi_dict = {}
    path_id_to_name = {}
    vpn_id_to_anynet_id = {}

    # Create xlation dicts and lists.

    logger.info("Caching Operators..")
    id_operator_dict, operator_id_dict = operators_to_name_dict(sdk)
    if id_operator_dict:
        global_id_name_dict.update(id_operator_dict)
    global_name_id_dict.update(operator_id_dict)
    if operator_id_dict:
        global_name_id_dict.update(operator_id_dict)

    logger.info("Caching Sites..")
    id_site_dict, site_id_dict, site_id_list, site_info_dict = siteid_to_name_dict(sdk)
    global_id_name_dict.update(id_site_dict)
    global_name_id_dict.update(site_id_dict)

    logger.info("Caching Elements..")
    id_element_dict, element_id_dict, element_site_dict, element_id_list = elements_to_name_dict(sdk)
    global_id_name_dict.update(id_element_dict)
    global_name_id_dict.update(element_id_dict)

    logger.info("Caching WAN Networks..")
    id_wannetwork_dict, name_wannetwork_id_dict, wannetwork_id_list, wannetwork_type_dict = wan_network_dicts(sdk)
    global_id_name_dict.update(id_wannetwork_dict)
    global_name_id_dict.update(name_wannetwork_id_dict)

    logger.info("Caching Circuit Catagories..")
    id_circuit_categories, name_circuit_categories = circuit_categories_dicts(sdk)
    global_id_name_dict.update(id_circuit_categories)
    global_name_id_dict.update(name_circuit_categories)

    logger.info("Caching Network Contexts..")
    id_network_contexts, name_circuit_contexts = network_context_dicts(sdk)
    global_id_name_dict.update(id_network_contexts)
    global_name_id_dict.update(name_circuit_contexts)

    logger.info("Caching Appdefs..")
    id_appdef_dict, name_appdef_dict, appdef_id_list = appdefs_to_name_dict(sdk)
    global_id_name_dict.update(id_appdef_dict)
    global_name_id_dict.update(name_appdef_dict)

    logger.info("Caching Policysets..")
    id_policyset_dict, name_policyset_dict, policyset_id_list = policyset_to_name_dict(sdk)
    global_id_name_dict.update(id_policyset_dict)
    global_name_id_dict.update(name_policyset_dict)

    logger.info("Caching Security Policysets..")
    id_securitypolicyset_dict, name_securitypolicyset_dict, \
        securitypolicyset_id_list = securitypolicyset_to_name_dict(sdk)
    global_id_name_dict.update(id_securitypolicyset_dict)
    global_name_id_dict.update(name_securitypolicyset_dict)

    logger.info("Caching Security Zones..")
    id_securityzone_dict, securityzone_id_dict, securityzone_id_list = securityzone_to_name_dict(sdk)
    global_id_name_dict.update(id_securityzone_dict)
    global_name_id_dict.update(securityzone_id_dict)

    id_interface_dict = {}

    logger.info("Filling Network Site->Element->Interface table..")

    for site in site_id_list:
        elements = []
        swi_id_dict = {}
        ln_id_dict = {}

        # enumerate elements
        for element in element_id_list:
            # Is this element bound to a site?
            site_in = element_site_dict.get(element, None)
            # if it is bound, and bound to this site, add to list.
            if site_in and site_in == site:
                # Query interfaces
                interfaces_list, if_id_to_name_item, if_name_to_id_item, _, \
                    _, if_id_data_entry = interface_query(site, element, sdk)
                # add the element to the list
                elements.append({
                    'id': element,
                    'name': id_element_dict.get(element, ""),
                    'interfaces': interfaces_list
                })
                # add the if id name mapping to the main dict
                if_id_to_name.update(if_id_to_name_item)
                # update grand interface list
                id_interface_dict.update(if_id_data_entry)


        system_list.append({
            'id': site,
            'name': id_site_dict.get(site, ""),
            'elements': elements
        })

        # query Site WAN Interface info
        resp = sdk.get.waninterfaces(site)
        swi_status = resp.cgx_status
        swi_query = resp.cgx_content

        if swi_status:
            # iterate all the site wan interfaces
            for current_swi in swi_query.get('items', []):
                # get the WN bound to the SWI.

                wan_network_id = current_swi.get('network_id', "")
                swi_id = current_swi.get('id', "")
                name = current_swi.get('name')

                if name and swi_id:
                    swi_id_name_dict[swi_id] = name
                elif swi_id and wan_network_id:
                    # Handle SWI with no name.
                    wan_network_name = id_wannetwork_dict.get(wan_network_id, wan_network_id)
                    swi_id_name_dict[swi_id] = "Circuit to {0}".format(wan_network_name)

                if swi_id:
                    # update SWI -> Site xlation dict
                    swi_to_site_dict[swi_id] = site

                # get the SWIs
                if wan_network_id and swi_id:
                    logger.debug('SWI_ID = SITE: {0} = {1}'.format(swi_id, site))

                    # query existing wan_network_to_swi dict if entry exists.
                    existing_swi_list = wan_network_to_swi_dict.get(wan_network_id, [])

                    # update swi -> WN xlate dict
                    swi_to_wan_network_dict[swi_id] = wan_network_id

                    # update WN -> swi xlate dict
                    existing_swi_list.append(swi_id)
                    wan_network_to_swi_dict[wan_network_id] = existing_swi_list

            # add to global
            global_swi_id.update(swi_id_name_dict)

        # query LAN Network info
        resp = sdk.get.lannetworks(site)
        ln_status = resp.cgx_status
        ln_query = resp.cgx_content

        if ln_status:
            for ln in ln_query.get('items'):
                ln_id = ln.get('id')
                ln_name = ln.get('name')

                if ln_id and ln_name:
                    ln_id_dict[ln_id] = ln_name

            # add to global
            global_ln_id.update(ln_id_dict)

    logger.info("Loading VPN topology information for {0} sites, please wait...".format(len(site_id_list)))

    # add all interface IDs
    # note - can't reliably make reverse name to ID items here, as they are not global.
    global_id_name_dict.update(if_id_to_name)
    global_id_name_dict.update(global_swi_id)
    global_id_name_dict.update(global_ln_id)

    for site in site_id_list:
        site_swi_list = []

        query = {
            "type": "basenet",
            "nodes": [
                site
            ]
        }

        status = False
        rest_call_retry = 0

        resp = sdk.post.topology(query)
        status = resp.cgx_status
        topology = resp.cgx_content

        if status and topology:
            # iterate topology. We need to iterate all of the matching SWIs, and existing anynet connections (sorted).
            logger.debug("TOPOLOGY: {0}".format(json.dumps(topology, indent=4)))

            for link in topology.get('links', []):
                link_type = link.get('type', "")

                # if an anynet link (SWI to SWI)
                if link_type in ["anynet", "public-anynet", "private-anynet"]:
                    # vpn record, check for uniqueness.
                    # 4.4.1
                    source_swi = link.get('source_wan_if_id')
                    if not source_swi:
                        # 4.3.x compatibility
                        source_swi = link.get('source_wan_path_id')
                        if source_swi:
                            link['source_wan_if_id'] = source_swi
                    # 4.4.1
                    dest_swi = link.get('target_wan_if_id')
                    if not dest_swi:
                        # 4.3.x compatibility
                        dest_swi = link.get('target_wan_path_id')
                        if dest_swi:
                            link['target_wan_if_id'] = dest_swi
                    # create anynet lookup key
                    # anynet_lookup_key = "_".join(sorted([source_swi, dest_swi]))
                    # use path ID
                    anynet_lookup_key = link.get('path_id')
                    if not all_anynets.get(anynet_lookup_key, None):
                        # path is not in current anynets, add
                        all_anynets[anynet_lookup_key] = link
                    else:
                        # path_id already seen.
                        pass

                elif link_type in ['vpn']:
                    vpn_lookup_key = link.get('path_id')
                    if not all_vpns.get(vpn_lookup_key, None):
                        # path is not in VPNs, add.
                        all_vpns[vpn_lookup_key] = link
        else:
            # Bail out
            logger.info("ERROR: could not query site ID {0}. Continuing.".format(site))

    # update all_anynets with site info. Can't do this above, because xlation table not finished when needed.
    for anynet_key, link in all_anynets.items():
        # 4.4.1
        source_swi = link.get('source_wan_if_id')
        if not source_swi:
            # 4.3.x compatibility
            source_swi = link.get('source_wan_path_id')
        # 4.4.1
        dest_swi = link.get('target_wan_if_id')
        if not dest_swi:
            # 4.3.x compatibility
            dest_swi = link.get('target_wan_path_id')

        source_site_id = swi_to_site_dict.get(source_swi, 'UNKNOWN (Unable to map SWI to Site ID)')
        target_site_id = swi_to_site_dict.get(dest_swi, 'UNKNOWN (Unable to map SWI to Site ID)')
        source_wan_network_name = link.get("source_wan_network")
        target_wan_network_name = link.get("target_wan_network")

        # update struct in case it's needed later
        link['source_site_id'] = source_site_id
        link['target_site_id'] = target_site_id

        # get names.
        source_site_name = id_site_dict.get(source_site_id, source_site_id)
        target_site_name = id_site_dict.get(target_site_id, target_site_id)
        source_swi_name = swi_id_name_dict.get(source_swi, source_swi)
        target_swi_name = swi_id_name_dict.get(dest_swi, dest_swi)

        # build text map.
        anynet_text = "{0} ('{1}' via '{2}') <-> ('{4}' via '{5}') {3}".format(
            source_site_name,
            source_wan_network_name,
            source_swi_name,
            target_site_name,
            target_wan_network_name,
            target_swi_name,
        )

        # update pathid to name dict
        path_id_to_name[anynet_key] = anynet_text

    logger.info("SWI -> WN xlate ({0}): {1}".format(len(swi_to_wan_network_dict),
                                                    json.dumps(swi_to_wan_network_dict, indent=4)))
    logger.info("All Anynets ({0}): {1}".format(len(all_anynets),
                                                json.dumps(all_anynets, indent=4)))
    logger.info("All VPNs ({0}): {1}".format(len(all_vpns),
                                             json.dumps(all_vpns, indent=4)))
    logger.info("Site -> SWI construct ({0}): {1}".format(len(site_swi_dict),
                                                          json.dumps(site_swi_dict, indent=4)))
    logger.info("WN to SWI xlate ({0}): {1}".format(len(wan_network_to_swi_dict),
                                                    json.dumps(wan_network_to_swi_dict, indent=4)))
    logger.info("SWI -> SITE xlate ({0}): {1}".format(len(swi_to_site_dict),
                                                      json.dumps(swi_to_site_dict, indent=4)))

    # create VPN to anynet maps AND update text mappings.

    for vpn_key, link in all_vpns.items():
        anynet_link_id = link.get("anynet_link_id")
        source_element_id = link.get("source_node_id")
        target_element_id = link.get("target_node_id")

        # update vpn -> anynet table
        vpn_id_to_anynet_id[vpn_key] = anynet_link_id

        # get names
        source_element_name = id_element_dict.get(source_element_id, source_element_id)
        target_element_name = id_element_dict.get(target_element_id, target_element_id)
        anynet_text = path_id_to_name.get(anynet_link_id, anynet_link_id)

        vpn_text = "[{0}] : {1} : [{2}]".format(
            source_element_name,
            anynet_text,
            target_element_name
        )

        # update path mapping
        path_id_to_name[vpn_key] = vpn_text

    # done, update global
    global_id_name_dict.update(path_id_to_name)

    if reverse:
        # return both id_name and what we can get of name_id.
        return global_id_name_dict, global_name_id_dict

    return global_id_name_dict


def gen(sdk, reverse=False):
    """
    Shortcut to generate_id_name_map
    :param sdk: CloudGenix API constructor
    :param reverse: Generate reverse name-> ID map as well, return tuple with both.
    :return: ID Name dictionary
    """
    return generate_id_name_map(sdk, reverse=reverse)
