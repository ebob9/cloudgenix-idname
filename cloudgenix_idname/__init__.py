"""
ID -> Name Map for CloudGenix Python SDK.

This module takes a API() constructor from the Cloudgenix Python SDK
https://github.com/CloudGenix/sdk-python

And builds an ID keyed name dictionary.

"""
import logging
from copy import deepcopy
import sys

from cloudgenix import CloudGenixAPIError, jdout_detailed

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

role_xlate = {
    'HUB': 'DC',
    'SPOKE': 'Branch'
}

QUERY_ALL = {
    'sort_params': {
        'id': 'desc'
    }
}

######################################################
#
# Begin CloudGenix-idname 2.0 functions
#   New 2.0 uses a class to make ANY/ANY attribute
#   lookup map dicts. Also caches and gets
#   incremental updates only!
#
######################################################


class CloudGenixIDName(object):
    """
    Class to generate flexible key -> value maps (not just ID -> Name)
    """
    sdk = None
    logger = None
    sites_cache = None
    sites_newest = None
    elements_cache = None
    elements_newest = None
    machines_cache = None
    machines_newest = None
    policysets_cache = None
    policysets_newest = None
    securitypolicysets_cache = None
    securitypolicysets_newest = None
    securityzones_cache = None
    securityzones_newest = None
    networkpolicysetstacks_cache = None
    networkpolicysetstacks_newest = None
    networkpolicysets_cache = None
    networkpolicysets_newest = None
    prioritypolicysetstacks_cache = None
    prioritypolicysetstacks_newest = None
    prioritypolicysets_cache = None
    prioritypolicysets_newest = None
    waninterfacelabels_cache = None
    waninterfacelabels_newest = None
    wannetworks_cache = None
    wannetworks_newest = None
    wanoverlays_cache = None
    wanoverlays_newest = None
    servicebindingmaps_cache = None
    servicebindingmaps_newest = None
    serviceendpoints_cache = None
    serviceendpoints_newest = None
    ipsecprofiles_cache = None
    ipsecprofiles_newest = None
    networkcontexts_cache = None
    networkcontexts_newest = None
    appdefs_cache = None
    appdefs_newest = None
    natglobalprefixes_cache = None
    natglobalprefixes_newest = None
    natlocalprefixes_cache = None
    natlocalprefixes_newest = None
    natpolicypools_cache = None
    natpolicypools_newest = None
    natpolicysetstacks_cache = None
    natpolicysetstacks_newest = None
    natpolicysets_cache = None
    natpolicysets_newest = None
    natzones_cache = None
    natzones_newest = None
    tenant_operators_cache = None
    tenant_operators_newest = None
    topology_cache = None
    topology_newest = None
    interfaces_cache = None
    interfaces_newest = None
    waninterfaces_cache = None
    waninterfaces_newest = None
    lannetworks_cache = None
    lannetworks_newest = None
    spokeclusters_cache = None
    spokeclusters_newest = None
    vpnlinks_cache = None
    vpnlinks_newest = None
    anynets_cache = None
    anynets_newest = None
    localprefixfilters_cache = None
    localprefixfilters_newest = None
    globalprefixfilters_cache = None
    globalprefixfilters_newest = None

    nag_cache = []

    def __init__(self, authenticated_sdk):
        self.sdk = authenticated_sdk
        self.logger = logging.getLogger(__name__)
        self.logger.info('Called CloudGenix ID->Name')

    # update all
    def update_all_caches(self):
        self.update_sites_cache()
        self.update_elements_cache()
        self.update_machines_cache()
        self.update_policysets_cache()
        self.update_securitypolicysets_cache()
        self.update_securityzones_cache()
        self.update_networkpolicysetstacks_cache()
        self.update_networkpolicysets_cache()
        self.update_prioritypolicysetstacks_cache()
        self.update_prioritypolicysets_cache()
        self.update_waninterfacelabels_cache()
        self.update_wannetworks_cache()
        self.update_wanoverlays_cache()
        self.update_servicebindingmaps_cache()
        self.update_serviceendpoints_cache()
        self.update_ipsecprofiles_cache()
        self.update_networkcontexts_cache()
        self.update_appdefs_cache()
        self.update_natglobalprefixes_cache()
        self.update_natlocalprefixes_cache()
        self.update_natpolicypools_cache()
        self.update_natpolicysetstacks_cache()
        self.update_natpolicysets_cache()
        self.update_natzones_cache()
        self.update_tenant_operators_cache()
        self.update_topology_cache()
        self.update_interfaces_cache()
        self.update_waninterfaces_cache()
        self.update_lannetworks_cache()
        self.update_spokeclusters_cache()
        self.update_vpnlinks_cache()
        self.update_anynets_cache()
        self.update_localprefixfilters_cache()
        self.update_globalprefixfilters_cache()

    ######################################################
    #
    # Begin Individual Object Cache Update functions
    #
    ######################################################

    def update_sites_cache(self):
        logger.debug("update_sites_cache function")
        if self.sites_cache is None or self.sites_newest is None:
            # no cache data, get full dump
            self.sites_cache, self.sites_newest = self.iterate_sdk_query(self.sdk.post.sites_query,
                                                                         QUERY_ALL,
                                                                         'sites')
        else:
            # update called and we already have a cache, pull new only
            updated_sites_cache, updated_sites_newest = self.iterate_sdk_query(self.sdk.post.sites_query,
                                                                               query_newer_than(self.sites_newest),
                                                                               'sites')
            # update sites cache, if needed
            if len(updated_sites_cache) > 0:
                self.sites_cache = update_cache_bykey(self.sites_cache, updated_sites_cache, key='id')

            if updated_sites_newest > self.sites_newest:
                self.sites_newest = updated_sites_newest

        return

    def update_elements_cache(self):
        logger.debug("update_elements_cache function")
        if self.elements_cache is None or self.elements_newest is None:
            # no cache data, get full dump
            self.elements_cache, self.elements_newest = self.iterate_sdk_query(self.sdk.post.elements_query,
                                                                               QUERY_ALL,
                                                                               'elements')
        else:
            # update called and we already have a cache, pull new only
            updated_elements_cache, updated_elements_newest = self.iterate_sdk_query(self.sdk.post.elements_query,
                                                                                     query_newer_than(
                                                                                         self.elements_newest),
                                                                                     'elements')
            # update elements cache, if needed
            if len(updated_elements_cache) > 0:
                self.elements_cache = update_cache_bykey(self.elements_cache, updated_elements_cache, key='id')

            if updated_elements_newest > self.elements_newest:
                self.elements_newest = updated_elements_newest

        return

    def update_machines_cache(self):
        logger.debug("update_machines_cache function")
        if self.machines_cache is None or self.machines_newest is None:
            # no cache data, get full dump
            self.machines_cache, self.machines_newest = self.iterate_sdk_query(self.sdk.post.machines_query,
                                                                               QUERY_ALL,
                                                                               'machines')
        else:
            # update called and we already have a cache, pull new only
            updated_machines_cache, updated_machines_newest = self.iterate_sdk_query(self.sdk.post.machines_query,
                                                                                     query_newer_than(
                                                                                         self.machines_newest),
                                                                                     'machines')
            # update machines cache, if needed
            if len(updated_machines_cache) > 0:
                self.machines_cache = update_cache_bykey(self.machines_cache, updated_machines_cache, key='id')

            if updated_machines_newest > self.machines_newest:
                self.machines_newest = updated_machines_newest

        return

    def update_policysets_cache(self):
        logger.debug("update_policysets_cache function")
        if self.policysets_cache is None or self.policysets_newest is None:
            # no cache data, get full dump
            self.policysets_cache, self.policysets_newest = self.iterate_sdk_query(self.sdk.post.policysets_query,
                                                                                   QUERY_ALL,
                                                                                   'policysets')
        else:
            # update called and we already have a cache, pull new only
            updated_policysets_cache, updated_policysets_newest = self.iterate_sdk_query(self.sdk.post.policysets_query,
                                                                                         query_newer_than(
                                                                                             self.policysets_newest),
                                                                                         'policysets')
            # update policysets cache, if needed
            if len(updated_policysets_cache) > 0:
                self.policysets_cache = update_cache_bykey(self.policysets_cache, updated_policysets_cache, key='id')

            if updated_policysets_newest > self.policysets_newest:
                self.policysets_newest = updated_policysets_newest

        return

    def update_securitypolicysets_cache(self):
        logger.debug("update_securitypolicysets_cache function")
        if self.securitypolicysets_cache is None or self.securitypolicysets_newest is None:
            # no cache data, get full dump
            self.securitypolicysets_cache, self.securitypolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.securitypolicysets_query,
                QUERY_ALL,
                'securitypolicysets')
        else:
            # update called and we already have a cache, pull new only
            updated_securitypolicysets_cache, updated_securitypolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.securitypolicysets_query,
                query_newer_than(self.securitypolicysets_newest),
                'securitypolicysets')
            # update securitypolicysets cache, if needed
            if len(updated_securitypolicysets_cache) > 0:
                self.securitypolicysets_cache = update_cache_bykey(self.securitypolicysets_cache,
                                                                   updated_securitypolicysets_cache, key='id')

            if updated_securitypolicysets_newest > self.securitypolicysets_newest:
                self.securitypolicysets_newest = updated_securitypolicysets_newest

        return

    def update_securityzones_cache(self):
        logger.debug("update_securityzones_cache function")
        if self.securityzones_cache is None or self.securityzones_newest is None:
            # no cache data, get full dump
            self.securityzones_cache, self.securityzones_newest = self.iterate_sdk_query(
                self.sdk.post.securityzones_query,
                QUERY_ALL,
                'securityzones')
        else:
            # update called and we already have a cache, pull new only
            updated_securityzones_cache, updated_securityzones_newest = self.iterate_sdk_query(
                self.sdk.post.securityzones_query,
                query_newer_than(self.securityzones_newest),
                'securityzones')
            # update securityzones cache, if needed
            if len(updated_securityzones_cache) > 0:
                self.securityzones_cache = update_cache_bykey(self.securityzones_cache, updated_securityzones_cache,
                                                              key='id')

            if updated_securityzones_newest > self.securityzones_newest:
                self.securityzones_newest = updated_securityzones_newest

        return

    def update_networkpolicysetstacks_cache(self):
        logger.debug("update_networkpolicysetstacks_cache function")
        if self.networkpolicysetstacks_cache is None or self.networkpolicysetstacks_newest is None:
            # no cache data, get full dump
            self.networkpolicysetstacks_cache, self.networkpolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.networkpolicysetstacks_query,
                QUERY_ALL,
                'networkpolicysetstacks')
        else:
            # update called and we already have a cache, pull new only
            updated_networkpolicysetstacks_cache, updated_networkpolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.networkpolicysetstacks_query,
                query_newer_than(self.networkpolicysetstacks_newest),
                'networkpolicysetstacks')
            # update networkpolicysetstacks cache, if needed
            if len(updated_networkpolicysetstacks_cache) > 0:
                self.networkpolicysetstacks_cache = update_cache_bykey(self.networkpolicysetstacks_cache,
                                                                       updated_networkpolicysetstacks_cache, key='id')

            if updated_networkpolicysetstacks_newest > self.networkpolicysetstacks_newest:
                self.networkpolicysetstacks_newest = updated_networkpolicysetstacks_newest

        return

    def update_networkpolicysets_cache(self):
        logger.debug("update_networkpolicysets_cache function")
        if self.networkpolicysets_cache is None or self.networkpolicysets_newest is None:
            # no cache data, get full dump
            self.networkpolicysets_cache, self.networkpolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.networkpolicysets_query,
                QUERY_ALL,
                'networkpolicysets')
        else:
            # update called and we already have a cache, pull new only
            updated_networkpolicysets_cache, updated_networkpolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.networkpolicysets_query,
                query_newer_than(self.networkpolicysets_newest),
                'networkpolicysets')
            # update networkpolicysets cache, if needed
            if len(updated_networkpolicysets_cache) > 0:
                self.networkpolicysets_cache = update_cache_bykey(self.networkpolicysets_cache,
                                                                  updated_networkpolicysets_cache, key='id')

            if updated_networkpolicysets_newest > self.networkpolicysets_newest:
                self.networkpolicysets_newest = updated_networkpolicysets_newest

        return

    def update_prioritypolicysetstacks_cache(self):
        logger.debug("update_prioritypolicysetstacks_cache function")
        if self.prioritypolicysetstacks_cache is None or self.prioritypolicysetstacks_newest is None:
            # no cache data, get full dump
            self.prioritypolicysetstacks_cache, self.prioritypolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.prioritypolicysetstacks_query,
                QUERY_ALL,
                'prioritypolicysetstacks')
        else:
            # update called and we already have a cache, pull new only
            updated_prioritypolicysetstacks_cache, updated_prioritypolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.prioritypolicysetstacks_query,
                query_newer_than(self.prioritypolicysetstacks_newest),
                'prioritypolicysetstacks')
            # update prioritypolicysetstacks cache, if needed
            if len(updated_prioritypolicysetstacks_cache) > 0:
                self.prioritypolicysetstacks_cache = update_cache_bykey(self.prioritypolicysetstacks_cache,
                                                                        updated_prioritypolicysetstacks_cache, key='id')

            if updated_prioritypolicysetstacks_newest > self.prioritypolicysetstacks_newest:
                self.prioritypolicysetstacks_newest = updated_prioritypolicysetstacks_newest

        return

    def update_prioritypolicysets_cache(self):
        logger.debug("update_prioritypolicysets_cache function")
        if self.prioritypolicysets_cache is None or self.prioritypolicysets_newest is None:
            # no cache data, get full dump
            self.prioritypolicysets_cache, self.prioritypolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.prioritypolicysets_query,
                QUERY_ALL,
                'prioritypolicysets')
        else:
            # update called and we already have a cache, pull new only
            updated_prioritypolicysets_cache, updated_prioritypolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.prioritypolicysets_query,
                query_newer_than(self.prioritypolicysets_newest),
                'prioritypolicysets')
            # update prioritypolicysets cache, if needed
            if len(updated_prioritypolicysets_cache) > 0:
                self.prioritypolicysets_cache = update_cache_bykey(self.prioritypolicysets_cache,
                                                                   updated_prioritypolicysets_cache, key='id')

            if updated_prioritypolicysets_newest > self.prioritypolicysets_newest:
                self.prioritypolicysets_newest = updated_prioritypolicysets_newest

        return

    def update_waninterfacelabels_cache(self):
        logger.debug("update_waninterfacelabels_cache function")
        if self.waninterfacelabels_cache is None or self.waninterfacelabels_newest is None:
            # no cache data, get full dump
            self.waninterfacelabels_cache, self.waninterfacelabels_newest = self.iterate_sdk_query(
                self.sdk.post.waninterfacelabels_query,
                QUERY_ALL,
                'waninterfacelabels')
        else:
            # update called and we already have a cache, pull new only
            updated_waninterfacelabels_cache, updated_waninterfacelabels_newest = self.iterate_sdk_query(
                self.sdk.post.waninterfacelabels_query,
                query_newer_than(self.waninterfacelabels_newest),
                'waninterfacelabels')
            # update waninterfacelabels cache, if needed
            if len(updated_waninterfacelabels_cache) > 0:
                self.waninterfacelabels_cache = update_cache_bykey(self.waninterfacelabels_cache,
                                                                   updated_waninterfacelabels_cache, key='id')

            if updated_waninterfacelabels_newest > self.waninterfacelabels_newest:
                self.waninterfacelabels_newest = updated_waninterfacelabels_newest

        return

    def update_wannetworks_cache(self):
        logger.debug("update_wannetworks_cache function")
        if self.wannetworks_cache is None or self.wannetworks_newest is None:
            # no cache data, get full dump
            self.wannetworks_cache, self.wannetworks_newest = self.iterate_sdk_query(self.sdk.post.wannetworks_query,
                                                                                     QUERY_ALL,
                                                                                     'wannetworks')
        else:
            # update called and we already have a cache, pull new only
            updated_wannetworks_cache, updated_wannetworks_newest = self.iterate_sdk_query(
                self.sdk.post.wannetworks_query,
                query_newer_than(self.wannetworks_newest),
                'wannetworks')
            # update wannetworks cache, if needed
            if len(updated_wannetworks_cache) > 0:
                self.wannetworks_cache = update_cache_bykey(self.wannetworks_cache, updated_wannetworks_cache, key='id')

            if updated_wannetworks_newest > self.wannetworks_newest:
                self.wannetworks_newest = updated_wannetworks_newest

        return

    def update_wanoverlays_cache(self):
        # wanoverlays has no query API. Full GET only.
        logger.debug("update_wanoverlays_cache function")
        self.wanoverlays_cache, self.wanoverlays_newest = self.iterate_sdk_get(self.sdk.get.wanoverlays,
                                                                               'wanoverlays')
        return

    def update_servicebindingmaps_cache(self):
        logger.debug("update_servicebindingmaps_cache function")
        if self.servicebindingmaps_cache is None or self.servicebindingmaps_newest is None:
            # no cache data, get full dump
            self.servicebindingmaps_cache, self.servicebindingmaps_newest = self.iterate_sdk_query(
                self.sdk.post.servicebindingmaps_query,
                QUERY_ALL,
                'servicebindingmaps')
        else:
            # update called and we already have a cache, pull new only
            updated_servicebindingmaps_cache, updated_servicebindingmaps_newest = self.iterate_sdk_query(
                self.sdk.post.servicebindingmaps_query,
                query_newer_than(self.servicebindingmaps_newest),
                'servicebindingmaps')
            # update servicebindingmaps cache, if needed
            if len(updated_servicebindingmaps_cache) > 0:
                self.servicebindingmaps_cache = update_cache_bykey(self.servicebindingmaps_cache,
                                                                   updated_servicebindingmaps_cache, key='id')

            if updated_servicebindingmaps_newest > self.servicebindingmaps_newest:
                self.servicebindingmaps_newest = updated_servicebindingmaps_newest

        return

    def update_serviceendpoints_cache(self):
        logger.debug("update_serviceendpoints_cache function")
        if self.serviceendpoints_cache is None or self.serviceendpoints_newest is None:
            # no cache data, get full dump
            self.serviceendpoints_cache, self.serviceendpoints_newest = self.iterate_sdk_query(
                self.sdk.post.serviceendpoints_query,
                QUERY_ALL,
                'serviceendpoints')
        else:
            # update called and we already have a cache, pull new only
            updated_serviceendpoints_cache, updated_serviceendpoints_newest = self.iterate_sdk_query(
                self.sdk.post.serviceendpoints_query,
                query_newer_than(self.serviceendpoints_newest),
                'serviceendpoints')
            # update serviceendpoints cache, if needed
            if len(updated_serviceendpoints_cache) > 0:
                self.serviceendpoints_cache = update_cache_bykey(self.serviceendpoints_cache,
                                                                 updated_serviceendpoints_cache, key='id')

            if updated_serviceendpoints_newest > self.serviceendpoints_newest:
                self.serviceendpoints_newest = updated_serviceendpoints_newest

        return

    def update_ipsecprofiles_cache(self):
        logger.debug("update_ipsecprofiles_cache function")
        if self.ipsecprofiles_cache is None or self.ipsecprofiles_newest is None:
            # no cache data, get full dump
            self.ipsecprofiles_cache, self.ipsecprofiles_newest = self.iterate_sdk_query(
                self.sdk.post.ipsecprofiles_query,
                QUERY_ALL,
                'ipsecprofiles')
        else:
            # update called and we already have a cache, pull new only
            updated_ipsecprofiles_cache, updated_ipsecprofiles_newest = self.iterate_sdk_query(
                self.sdk.post.ipsecprofiles_query,
                query_newer_than(self.ipsecprofiles_newest),
                'ipsecprofiles')
            # update ipsecprofiles cache, if needed
            if len(updated_ipsecprofiles_cache) > 0:
                self.ipsecprofiles_cache = update_cache_bykey(self.ipsecprofiles_cache, updated_ipsecprofiles_cache,
                                                              key='id')

            if updated_ipsecprofiles_newest > self.ipsecprofiles_newest:
                self.ipsecprofiles_newest = updated_ipsecprofiles_newest

        return

    def update_networkcontexts_cache(self):
        logger.debug("update_networkcontexts_cache function")
        if self.networkcontexts_cache is None or self.networkcontexts_newest is None:
            # no cache data, get full dump
            self.networkcontexts_cache, self.networkcontexts_newest = self.iterate_sdk_query(
                self.sdk.post.networkcontexts_query,
                QUERY_ALL,
                'networkcontexts')
        else:
            # update called and we already have a cache, pull new only
            updated_networkcontexts_cache, updated_networkcontexts_newest = self.iterate_sdk_query(
                self.sdk.post.networkcontexts_query,
                query_newer_than(self.networkcontexts_newest),
                'networkcontexts')
            # update networkcontexts cache, if needed
            if len(updated_networkcontexts_cache) > 0:
                self.networkcontexts_cache = update_cache_bykey(self.networkcontexts_cache,
                                                                updated_networkcontexts_cache, key='id')

            if updated_networkcontexts_newest > self.networkcontexts_newest:
                self.networkcontexts_newest = updated_networkcontexts_newest

        return

    def update_appdefs_cache(self):
        logger.debug("update_appdefs_cache function")
        if self.appdefs_cache is None or self.appdefs_newest is None:
            # no cache data, get full dump
            self.appdefs_cache, self.appdefs_newest = self.iterate_sdk_query(self.sdk.post.appdefs_query,
                                                                             QUERY_ALL,
                                                                             'appdefs')
        else:
            # update called and we already have a cache, pull new only
            updated_appdefs_cache, updated_appdefs_newest = self.iterate_sdk_query(self.sdk.post.appdefs_query,
                                                                                   query_newer_than(
                                                                                       self.appdefs_newest),
                                                                                   'appdefs')
            # update appdefs cache, if needed
            if len(updated_appdefs_cache) > 0:
                self.appdefs_cache = update_cache_bykey(self.appdefs_cache, updated_appdefs_cache, key='id')

            if updated_appdefs_newest > self.appdefs_newest:
                self.appdefs_newest = updated_appdefs_newest

        return

    def update_natglobalprefixes_cache(self):
        logger.debug("update_natglobalprefixes_cache function")
        if self.natglobalprefixes_cache is None or self.natglobalprefixes_newest is None:
            # no cache data, get full dump
            self.natglobalprefixes_cache, self.natglobalprefixes_newest = self.iterate_sdk_query(
                self.sdk.post.natglobalprefixes_query,
                QUERY_ALL,
                'natglobalprefixes')
        else:
            # update called and we already have a cache, pull new only
            updated_natglobalprefixes_cache, updated_natglobalprefixes_newest = self.iterate_sdk_query(
                self.sdk.post.natglobalprefixes_query,
                query_newer_than(self.natglobalprefixes_newest),
                'natglobalprefixes')
            # update natglobalprefixes cache, if needed
            if len(updated_natglobalprefixes_cache) > 0:
                self.natglobalprefixes_cache = update_cache_bykey(self.natglobalprefixes_cache,
                                                                  updated_natglobalprefixes_cache, key='id')

            if updated_natglobalprefixes_newest > self.natglobalprefixes_newest:
                self.natglobalprefixes_newest = updated_natglobalprefixes_newest

        return

    def update_natlocalprefixes_cache(self):
        logger.debug("update_natlocalprefixes_cache function")
        if self.natlocalprefixes_cache is None or self.natlocalprefixes_newest is None:
            # no cache data, get full dump
            self.natlocalprefixes_cache, self.natlocalprefixes_newest = self.iterate_sdk_query(
                self.sdk.post.natlocalprefixes_query,
                QUERY_ALL,
                'natlocalprefixes')
        else:
            # update called and we already have a cache, pull new only
            updated_natlocalprefixes_cache, updated_natlocalprefixes_newest = self.iterate_sdk_query(
                self.sdk.post.natlocalprefixes_query,
                query_newer_than(self.natlocalprefixes_newest),
                'natlocalprefixes')
            # update natlocalprefixes cache, if needed
            if len(updated_natlocalprefixes_cache) > 0:
                self.natlocalprefixes_cache = update_cache_bykey(self.natlocalprefixes_cache,
                                                                 updated_natlocalprefixes_cache, key='id')

            if updated_natlocalprefixes_newest > self.natlocalprefixes_newest:
                self.natlocalprefixes_newest = updated_natlocalprefixes_newest

        return

    def update_natpolicypools_cache(self):
        logger.debug("update_natpolicypools_cache function")
        if self.natpolicypools_cache is None or self.natpolicypools_newest is None:
            # no cache data, get full dump
            self.natpolicypools_cache, self.natpolicypools_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicypools_query,
                QUERY_ALL,
                'natpolicypools')
        else:
            # update called and we already have a cache, pull new only
            updated_natpolicypools_cache, updated_natpolicypools_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicypools_query,
                query_newer_than(self.natpolicypools_newest),
                'natpolicypools')
            # update natpolicypools cache, if needed
            if len(updated_natpolicypools_cache) > 0:
                self.natpolicypools_cache = update_cache_bykey(self.natpolicypools_cache, updated_natpolicypools_cache,
                                                               key='id')

            if updated_natpolicypools_newest > self.natpolicypools_newest:
                self.natpolicypools_newest = updated_natpolicypools_newest

        return

    def update_natpolicysetstacks_cache(self):
        logger.debug("update_natpolicysetstacks_cache function")
        if self.natpolicysetstacks_cache is None or self.natpolicysetstacks_newest is None:
            # no cache data, get full dump
            self.natpolicysetstacks_cache, self.natpolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicysetstacks_query,
                QUERY_ALL,
                'natpolicysetstacks')
        else:
            # update called and we already have a cache, pull new only
            updated_natpolicysetstacks_cache, updated_natpolicysetstacks_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicysetstacks_query,
                query_newer_than(self.natpolicysetstacks_newest),
                'natpolicysetstacks')
            # update natpolicysetstacks cache, if needed
            if len(updated_natpolicysetstacks_cache) > 0:
                self.natpolicysetstacks_cache = update_cache_bykey(self.natpolicysetstacks_cache,
                                                                   updated_natpolicysetstacks_cache, key='id')

            if updated_natpolicysetstacks_newest > self.natpolicysetstacks_newest:
                self.natpolicysetstacks_newest = updated_natpolicysetstacks_newest

        return

    def update_natpolicysets_cache(self):
        logger.debug("update_natpolicysets_cache function")
        if self.natpolicysets_cache is None or self.natpolicysets_newest is None:
            # no cache data, get full dump
            self.natpolicysets_cache, self.natpolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicysets_query,
                QUERY_ALL,
                'natpolicysets')
        else:
            # update called and we already have a cache, pull new only
            updated_natpolicysets_cache, updated_natpolicysets_newest = self.iterate_sdk_query(
                self.sdk.post.natpolicysets_query,
                query_newer_than(self.natpolicysets_newest),
                'natpolicysets')
            # update natpolicysets cache, if needed
            if len(updated_natpolicysets_cache) > 0:
                self.natpolicysets_cache = update_cache_bykey(self.natpolicysets_cache,
                                                              updated_natpolicysets_cache, key='id')

            if updated_natpolicysets_newest > self.natpolicysets_newest:
                self.natpolicysets_newest = updated_natpolicysets_newest

        return

    def update_natzones_cache(self):
        logger.debug("update_natzones_cache function")
        if self.natzones_cache is None or self.natzones_newest is None:
            # no cache data, get full dump
            self.natzones_cache, self.natzones_newest = self.iterate_sdk_query(self.sdk.post.natzones_query,
                                                                               QUERY_ALL,
                                                                               'natzones')
        else:
            # update called and we already have a cache, pull new only
            updated_natzones_cache, updated_natzones_newest = self.iterate_sdk_query(self.sdk.post.natzones_query,
                                                                                     query_newer_than(
                                                                                         self.natzones_newest),
                                                                                     'natzones')
            # update natzones cache, if needed
            if len(updated_natzones_cache) > 0:
                self.natzones_cache = update_cache_bykey(self.natzones_cache, updated_natzones_cache, key='id')

            if updated_natzones_newest > self.natzones_newest:
                self.natzones_newest = updated_natzones_newest

        return

    def update_tenant_operators_cache(self):
        # tenant_operators has no query API. Full GET only.
        logger.debug("update_tenant_operators_cache function")
        self.tenant_operators_cache, self.tenant_operators_newest = self.iterate_sdk_get(self.sdk.get.tenant_operators,
                                                                                         'tenant_operators')
        return

    def update_topology_cache(self):
        # Non delta caching function
        # self.topology_cache, self.topology_newest = self.extract_links(self.sdk.post.topology({"stub_links": "True",
        #                                                                                        "type": "anynet",
        #                                                                                        "links_only": False}))
        logger.debug("update_topology_cache function")
        if self.topology_cache is None or self.topology_newest is None:
            # # no cache data, get full dump
            # self.topology_cache, self.topology_newest = self.iterate_sdk_query(
            #     self.sdk.post.topology_query,
            #     QUERY_ALL,
            #     'topology')
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.topology_cache, self.topology_newest = self.iterate_sdk_get_bysite(
                self.sdk.post.topology, error_label='topology', data='{{"type":"basenet","nodes":[{0}]}}',
                extract="links")

        else:
            # # update called and we already have a cache, pull new only
            # updated_topology_cache, updated_topology_newest = self.iterate_sdk_query(
            #     self.sdk.post.topology_query,
            #     query_newer_than(
            #         self.topology_newest),
            #     'topology')
            # # update topology cache, if needed
            # if len(updated_topology_cache) > 0:
            #     self.topology_cache = update_cache_bykey(self.topology_cache, updated_topology_cache,
            #                                                   key='id')
            #
            # if updated_topology_newest > self.topology_newest:
            #     self.topology_newest = updated_topology_newest
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.topology_cache, self.topology_newest = self.iterate_sdk_get_bysite(
                self.sdk.post.topology, error_label='topology', data='{{"type":"basenet","nodes":[{0}]}}',
                extract="links")

        return

    def update_interfaces_cache(self):
        logger.debug("update_interfaces_cache function")
        if self.interfaces_cache is None or self.interfaces_newest is None:
            # no cache data, get full dump
            self.interfaces_cache, self.interfaces_newest = self.iterate_sdk_query(self.sdk.post.interfaces_query,
                                                                                   QUERY_ALL,
                                                                                   'interfaces')
        else:
            # update called and we already have a cache, pull new only
            updated_interfaces_cache, updated_interfaces_newest = self.iterate_sdk_query(self.sdk.post.interfaces_query,
                                                                                         query_newer_than(
                                                                                             self.interfaces_newest),
                                                                                         'interfaces')
            # update interfaces cache, if needed
            if len(updated_interfaces_cache) > 0:
                self.interfaces_cache = update_cache_bykey(self.interfaces_cache, updated_interfaces_cache, key='id')

            if updated_interfaces_newest > self.interfaces_newest:
                self.interfaces_newest = updated_interfaces_newest

        return

    def update_waninterfaces_cache(self):
        # Non delta caching function
        logger.debug("update_waninterfaces_cache function")
        if self.waninterfaces_cache is None or self.waninterfaces_newest is None:
            # # no cache data, get full dump
            # self.waninterfaces_cache, self.waninterfaces_newest = self.iterate_sdk_query(
            #     self.sdk.post.waninterfaces_query,
            #     QUERY_ALL,
            #     'waninterfaces')
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.waninterfaces_cache, self.waninterfaces_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.waninterfaces, 'waninterfaces')

        else:
            # # update called and we already have a cache, pull new only
            # updated_waninterfaces_cache, updated_waninterfaces_newest = self.iterate_sdk_query(
            #     self.sdk.post.waninterfaces_query,
            #     query_newer_than(
            #         self.waninterfaces_newest),
            #     'waninterfaces')
            # # update waninterfaces cache, if needed
            # if len(updated_waninterfaces_cache) > 0:
            #     self.waninterfaces_cache = update_cache_bykey(self.waninterfaces_cache, updated_waninterfaces_cache,
            #                                                   key='id')
            #
            # if updated_waninterfaces_newest > self.waninterfaces_newest:
            #     self.waninterfaces_newest = updated_waninterfaces_newest
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.waninterfaces_cache, self.waninterfaces_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.waninterfaces, 'waninterfaces')

        return

    def update_lannetworks_cache(self):
        # Non delta caching function
        logger.debug("update_lannetworks_cache function")
        if self.lannetworks_cache is None or self.lannetworks_newest is None:
            # # no cache data, get full dump
            # self.lannetworks_cache, self.lannetworks_newest = self.iterate_sdk_query(self.sdk.post.lannetworks_query,
            #                                                                          QUERY_ALL,
            #                                                                          'lannetworks')
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.lannetworks_cache, self.lannetworks_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.lannetworks, 'lannetworks')

        else:
            # # update called and we already have a cache, pull new only
            # updated_lannetworks_cache, updated_lannetworks_newest = self.iterate_sdk_query(
            #     self.sdk.post.lannetworks_query,
            #     query_newer_than(
            #         self.lannetworks_newest),
            #     'lannetworks')
            # # update lannetworks cache, if needed
            # if len(updated_lannetworks_cache) > 0:
            #     self.lannetworks_cache = update_cache_bykey(self.lannetworks_cache, updated_lannetworks_cache,
            #     key='id')
            #
            # if updated_lannetworks_newest > self.lannetworks_newest:
            #     self.lannetworks_newest = updated_lannetworks_newest
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.lannetworks_cache, self.lannetworks_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.lannetworks, 'lannetworks')

        return

    def update_spokeclusters_cache(self):
        # Non delta caching function
        logger.debug("update_spokeclusters_cache function")
        if self.spokeclusters_cache is None or self.spokeclusters_newest is None:
            # # no cache data, get full dump
            # self.spokeclusters_cache, self.spokeclusters_newest = \
            # self.iterate_sdk_query(self.sdk.post.spokeclusters_query, QUERY_ALL, spokeclusters')
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.spokeclusters_cache, self.spokeclusters_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.spokeclusters, 'spokeclusters')

        else:
            # # update called and we already have a cache, pull new only
            # updated_spokeclusters_cache, updated_spokeclusters_newest = self.iterate_sdk_query(
            #     self.sdk.post.spokeclusters_query,
            #     query_newer_than(
            #         self.spokeclusters_newest),
            #     'spokeclusters')
            # # update spokeclusters cache, if needed
            # if len(updated_spokeclusters_cache) > 0:
            #     self.spokeclusters_cache = update_cache_bykey(self.spokeclusters_cache,
            #     updated_spokeclusters_cache, key='id')
            #
            # if updated_spokeclusters_newest > self.spokeclusters_newest:
            #     self.spokeclusters_newest = updated_spokeclusters_newest
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.spokeclusters_cache, self.spokeclusters_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.spokeclusters, 'spokeclusters')

        return

    def update_vpnlinks_cache(self):
        logger.debug("update_vpnlinks_cache function")
        if self.vpnlinks_cache is None or self.vpnlinks_newest is None:
            # no cache data, get full dump
            self.vpnlinks_cache, self.vpnlinks_newest = self.iterate_sdk_query(
                self.sdk.post.vpnlinks_query,
                QUERY_ALL,
                'vpnlinks')
        else:
            # update called and we already have a cache, pull new only
            updated_vpnlinks_cache, updated_vpnlinks_newest = self.iterate_sdk_query(
                self.sdk.post.vpnlinks_query,
                query_newer_than(self.vpnlinks_newest),
                'vpnlinks')
            # update vpnlinks cache, if needed
            if len(updated_vpnlinks_cache) > 0:
                self.vpnlinks_cache = update_cache_bykey(self.vpnlinks_cache, updated_vpnlinks_cache,
                                                         key='id')

            if updated_vpnlinks_newest > self.vpnlinks_newest:
                self.vpnlinks_newest = updated_vpnlinks_newest

        return

    def update_anynets_cache(self):
        # Non delta caching function
        logger.debug("update_anynets_cache function")
        self.anynets_cache, self.anynets_newest = self.extract_links(self.sdk.post.topology({"stub_links": "True",
                                                                                             "type": "anynet",
                                                                                             "links_only": False}))

    def update_localprefixfilters_cache(self):
        logger.debug("update_localprefixfilters_cache function")
        if self.localprefixfilters_cache is None or self.localprefixfilters_newest is None:
            # no cache data, get full dump
            self.localprefixfilters_cache, self.localprefixfilters_newest = self.iterate_sdk_query(
                self.sdk.post.localprefixfilters_query,
                QUERY_ALL,
                'localprefixfilters')
        else:
            # update called and we already have a cache, pull new only
            updated_localprefixfilters_cache, updated_localprefixfilters_newest = self.iterate_sdk_query(
                self.sdk.post.localprefixfilters_query,
                query_newer_than(self.localprefixfilters_newest),
                'localprefixfilters')
            # update localprefixfilters cache, if needed
            if len(updated_localprefixfilters_cache) > 0:
                self.localprefixfilters_cache = update_cache_bykey(self.localprefixfilters_cache,
                                                                   updated_localprefixfilters_cache, key='id')

            if updated_localprefixfilters_newest > self.localprefixfilters_newest:
                self.localprefixfilters_newest = updated_localprefixfilters_newest

        return

    def update_globalprefixfilters_cache(self):
        logger.debug("update_globalprefixfilters_cache function")
        if self.globalprefixfilters_cache is None or self.globalprefixfilters_newest is None:
            # no cache data, get full dump
            self.globalprefixfilters_cache, self.globalprefixfilters_newest = self.iterate_sdk_query(
                self.sdk.post.globalprefixfilters_query,
                QUERY_ALL,
                'globalprefixfilters')
        else:
            # update called and we already have a cache, pull new only
            updated_globalprefixfilters_cache, updated_globalprefixfilters_newest = self.iterate_sdk_query(
                self.sdk.post.globalprefixfilters_query,
                query_newer_than(self.globalprefixfilters_newest),
                'globalprefixfilters')
            # update globalprefixfilters cache, if needed
            if len(updated_globalprefixfilters_cache) > 0:
                self.globalprefixfilters_cache = update_cache_bykey(self.globalprefixfilters_cache,
                                                                    updated_globalprefixfilters_cache,
                                                                    key='id')

            if updated_globalprefixfilters_newest > self.globalprefixfilters_newest:
                self.globalprefixfilters_newest = updated_globalprefixfilters_newest

        return

    ######################################################
    #
    # Begin Lookup Map (x to y dict) section.
    #
    ######################################################

    def generate_sites_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                           update_cache=True):
        """
        Generate a sites lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current sites info.
        if update_cache:
            self.update_sites_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.sites_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_elements_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                              update_cache=True):
        """
        Generate a elements lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current elements info.
        if update_cache:
            self.update_elements_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.elements_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_machines_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                              update_cache=True):
        """
        Generate a machines lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current machines info.
        if update_cache:
            self.update_machines_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.machines_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_policysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                update_cache=True):
        """
        Generate a policysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current policysets info.
        if update_cache:
            self.update_policysets_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.policysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_securitypolicysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a securitypolicysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current securitypolicysets info.
        if update_cache:
            self.update_securitypolicysets_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.securitypolicysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_securityzones_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                   update_cache=True):
        """
        Generate a securityzones lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current securityzones info.
        if update_cache:
            self.update_securityzones_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.securityzones_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_networkpolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                            update_cache=True):
        """
        Generate a networkpolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current networkpolicysetstacks info.
        if update_cache:
            self.update_networkpolicysetstacks_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.networkpolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_networkpolicysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                       update_cache=True):
        """
        Generate a networkpolicysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current networkpolicysets info.
        if update_cache:
            self.update_networkpolicysets_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.networkpolicysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_prioritypolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                             update_cache=True):
        """
        Generate a prioritypolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current prioritypolicysetstacks info.
        if update_cache:
            self.update_prioritypolicysetstacks_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.prioritypolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_prioritypolicysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a prioritypolicysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current prioritypolicysets info.
        if update_cache:
            self.update_prioritypolicysets_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.prioritypolicysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_waninterfacelabels_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a waninterfacelabels lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current waninterfacelabels info.
        if update_cache:
            self.update_waninterfacelabels_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.waninterfacelabels_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_wannetworks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                 update_cache=True):
        """
        Generate a wannetworks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current wannetworks info.
        if update_cache:
            self.update_wannetworks_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.wannetworks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_wanoverlays_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                 update_cache=True):
        """
        Generate a wanoverlays lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current wanoverlays info.
        if update_cache:
            self.update_wanoverlays_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.wanoverlays_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_servicebindingmaps_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a servicebindingmaps lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current servicebindingmaps info.
        if update_cache:
            self.update_servicebindingmaps_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.servicebindingmaps_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_serviceendpoints_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                      update_cache=True):
        """
        Generate a serviceendpoints lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current serviceendpoints info.
        if update_cache:
            self.update_serviceendpoints_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.serviceendpoints_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_ipsecprofiles_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                   update_cache=True):
        """
        Generate a ipsecprofiles lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current ipsecprofiles info.
        if update_cache:
            self.update_ipsecprofiles_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.ipsecprofiles_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_networkcontexts_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                     update_cache=True):
        """
        Generate a networkcontexts lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current networkcontexts info.
        if update_cache:
            self.update_networkcontexts_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.networkcontexts_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_appdefs_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                             update_cache=True):
        """
        Generate a appdefs lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current appdefs info.
        if update_cache:
            self.update_appdefs_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.appdefs_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natglobalprefixes_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                       update_cache=True):
        """
        Generate a natglobalprefixes lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natglobalprefixes info.
        if update_cache:
            self.update_natglobalprefixes_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natglobalprefixes_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natlocalprefixes_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                      update_cache=True):
        """
        Generate a natlocalprefixes lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natlocalprefixes info.
        if update_cache:
            self.update_natlocalprefixes_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natlocalprefixes_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natpolicypools_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                    update_cache=True):
        """
        Generate a natpolicypools lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natpolicypools info.
        if update_cache:
            self.update_natpolicypools_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natpolicypools_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natpolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a natpolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natpolicysetstacks info.
        if update_cache:
            self.update_natpolicysetstacks_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natpolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natpolicysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                   update_cache=True):
        """
        Generate a natpolicysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natpolicysets info.
        if update_cache:
            self.update_natpolicysets_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natpolicysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natzones_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                              update_cache=True):
        """
        Generate a natzones lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natzones info.
        if update_cache:
            self.update_natzones_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natzones_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_tenant_operators_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                      update_cache=True):
        """
        Generate a tenant_operators lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current tenant_operators info.
        if update_cache:
            self.update_tenant_operators_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.tenant_operators_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_topology_map(self, key_val='path_id', value_val='name', force_nag=False, nag_cache=None,
                              update_cache=True):
        """
        Generate a topology lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current topology info.
        if update_cache:
            self.update_topology_cache()

        # Prep to dedupe links by ID
        used_id_list = []

        # We need to create some computed name objects. Lets run through the cache and make new entries.
        special_topology_cache = []
        # we also need sites and elements id->name map here
        sites_id2n = self.generate_sites_map()
        elements_id2n = self.generate_elements_map()

        # Iterate entries to add idnamev1 and idnamev2 entries, and remove duplicate path IDs.
        for path in self.topology_cache:
            # ensure deepcopy to dereference items
            updated_path = deepcopy(path)
            path_type = path.get('type')
            path_id = path.get('path_id')
            if path_id not in used_id_list:
                # new path
                if path_type in ["anynet", "public-anynet", "private-anynet"]:
                    # anynet link, get relevant names
                    source_site_name = path.get("source_site_name")
                    target_site_name = path.get("target_site_name")
                    source_wan_network = path.get("source_wan_network")
                    target_wan_network = path.get("target_wan_network")
                    source_circuit_name = path.get("source_circuit_name")
                    target_circuit_name = path.get("target_circuit_name")
                    # circuit names may be blank. Normalize.
                    if not source_circuit_name:
                        source_circuit_name = "Circuit to {0}".format(source_wan_network)
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(target_wan_network)
                    idnamev1_text = "{0} ('{1}' via '{2}') <-> ('{3}' via '{4}') {5}".format(
                        source_site_name,
                        source_wan_network,
                        source_circuit_name,
                        target_circuit_name,
                        target_wan_network,
                        target_site_name
                    )
                    idnamev2_text = "{0}:{1} - {2}:{3}".format(
                        source_site_name,
                        source_circuit_name,
                        target_circuit_name,
                        target_site_name
                    )
                    updated_path['idnamev1'] = idnamev1_text
                    updated_path['idnamev2'] = idnamev2_text

                elif path_type in ["vpn"]:
                    # vpn link, get relevant names
                    source_site_name = path.get("source_site_name")
                    target_site_name = path.get("target_site_name")
                    source_wan_network = path.get("source_wan_network")
                    target_wan_network = path.get("target_wan_network")
                    source_circuit_name = path.get("source_circuit_name")
                    target_circuit_name = path.get("target_circuit_name")
                    # circuit names may be blank. Normalize.
                    if not source_circuit_name:
                        source_circuit_name = "Circuit to {0}".format(source_wan_network)
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(target_wan_network)
                    # for vpn, get element names.
                    source_node_id = path.get("source_node_id")
                    source_element_name = elements_id2n.get(source_node_id)
                    target_node_id = path.get("target_node_id")
                    target_element_name = elements_id2n.get(target_node_id)

                    idnamev1_text = "[{0}] : {1} ('{2}' via '{3}') <-> ('{4}' via '{5}') {6} [{7}]".format(
                        source_element_name,
                        source_site_name,
                        source_wan_network,
                        source_circuit_name,
                        target_circuit_name,
                        target_wan_network,
                        target_site_name,
                        target_element_name
                    )
                    idnamev2_text = "{0}:{1} - {2}:{3}".format(
                        source_element_name,
                        source_circuit_name,
                        target_circuit_name,
                        target_element_name
                    )
                    updated_path['idnamev1'] = idnamev1_text
                    updated_path['idnamev2'] = idnamev2_text

                elif path_type in ["priv-wan-stub", "internet-stub"]:
                    # Stub (direct) links.
                    target_site_name = sites_id2n.get(path.get("target_node_id", ""))
                    if not target_site_name:
                        target_site_name = "UNKNOWN"

                    target_circuit_name = path.get("target_circuit_name")
                    network = path.get("network")
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(network)

                    if path_type == "priv-wan-stub":
                        dest_name = "Direct Private WAN"
                    elif path_type == "internet-stub":
                        dest_name = "Direct Internet"
                    else:
                        dest_name = "UNKNOWN"

                    idnamev1_text = "{0} ('{1}' via '{2}') <-> {3}".format(
                        target_site_name,
                        network,
                        target_circuit_name,
                        dest_name
                    )
                    idnamev2_text = "{0}:{1} - {2}".format(
                        target_site_name,
                        target_circuit_name,
                        dest_name
                    )
                    updated_path['idnamev1'] = idnamev1_text
                    updated_path['idnamev2'] = idnamev2_text

                # add the changes.
                used_id_list.append(path_id)
                special_topology_cache.append(updated_path)
            else:
                # duplicate path ID
                pass

        # use the special cache instead of the normal one
        return self.sdk.build_lookup_dict(special_topology_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_anynets_map(self, key_val='path_id', value_val='name', force_nag=False, nag_cache=None,
                             update_cache=True):
        """
        Generate a anynet lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current topology info.
        if update_cache:
            self.update_anynets_cache()

        # Prep to dedupe links by ID
        used_id_list = []

        # We need to create some computed name objects. Lets run through the cache and make new entries.
        special_anynets_cache = []
        # we also need sites id->name map here
        sites_id2n = self.generate_sites_map()

        # Iterate entries to add idnamev1 and idnamev2 entries, and remove duplicate path IDs.
        for path in self.anynets_cache:
            # ensure deepcopy to dereference items
            updated_path = deepcopy(path)
            path_type = path.get('type')
            path_id = path.get('path_id')
            if path_id not in used_id_list:
                # new path
                if path_type in ["anynet", "public-anynet", "private-anynet"]:
                    # anynet link, get relevant names
                    source_site_name = path.get("source_site_name")
                    target_site_name = path.get("target_site_name")
                    source_wan_network = path.get("source_wan_network")
                    target_wan_network = path.get("target_wan_network")
                    source_circuit_name = path.get("source_circuit_name")
                    target_circuit_name = path.get("target_circuit_name")
                    # circuit names may be blank. Normalize.
                    if not source_circuit_name:
                        source_circuit_name = "Circuit to {0}".format(source_wan_network)
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(target_wan_network)
                    idnamev1_text = "{0} ('{1}' via '{2}') <-> ('{3}' via '{4}') {5}".format(
                        source_site_name,
                        source_wan_network,
                        source_circuit_name,
                        target_circuit_name,
                        target_wan_network,
                        target_site_name
                    )
                    idnamev2_text = "{0}:{1} - {2}:{3}".format(
                        source_site_name,
                        source_circuit_name,
                        target_circuit_name,
                        target_site_name
                    )
                    updated_path['idnamev1'] = idnamev1_text
                    updated_path['idnamev2'] = idnamev2_text

                elif path_type in ["priv-wan-stub", "internet-stub"]:
                    # Stub (direct) links.
                    target_site_name = sites_id2n.get(path.get("target_node_id", ""))
                    if not target_site_name:
                        target_site_name = "UNKNOWN"

                    target_circuit_name = path.get("target_circuit_name")
                    network = path.get("network")
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(network)

                    if path_type == "priv-wan-stub":
                        dest_name = "Direct Private WAN"
                    elif path_type == "internet-stub":
                        dest_name = "Direct Internet"
                    else:
                        dest_name = "UNKNOWN"

                    idnamev1_text = "{0} ('{1}' via '{2}') <-> {3}".format(
                        target_site_name,
                        network,
                        target_circuit_name,
                        dest_name
                    )
                    idnamev2_text = "{0}:{1} - {2}".format(
                        target_site_name,
                        target_circuit_name,
                        dest_name
                    )
                    updated_path['idnamev1'] = idnamev1_text
                    updated_path['idnamev2'] = idnamev2_text

                # add the changes.
                used_id_list.append(path_id)
                special_anynets_cache.append(updated_path)
            else:
                # duplicate path ID
                pass

        # use the special cache instead of the normal one
        return self.sdk.build_lookup_dict(special_anynets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_interfaces_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                update_cache=True):
        """
        Generate a interfaces lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current interfaces info.
        if update_cache:
            self.update_interfaces_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.interfaces_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_waninterfaces_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                   update_cache=True):
        """
        Generate a waninterfaces lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current waninterfaces info.
        if update_cache:
            self.update_waninterfaces_cache()

        # if using name, waninterfaces can have blank name, which UI normalizes to "Circuit to <wannetwork>". Do that
        # here as well.
        if key_val == 'name' or value_val == 'name':
            # ok, we have to do translation :(
            # ensure we have a wannetwork id to name map, which will also update the wannetwork cache.
            wannetwork_id2n = self.generate_wannetworks_map()
            name_fixed_waninterfaces_cache = []
            for waninterface in self.waninterfaces_cache:
                waninterface_name = waninterface.get('name')
                if not waninterface_name:
                    waninterface_network_id = waninterface.get('network_id')
                    patched_waninterface = dict(waninterface)
                    if waninterface_network_id is not None:
                        # lets make a name.
                        patched_waninterface['name'] = "Circuit to {0}" \
                                                       "".format(wannetwork_id2n.get(waninterface_network_id,
                                                                                     waninterface_network_id))

                    else:
                        # No network_id, something is broken.
                        patched_waninterface['name'] = "Circuit to UNKNOWN (No network_id present)"

                    # update the fixed cache
                    name_fixed_waninterfaces_cache.append(patched_waninterface)

                else:
                    # this waninterface has a name. Add it, and move on.
                    name_fixed_waninterfaces_cache.append(waninterface)

            # ok, now that we are fixed, return map using fixed cache.
            return self.sdk.build_lookup_dict(name_fixed_waninterfaces_cache,
                                              key_val=key_val,
                                              value_val=value_val,
                                              force_nag=force_nag,
                                              nag_cache=already_nagged_dup_keys)

        # If we got here, we are not using name key or val, just return the requested dict
        return self.sdk.build_lookup_dict(self.waninterfaces_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_lannetworks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                 update_cache=True):
        """
        Generate a lannetworks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current lannetworks info.
        if update_cache:
            self.update_lannetworks_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.lannetworks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_spokeclusters_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                   update_cache=True):
        """
        Generate a spokeclusters lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current spokeclusters info.
        if update_cache:
            self.update_spokeclusters_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.spokeclusters_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_localprefixfilters_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                        update_cache=True):
        """
        Generate a localprefixfilters lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current localprefixfilters info.
        if update_cache:
            self.update_localprefixfilters_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.localprefixfilters_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_globalprefixfilters_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None,
                                         update_cache=True):
        """
        Generate a globalprefixfilters lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.
        :param update_cache: Bool, if False, skip cache update.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current globalprefixfilters info.
        if update_cache:
            self.update_globalprefixfilters_cache()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.globalprefixfilters_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    ######################################################
    #
    # Begin Class Helper functions section
    #
    ######################################################

    def extract_links(self, resp_object, error_label=None, pass_code_list=None):
        """
        Extract list of links from a CloudGenix API Response object.
        """

        if pass_code_list is None:
            pass_code_list = [404, 400]

        links = resp_object.cgx_content.get('links')

        if resp_object.cgx_status and links is not None:
            # get newest link
            latest_timestamp = max([entry["_updated_on_utc"] for entry in links
                                   if entry.get("_updated_on_utc") and
                                   isinstance(entry.get("_updated_on_utc"), int)],
                                   default=0)
            return links, latest_timestamp

        # handle 404 and other error codes for certain APIs where objects may not exist
        elif resp_object.status_code in pass_code_list:
            return [{}], 0

        else:
            if error_label is not None:
                self.sdk.throw_error("Unable to extract links from {0}.".format(error_label), resp_object)
                return [{}], 0
            else:
                self.sdk.throw_error("Unable to extract links from response.".format(error_label), resp_object)
                return [{}], 0

    def iterate_sdk_get(self, sdk_function, error_label=None):
        logger.debug("iterate_sdk_get function:")
        resp = sdk_function()
        try:
            current_items = self.sdk.extract_items(resp, error_label=error_label)
        except CloudGenixAPIError as e:
            # change API error to warning.
            self.throw_warning(str(e))
            # return empty list and 0 last update timestamp.
            return [], 0

        current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                       if entry.get("_updated_on_utc") and
                                       isinstance(entry.get("_updated_on_utc"), int)],
                                       default=0)
        return current_items, current_latest_timestamp

    def iterate_sdk_get_bysite(self, sdk_function, error_label=None, data=None, extract="items"):
        # This function is to work around CGB-15184, and lack of topology query TODO remove when fixed.
        logger.debug("interate_sdk_get_bysite function:")
        # make sure sites list is current.
        self.update_sites_cache()
        # extract all site IDs
        site_id_list = [entry['id'] for entry in self.sites_cache if entry.get('id')]
        response_items = []
        response_latest_timestamp = 0
        for site_id in site_id_list:

            if data is not None:
                resp = sdk_function(data=data.format(site_id))
            else:
                resp = sdk_function(site_id)

            if extract == "links":
                current_items, current_latest_timestamp = self.extract_links(resp, error_label=error_label)
            else:
                current_items = self.sdk.extract_items(resp, error_label=error_label)
                current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                               if entry.get("_updated_on_utc") and
                                               isinstance(entry.get("_updated_on_utc"), int)],
                                               default=0)
            # Extend the response
            response_items.extend(current_items)
            # update latest timestamp
            if current_latest_timestamp > response_latest_timestamp:
                response_latest_timestamp = current_latest_timestamp

        return response_items, response_latest_timestamp

    def iterate_sdk_get_byelement(self, sdk_function, error_label=None, data=None):
        # This function is just to work around lack of query api for certian APIs.
        logger.debug("interate_sdk_get_byelement function:")
        # make sure elements list is current.

        self.update_elements_cache()

        # extract all element and site IDs
        element_site_id_list = [(entry['id'], entry['site_id']) for entry in self.elements_cache if entry.get('id') and
                                entry.get('site_id')]
        response_items = []
        response_latest_timestamp = 0

        for element_id, site_id in element_site_id_list:

            if data is not None:
                resp = sdk_function(site_id, element_id, data)
            else:
                resp = sdk_function(site_id, element_id)

            current_items = self.sdk.extract_items(resp, error_label=error_label)
            current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                           if entry.get("_updated_on_utc") and
                                           isinstance(entry.get("_updated_on_utc"), int)],
                                           default=0)
            # Extend the response
            response_items.extend(current_items)
            # update latest timestamp
            if current_latest_timestamp > response_latest_timestamp:
                response_latest_timestamp = current_latest_timestamp

        return response_items, response_latest_timestamp

    def iterate_sdk_query(self, sdk_function, query_dict, error_label=None):
        """

        :param sdk_function:
        :param query_dict:
        :param error_label:
        :return:
        """
        logger.debug("iterate_sdk_query function:")
        # query should be dict, make shallow copy
        local_query_dict = dict(query_dict)
        results_list = []
        next_page = 1
        resp = sdk_function(local_query_dict)
        total_count = resp.cgx_content.get('total_count')
        current_items = self.sdk.extract_items(resp, error_label=error_label)
        results_list.extend(current_items)
        # get the latest "_updated_on_utc" from current_items
        current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                       if entry.get("_updated_on_utc") and
                                       isinstance(entry.get("_updated_on_utc"), int)],
                                       default=0)
        results_newest = current_latest_timestamp
        # iterate and make queries
        while len(current_items) != 0:
            debug_str = "NEXT_PAGE: {0}: ".format(next_page)
            next_page += 1
            local_query_dict['dest_page'] = next_page
            next_resp = sdk_function(local_query_dict)
            current_items = self.sdk.extract_items(next_resp, error_label=error_label)
            results_list.extend(current_items)
            results_pct = len(results_list) / int(total_count) * 100
            debug_str += "+{0}, {1} out of {2}({3}).".format(len(current_items), len(results_list), total_count,
                                                             results_pct)
            logger.debug(debug_str)
            # get the latest "_updated_on_utc" from current_items
            current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                           if entry.get("_updated_on_utc") and
                                           isinstance(entry.get("_updated_on_utc"), int)],
                                           default=0)
            if results_newest < current_latest_timestamp:
                results_newest = current_latest_timestamp
            # if there are current items, should continue to loop. Otherwise exit.
        # return a tuple of both list of items and the newest timestamp
        return results_list, results_newest

    @staticmethod
    def throw_warning(message, resp=None, cr=True):
        """
        Recoverable Warning.

        """
        output = "WARNING: " + str(message)
        if cr:
            output += "\n"
        sys.stderr.write(output)
        if resp is not None:
            output2 = str(jdout_detailed(resp))
            if cr:
                output2 += "\n"
            sys.stderr.write(output2)
        return

######################################################
#
# Begin Global Helper functions section
#
######################################################


def update_cache_bykey(cache_list, new_list, key='id'):
    """
    Given a cache list of dicts, update the cache with a 2nd list of dicts by a specific key in the dict.
    :param cache_list: List of dicts
    :param new_list: New list of dicts to update by
    :param key: Optional, key to use as the identifier to update new entries with
    :return: Updated list of dicts
    """
    # create a cache dict keyed by id.
    cache_bykey = {entry[key]: entry for entry in cache_list if entry.get(key)}
    # create a new dict keyed by id.
    new_bykey = {entry[key]: entry for entry in new_list if entry.get(key)}
    # combine and update cache into a 3rd dict
    combined_bykey = {**cache_bykey, **new_bykey}
    # return a list of the updated dict.
    return [value for key, value in combined_bykey.items()]


def query_newer_than(timestamp):
    """
    Return a query string for later than "timestamp"
    :param timestamp: CloudGenix timestamp
    :return: Dictionary of the query
    """
    return {
        "query_params": {
            "_updated_on_utc": {
                "gt": timestamp
            }
        },
        "sort_params": {
            "id": "desc"
        }
    }


######################################################
#
# Begin Backwards compatibility section.
#   These are the old 1.2 idname functions. We'll
#   silently use the new 2.0 method for increased
#   performance.
#
######################################################

# For old cloudgenix-idname functions, lets set a global instance of the class. We'll update it with an
# Authenticated SDK on each call.
global_idname = CloudGenixIDName(None)


def operators_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    operators_id2n = global_idname.generate_tenant_operators_map()
    operators_n2id = global_idname.generate_tenant_operators_map(key_val='name', value_val='id', update_cache=False)
    operators_id2email = global_idname.generate_tenant_operators_map(key_val='id', value_val='email',
                                                                     update_cache=False)
    operators_email2id = global_idname.generate_tenant_operators_map(key_val='email', value_val='id',
                                                                     update_cache=False)

    # for operators, name is the preferred name over email. Update name dicts over email to overwrite.
    xlate_id2n = operators_id2email
    xlate_n2id = operators_email2id
    xlate_id2n.update(operators_id2n)
    xlate_n2id.update(operators_n2id)

    return xlate_id2n, xlate_n2id


def siteid_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_sites_map()
    xlate_n2id = global_idname.generate_sites_map(key_val='name', value_val='id', update_cache=False)

    # create an id list and id to site object map to return. Use the updated sites cache.
    id_list = []
    id_info_dict = {}
    for site in global_idname.sites_cache:
        s_id = site.get('id')
        if s_id:
            id_list.append(s_id)
            id_info_dict[s_id] = site

    return xlate_id2n, xlate_n2id, id_list, id_info_dict


def elements_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_elements_map()
    xlate_n2id = global_idname.generate_elements_map(key_val='name', value_val='id', update_cache=False)

    # create an id list and id to site object map to return. Use the updated elements cache.
    id_list = []
    site_xlate_dict = {}
    for element in global_idname.elements_cache:
        e_id = element.get('id')
        site = element.get('site_id')

        if e_id:
            id_list.append(e_id)

        if site and e_id:
            site_xlate_dict[e_id] = site

    return xlate_id2n, xlate_n2id, site_xlate_dict, id_list


def securityzone_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_securityzones_map()
    xlate_n2id = global_idname.generate_securityzones_map(key_val='name', value_val='id', update_cache=False)

    # create an id list to return. Use the updated securityzones cache.
    id_list = []

    for securityzone in global_idname.securityzones_cache:
        sz_id = securityzone.get('id')

        if sz_id:
            id_list.append(sz_id)

    return xlate_id2n, xlate_n2id, id_list


def interface_query(site_id, element_id, sdk):

    # Leaving this function intact. 2.0 idname gets all interfaces at once without iterating.
    # This function may be more efficient for single-element maps.

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

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_wannetworks_map()
    xlate_n2id = global_idname.generate_wannetworks_map(key_val='name', value_val='id', update_cache=False)
    xlate_id2t = global_idname.generate_wannetworks_map(key_val='id', value_val='type', update_cache=False)

    id_list = []
    # create an id list to return. Use the updated wannetworks cache.

    for wannetwork in global_idname.wannetworks_cache:
        wn_id = wannetwork.get('id')

        if wn_id:
            id_list.append(wn_id)

    return xlate_id2n, xlate_n2id, id_list, xlate_id2t


def circuit_categories_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_waninterfacelabels_map()
    xlate_n2id = global_idname.generate_waninterfacelabels_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def network_context_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_networkcontexts_map()
    xlate_n2id = global_idname.generate_networkcontexts_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def appdefs_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_appdefs_map()
    xlate_n2id = global_idname.generate_appdefs_map(key_val='display_name', value_val='id', update_cache=False)

    id_list = []
    # create an id list to return. Use the updated appdefs cache.
    for appdef in global_idname.appdefs_cache:
        app_id = appdef.get('id')

        if app_id:
            id_list.append(app_id)

    return xlate_id2n, xlate_n2id, id_list


def natglobalprefixes_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_networkpolicysetstacks_map()
    xlate_n2id = global_idname.generate_networkpolicysetstacks_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def natlocalprefixes_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_natlocalprefixes_map()
    xlate_n2id = global_idname.generate_natlocalprefixes_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def natpolicypools_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_natpolicypools_map()
    xlate_n2id = global_idname.generate_natpolicypools_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def natpolicysetstacks_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_natpolicysetstacks_map()
    xlate_n2id = global_idname.generate_natpolicysetstacks_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def natpolicysets_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_natpolicysets_map()
    xlate_n2id = global_idname.generate_natpolicysets_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def natzones_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_natzones_map()
    xlate_n2id = global_idname.generate_natzones_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def policyset_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_policysets_map()
    xlate_n2id = global_idname.generate_policysets_map(key_val='display_name', value_val='id', update_cache=False)

    id_list = []
    # create an id list to return. Use the updated policysets cache.
    for policyset in global_idname.policysets_cache:
        obj_id = policyset.get('id')

        if obj_id:
            id_list.append(obj_id)

    return xlate_id2n, xlate_n2id, id_list


def networkpolicysetstacks_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_networkpolicysetstacks_map()
    xlate_n2id = global_idname.generate_networkpolicysetstacks_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def networkpolicysets_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_networkpolicysets_map()
    xlate_n2id = global_idname.generate_networkpolicysets_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def prioritypolicysetstacks_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_prioritypolicysetstacks_map()
    xlate_n2id = global_idname.generate_prioritypolicysetstacks_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def prioritypolicysets_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_prioritypolicysets_map()
    xlate_n2id = global_idname.generate_prioritypolicysets_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def securitypolicyset_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_securitypolicysets_map()
    xlate_n2id = global_idname.generate_securitypolicysets_map(key_val='display_name', value_val='id',
                                                               update_cache=False)

    id_list = []
    # create an id list to return. Use the updated securitypolicysets cache.
    for securitypolicyset in global_idname.securitypolicysets_cache:
        obj_id = securitypolicyset.get('id')

        if obj_id:
            id_list.append(obj_id)

    return xlate_id2n, xlate_n2id, id_list


def spokeclusters_to_name_dict(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_spokeclusters_map()
    xlate_n2id = global_idname.generate_spokeclusters_map(key_val='display_name', value_val='id', update_cache=False)

    id_list = []
    # create an id list to return. Use the updated spokeclusters cache.
    for spokecluster in global_idname.spokeclusters_cache:
        obj_id = spokecluster.get('id')

        if obj_id:
            id_list.append(obj_id)

    return xlate_id2n, xlate_n2id, id_list


def all_interface_dicts(sdk, pretty=False):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, lots of duplicates with the reverse.
    xlate_id2n = global_idname.generate_interfaces_map()
    # check if want pretty print
    if pretty:
        xlate_p_id2n = {k: "Interface {0}".format(v) for k, v in xlate_id2n.items()}
        return xlate_p_id2n
    else:
        return xlate_id2n


def lannetwork_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_lannetworks_map()
    xlate_n2id = global_idname.generate_lannetworks_map(key_val='name', value_val='id', update_cache=False)

    return xlate_id2n, xlate_n2id


def waninterface_dicts(sdk):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_waninterfaces_map()
    wannetworks_id2n = global_idname.generate_wannetworks_map()

    for waninterface in global_idname.waninterfaces_cache:
        obj_id = waninterface.get('id')
        obj_name = waninterface.get('name')
        obj_wannetwork_id = waninterface.get('network_id')

        # check for missing name.
        if not obj_name:
            # do UI name normalization for nameless SWIs
            xlate_id2n[obj_id] = "Circuit to {0}".format(wannetworks_id2n.get(obj_wannetwork_id, obj_wannetwork_id))

    return xlate_id2n


def anynet_dicts(sdk, pretty="idnamev2"):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, name to id, and other dicts
    xlate_id2n = global_idname.generate_anynets_map(value_val=pretty)
    xlate_n2id = global_idname.generate_anynets_map(key_val=pretty, value_val='path_id', update_cache=False)

    return xlate_id2n, xlate_n2id


def topology_dicts(sdk, pretty="idnamev2"):

    # Set the constructor to the just-provided SDK
    global_idname.sdk = sdk

    # get id to name, can't do reverse.
    xlate_id2n = global_idname.generate_topology_map(value_val=pretty)

    return xlate_id2n


def generate_id_name_map(sdk, reverse=False, idnamev1=True):
    """
    Generate the ID-NAME map dict
    :param sdk: CloudGenix API constructor
    :param reverse: Generate reverse name-> ID map as well, return tuple with both.
    :param idnamev1: Generate topology names in idnamev1 format.
    :return: ID Name dictionary
    """

    global_id_name_dict = {}
    global_name_id_dict = {}

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

    logger.info("Caching Networkpolicysetstacks..")
    id_networkpolicysetstack_dict, name_networkpolicysetstack_dict = \
        networkpolicysetstacks_dicts(sdk)
    global_id_name_dict.update(id_networkpolicysetstack_dict)
    global_name_id_dict.update(name_networkpolicysetstack_dict)

    logger.info("Caching Networkpolicysets..")
    id_networkpolicyset_dict, name_networkpolicyset_dict = \
        networkpolicysets_dicts(sdk)
    global_id_name_dict.update(id_networkpolicyset_dict)
    global_name_id_dict.update(name_networkpolicyset_dict)

    logger.info("Caching Prioritypolicysetstacks..")
    id_prioritypolicysetstack_dict, name_prioritypolicysetstack_dict = \
        prioritypolicysetstacks_dicts(sdk)
    global_id_name_dict.update(id_prioritypolicysetstack_dict)
    global_name_id_dict.update(name_prioritypolicysetstack_dict)

    logger.info("Caching Prioritypolicysets..")
    id_prioritypolicyset_dict, name_prioritypolicyset_dict = \
        prioritypolicysets_dicts(sdk)
    global_id_name_dict.update(id_prioritypolicyset_dict)
    global_name_id_dict.update(name_prioritypolicyset_dict)

    logger.info("Caching Natglobalprefixs..")
    id_natglobalprefix_dict, name_natglobalprefix_dict = \
        natglobalprefixes_dicts(sdk)
    global_id_name_dict.update(id_natglobalprefix_dict)
    global_name_id_dict.update(name_natglobalprefix_dict)

    logger.info("Caching Natlocalprefixs..")
    id_natlocalprefix_dict, name_natlocalprefix_dict = \
        natlocalprefixes_dicts(sdk)
    global_id_name_dict.update(id_natlocalprefix_dict)
    global_name_id_dict.update(name_natlocalprefix_dict)

    logger.info("Caching Natpolicypools..")
    id_natpolicypool_dict, name_natpolicypool_dict = \
        natpolicypools_dicts(sdk)
    global_id_name_dict.update(id_natpolicypool_dict)
    global_name_id_dict.update(name_natpolicypool_dict)

    logger.info("Caching Natpolicysetstacks..")
    id_natpolicysetstack_dict, name_natpolicysetstack_dict = \
        natpolicysetstacks_dicts(sdk)
    global_id_name_dict.update(id_natpolicysetstack_dict)
    global_name_id_dict.update(name_natpolicysetstack_dict)

    logger.info("Caching Natpolicysets..")
    id_natpolicyset_dict, name_natpolicyset_dict = \
        natpolicysets_dicts(sdk)
    global_id_name_dict.update(id_natpolicyset_dict)
    global_name_id_dict.update(name_natpolicyset_dict)

    logger.info("Caching Natzones..")
    id_natzone_dict, name_natzone_dict = \
        natzones_dicts(sdk)
    global_id_name_dict.update(id_natzone_dict)
    global_name_id_dict.update(name_natzone_dict)

    logger.info("Caching Security Policysets..")
    id_securitypolicyset_dict, name_securitypolicyset_dict, \
        securitypolicyset_id_list = securitypolicyset_to_name_dict(sdk)
    global_id_name_dict.update(id_securitypolicyset_dict)
    global_name_id_dict.update(name_securitypolicyset_dict)

    logger.info("Caching Security Zones..")
    id_securityzone_dict, securityzone_id_dict, securityzone_id_list = securityzone_to_name_dict(sdk)
    global_id_name_dict.update(id_securityzone_dict)
    global_name_id_dict.update(securityzone_id_dict)

    logger.info("Caching Spoke Clusters..")
    id_spokecluster_dict, spokecluster_id_dict, spokecluster_id_list = spokeclusters_to_name_dict(sdk)
    global_id_name_dict.update(id_spokecluster_dict)
    global_name_id_dict.update(spokecluster_id_dict)

    logger.info("Caching Interfaces..")
    id_interface_dict = all_interface_dicts(sdk, pretty=True)
    global_id_name_dict.update(id_interface_dict)

    logger.info("Caching LAN Networks..")
    id_lannetwork_dict, lannetwork_id_dict = lannetwork_dicts(sdk)
    global_id_name_dict.update(id_lannetwork_dict)
    global_name_id_dict.update(lannetwork_id_dict)

    logger.info("Caching WAN Interfaces..")
    id_waninterface_dict = waninterface_dicts(sdk)
    global_id_name_dict.update(id_waninterface_dict)

    logger.info("Caching Topology..")
    if idnamev1:
        topo_labels = 'idnamev1'
    else:
        topo_labels = 'idnamev2'
    id_topology_dict = topology_dicts(sdk, pretty=topo_labels)
    global_id_name_dict.update(id_topology_dict)

    if reverse:
        # return both id_name and what we can get of name_id.
        return global_id_name_dict, global_name_id_dict

    return global_id_name_dict


def gen(sdk, reverse=False, idnamev1=True):
    """
    Shortcut to generate_id_name_map
    :param sdk: CloudGenix API constructor
    :param reverse: Generate reverse name-> ID map as well, return tuple with both.
    :param idnamev1: Generate topology names in idnamev1 style.
    :return: ID Name dictionary
    """
    return generate_id_name_map(sdk, reverse=reverse, idnamev1=idnamev1)
