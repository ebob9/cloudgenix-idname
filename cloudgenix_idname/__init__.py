"""
ID -> Name Map for CloudGenix Python SDK.

This module takes a API() constructor from the Cloudgenix Python SDK
https://github.com/CloudGenix/sdk-python

And builds an ID keyed name dictionary.

"""
import time
import json
import logging
import cloudgenix

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

role_xlate: dict = {
    'HUB': 'DC',
    'SPOKE': 'Branch'
}

QUERY_ALL = {
    'sort_params': {
        'id': 'desc'
    }
}



class CloudGenixIDName(object):
    """
    Class to generate flexible key -> value maps (not just ID -> Name)
    """
    sdk: cloudgenix.API = None
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
    prioritypolicysetstacks_cache = None
    prioritypolicysetstacks_newest = None
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

    nag_cache = []

    def __init__(self, authenticated_sdk: cloudgenix.API):
        self.sdk = authenticated_sdk

    # update all
    def update_all_caches(self):
        self.sites_cache_update()
        self.elements_cache_update()
        self.machines_cache_update()
        self.policysets_cache_update()
        self.securitypolicysets_cache_update()
        self.securityzones_cache_update()
        self.networkpolicysetstacks_cache_update()
        self.prioritypolicysetstacks_cache_update()
        self.waninterfacelabels_cache_update()
        self.wannetworks_cache_update()
        self.wanoverlays_cache_update()
        self.servicebindingmaps_cache_update()
        self.serviceendpoints_cache_update()
        self.ipsecprofiles_cache_update()
        self.networkcontexts_cache_update()
        self.appdefs_cache_update()
        self.natglobalprefixes_cache_update()
        self.natlocalprefixes_cache_update()
        self.natpolicypools_cache_update()
        self.natpolicysetstacks_cache_update()
        self.natzones_cache_update()
        self.tenant_operators_cache_update()
        self.topology_cache_update()
        self.interfaces_cache_update()
        self.waninterfaces_cache_update()
        self.lannetworks_cache_update()

    ######################################################
    #
    # Begin Individual Object Cache Update functions
    #
    ######################################################

    def sites_cache_update(self):
        logger.debug("sites_cache_update function")
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

    def elements_cache_update(self):
        logger.debug("elements_cache_update function")
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

    def machines_cache_update(self):
        logger.debug("machines_cache_update function")
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

    def policysets_cache_update(self):
        logger.debug("policysets_cache_update function")
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

    def securitypolicysets_cache_update(self):
        logger.debug("securitypolicysets_cache_update function")
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

    def securityzones_cache_update(self):
        logger.debug("securityzones_cache_update function")
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

    def networkpolicysetstacks_cache_update(self):
        logger.debug("networkpolicysetstacks_cache_update function")
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

    def prioritypolicysetstacks_cache_update(self):
        logger.debug("prioritypolicysetstacks_cache_update function")
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

    def waninterfacelabels_cache_update(self):
        logger.debug("waninterfacelabels_cache_update function")
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

    def wannetworks_cache_update(self):
        logger.debug("wannetworks_cache_update function")
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

    def wanoverlays_cache_update(self):
        # wanoverlays has no query API. Full GET only.
        logger.debug("wanoverlays_cache_update function")
        self.wanoverlays_cache, self.wanoverlays_newest = self.iterate_sdk_get(self.sdk.get.wanoverlays,
                                                                               'wanoverlays')
        return

    def servicebindingmaps_cache_update(self):
        logger.debug("servicebindingmaps_cache_update function")
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

    def serviceendpoints_cache_update(self):
        logger.debug("serviceendpoints_cache_update function")
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

    def ipsecprofiles_cache_update(self):
        logger.debug("ipsecprofiles_cache_update function")
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

    def networkcontexts_cache_update(self):
        logger.debug("networkcontexts_cache_update function")
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

    def appdefs_cache_update(self):
        logger.debug("appdefs_cache_update function")
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

    def natglobalprefixes_cache_update(self):
        logger.debug("natglobalprefixes_cache_update function")
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

    def natlocalprefixes_cache_update(self):
        logger.debug("natlocalprefixes_cache_update function")
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

    def natpolicypools_cache_update(self):
        logger.debug("natpolicypools_cache_update function")
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

    def natpolicysetstacks_cache_update(self):
        logger.debug("natpolicysetstacks_cache_update function")
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

    def natzones_cache_update(self):
        logger.debug("natzones_cache_update function")
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

    def tenant_operators_cache_update(self):
        # tenant_operators has no query API. Full GET only.
        logger.debug("tenant_operators_cache_update function")
        self.tenant_operators_cache, self.tenant_operators_newest = self.iterate_sdk_get(self.sdk.get.tenant_operators,
                                                                                         'tenant_operators')
        return

    def topology_cache_update(self):
        self.topology_cache, self.topology_newest = self.extract_links(self.sdk.post.topology({"stub_links": "True",
                                                                                               "type": "anynet",
                                                                                               "links_only": False}))

    def interfaces_cache_update(self):
        logger.debug("interfaces_cache_update function")
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

    def waninterfaces_cache_update(self):
        logger.debug("waninterfaces_cache_update function")
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

    def lannetworks_cache_update(self):
        logger.debug("lannetworks_cache_update function")
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
            #     self.lannetworks_cache = update_cache_bykey(self.lannetworks_cache, updated_lannetworks_cache, key='id')
            #
            # if updated_lannetworks_newest > self.lannetworks_newest:
            #     self.lannetworks_newest = updated_lannetworks_newest
            # Due to CGB-15184, query requires site iteration. Just use get.
            self.lannetworks_cache, self.lannetworks_newest = self.iterate_sdk_get_bysite(
                self.sdk.get.lannetworks, 'lannetworks')

        return

    ######################################################
    #
    # Begin Lookup Map (x to y dict) section.
    #
    ######################################################

    def generate_sites_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a sites lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current sites info.
        self.sites_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.sites_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_elements_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a elements lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current elements info.
        self.elements_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.elements_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_machines_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a machines lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current machines info.
        self.machines_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.machines_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_policysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a policysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current policysets info.
        self.policysets_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.policysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_securitypolicysets_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a securitypolicysets lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current securitypolicysets info.
        self.securitypolicysets_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.securitypolicysets_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_securityzones_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a securityzones lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current securityzones info.
        self.securityzones_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.securityzones_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_networkpolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a networkpolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current networkpolicysetstacks info.
        self.networkpolicysetstacks_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.networkpolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_prioritypolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a prioritypolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current prioritypolicysetstacks info.
        self.prioritypolicysetstacks_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.prioritypolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_waninterfacelabels_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a waninterfacelabels lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current waninterfacelabels info.
        self.waninterfacelabels_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.waninterfacelabels_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_wannetworks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a wannetworks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current wannetworks info.
        self.wannetworks_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.wannetworks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_wanoverlays_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a wanoverlays lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current wanoverlays info.
        self.wanoverlays_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.wanoverlays_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_servicebindingmaps_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a servicebindingmaps lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current servicebindingmaps info.
        self.servicebindingmaps_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.servicebindingmaps_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_serviceendpoints_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a serviceendpoints lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current serviceendpoints info.
        self.serviceendpoints_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.serviceendpoints_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_ipsecprofiles_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a ipsecprofiles lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current ipsecprofiles info.
        self.ipsecprofiles_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.ipsecprofiles_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_networkcontexts_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a networkcontexts lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current networkcontexts info.
        self.networkcontexts_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.networkcontexts_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_appdefs_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a appdefs lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current appdefs info.
        self.appdefs_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.appdefs_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natglobalprefixes_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a natglobalprefixes lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natglobalprefixes info.
        self.natglobalprefixes_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natglobalprefixes_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natlocalprefixes_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a natlocalprefixes lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natlocalprefixes info.
        self.natlocalprefixes_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natlocalprefixes_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natpolicypools_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a natpolicypools lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natpolicypools info.
        self.natpolicypools_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natpolicypools_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natpolicysetstacks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a natpolicysetstacks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natpolicysetstacks info.
        self.natpolicysetstacks_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natpolicysetstacks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_natzones_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a natzones lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current natzones info.
        self.natzones_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.natzones_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_tenant_operators_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a tenant_operators lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current tenant_operators info.
        self.tenant_operators_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.tenant_operators_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_topology_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a topology lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current topology info.
        self.topology_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.topology_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_interfaces_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a interfaces lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current interfaces info.
        self.interfaces_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.interfaces_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    def generate_waninterfaces_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a waninterfaces lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current waninterfaces info.
        self.waninterfaces_cache_update()

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

    def generate_lannetworks_map(self, key_val='id', value_val='name', force_nag=False, nag_cache=None):
        """
        Generate a lannetworks lookup map
        :param key_val: The value from the object that should be the 'key' of the lookup dict
        :param value_val: The value from the object that should be the 'value' of the lookup dict
        :param force_nag: Optional - Bool, if True will nag even if key in `nag_cache`
        :param nag_cache: Optional - List of keys that already exist in a lookup dict that should be duplicate checked.

        :return: The lookup dict.
        """
        if nag_cache and isinstance(nag_cache, list):
            already_nagged_dup_keys = nag_cache
        else:
            already_nagged_dup_keys = []

        # Ensure we have current lannetworks info.
        self.lannetworks_cache_update()

        # return the requested dict
        return self.sdk.build_lookup_dict(self.lannetworks_cache,
                                          key_val=key_val,
                                          value_val=value_val,
                                          force_nag=force_nag,
                                          nag_cache=already_nagged_dup_keys)

    ######################################################
    #
    # Begin Helper functions section
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
        logger.debug("interate_sdk_get function:")
        resp = sdk_function()
        current_items = self.sdk.extract_items(resp, error_label=error_label)
        current_latest_timestamp = max([entry["_updated_on_utc"] for entry in current_items
                                       if entry.get("_updated_on_utc") and
                                       isinstance(entry.get("_updated_on_utc"), int)],
                                       default=0)
        return current_items, current_latest_timestamp

    def iterate_sdk_get_bysite(self, sdk_function, error_label=None):
        # This function is just to work around CGB-15184. TODO remove when fixed.
        logger.debug("interate_sdk_get_bysite function:")
        # make sure sites list is current.
        self.sites_cache_update()
        # extract all site IDs
        site_id_list = [entry['id'] for entry in self.sites_cache if entry.get('id')]
        response_items = []
        response_latest_timestamp = 0
        for site_id in site_id_list:
            resp = sdk_function(site_id)
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
        while len(current_items) is not 0:
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
        return xlate_dict, reverse_xlate_dict, id_list

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


def spokeclusters_to_name_dict(sdk):
    xlate_dict = {}
    reverse_xlate_dict = {}
    id_list = []

    resp = sdk.get.sites()
    sitelist = resp.cgx_content.get("items", None)

    for site in sitelist:
        sid = site['id']

        resp = sdk.get.spokeclusters(site_id = sid)
        spokeclusterlist = resp.cgx_content.get("items", None)

        # build translation dict
        for sc in spokeclusterlist:
            name = sc['name']
            spokecluster_id = sc['id']

            if name and spokecluster_id:
                xlate_dict[spokecluster_id] = name
                reverse_xlate_dict[name] = spokecluster_id

            if spokecluster_id:
                id_list.append(spokecluster_id)

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

    logger.info("Caching Spoke Clusters..")
    id_spokecluster_dict, spokecluster_id_dict, spokecluster_id_list = spokeclusters_to_name_dict(sdk)
    global_id_name_dict.update(id_spokecluster_dict)
    global_name_id_dict.update(spokecluster_id_dict)

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


