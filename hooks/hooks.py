#!/usr/bin/python

#
# Copyright 2012 Canonical Ltd.
#
# Authors:
#  Paul Collins <paul.collins@canonical.com>
#  James Page <james.page@ubuntu.com>
#

import glob
import os
import shutil
import sys
import uuid
import ceph
from charmhelpers.core.hookenv import (
    log,
    config,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    leader_set, leader_get,
    is_leader,
    status_set,
    remote_unit,
    Hooks, UnregisteredHookError,
    service_name
)

from charmhelpers.core.host import (
    service_restart,
    mkdir,
    cmp_pkgrevno
)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
    add_source
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.openstack.alternatives import install_alternative
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr
)

from utils import (
    render_template,
    get_public_addr,
    assert_charm_supports_ipv6
)

hooks = Hooks()


def install_upstart_scripts():
    # Only install upstart configurations for older versions
    if cmp_pkgrevno('ceph', "0.55.1") < 0:
        for x in glob.glob('files/upstart/*.conf'):
            shutil.copy(x, '/etc/init/')


@hooks.hook('install')
def install():
    execd_preinstall()
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    apt_install(packages=ceph.PACKAGES, fatal=True)
    install_upstart_scripts()


def emit_cephconf():
    cephcontext = {
        'auth_supported': config('auth-supported'),
        'mon_hosts': ' '.join(get_mon_hosts()),
        'fsid': leader_get('fsid'),
        'old_auth': cmp_pkgrevno('ceph', "0.51") < 0,
        'osd_journal_size': config('osd-journal-size'),
        'use_syslog': str(config('use-syslog')).lower(),
        'ceph_public_network': config('ceph-public-network'),
        'ceph_cluster_network': config('ceph-cluster-network'),
    }

    if config('prefer-ipv6'):
        dynamic_ipv6_address = get_ipv6_addr()[0]
        if not config('ceph-public-network'):
            cephcontext['public_addr'] = dynamic_ipv6_address
        if not config('ceph-cluster-network'):
            cephcontext['cluster_addr'] = dynamic_ipv6_address

    # Install ceph.conf as an alternative to support
    # co-existence with other charms that write this file
    charm_ceph_conf = "/var/lib/charm/{}/ceph.conf".format(service_name())
    mkdir(os.path.dirname(charm_ceph_conf))
    with open(charm_ceph_conf, 'w') as cephconf:
        cephconf.write(render_template('ceph.conf', cephcontext))
    install_alternative('ceph.conf', '/etc/ceph/ceph.conf',
                        charm_ceph_conf, 100)

JOURNAL_ZAPPED = '/var/lib/ceph/journal_zapped'


@hooks.hook('config-changed')
def config_changed():
    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    log('Monitor hosts are ' + repr(get_mon_hosts()))

    # Pre-flight checks
    if is_leader():
        if not leader_get('fsid') or not leader_get('monitor-secret'):
            status_set('maintenance', 'Creating FSID and Monitor Secret')
            opts = {
                'fsid': "{}".format(uuid.uuid1()),
                'monitor-secret': "{}".format(ceph.generate_monitor_secret()),
            }
            log("Settings for the cluster are: {}".format(opts))
            leader_set(opts)
    else:
        if leader_get('fsid') is None or leader_get('monitor-secret') is None:
            log('still waiting for leader to setup keys')
            status_set('waiting', 'Waiting for leader to setup keys')
            sys.exit(0)
    emit_cephconf()
    status_set('waiting', 'Waiting for mon quorum')


def get_mon_hosts():
    hosts = []
    addr = get_public_addr()
    hosts.append('{}:6789'.format(format_ipv6_addr(addr) or addr))

    for relid in relation_ids('mon'):
        for unit in related_units(relid):
            addr = relation_get('ceph-public-address', unit, relid)
            if addr is not None:
                hosts.append('{}:6789'.format(
                    format_ipv6_addr(addr) or addr))

    hosts.sort()
    return hosts


@hooks.hook('mon-relation-joined')
def mon_relation_joined():
    for relid in relation_ids('mon'):
        relation_set(relation_id=relid,
                     relation_settings={'ceph-public-address':
                                        get_public_addr()})


@hooks.hook('mon-relation-departed',
            'mon-relation-changed')
def mon_relation():
    emit_cephconf()

    moncount = int(config('monitor-count'))
    if len(get_mon_hosts()) >= moncount:
        ceph.bootstrap_monitor_cluster(leader_get('monitor-secret'))
        ceph.wait_for_bootstrap()
        notify_osds()
        notify_radosgws()
        notify_client()
        status_set("active", "Ceph Monitor quorum is ready")
    else:
        log('Not enough mons ({}), punting.'
            .format(len(get_mon_hosts())))


def notify_osds():
    for relid in relation_ids('osd'):
        osd_relation(relid)


def notify_radosgws():
    for relid in relation_ids('radosgw'):
        radosgw_relation(relid)


def notify_client():
    for relid in relation_ids('client'):
        client_relation(relid)


def upgrade_keys():
    ''' Ceph now required mon allow rw for pool creation '''
    if len(relation_ids('radosgw')) > 0:
        ceph.upgrade_key_caps('client.radosgw.gateway',
                              ceph._radosgw_caps)
    for relid in relation_ids('client'):
        units = related_units(relid)
        if len(units) > 0:
            service_name = units[0].split('/')[0]
            ceph.upgrade_key_caps('client.{}'.format(service_name),
                                  ceph._default_caps)


@hooks.hook('osd-relation-joined')
def osd_relation(relid=None):
    if ceph.is_quorum():
        log('mon cluster in quorum - providing fsid & keys')
        data = {
            'fsid': leader_get('fsid'),
            'osd_bootstrap_key': ceph.get_osd_bootstrap_key(),
            'auth': config('auth-supported'),
            'ceph-public-address': get_public_addr(),
        }
        relation_set(relation_id=relid,
                     relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring fsid provision')


@hooks.hook('radosgw-relation-joined')
def radosgw_relation(relid=None):
    # Install radosgw for admin tools
    apt_install(packages=filter_installed_packages(['radosgw']))
    if ceph.is_quorum():
        log('mon cluster in quorum - providing radosgw with keys')
        data = {
            'fsid': leader_get('fsid'),
            'radosgw_key': ceph.get_radosgw_key(),
            'auth': config('auth-supported'),
            'ceph-public-address': get_public_addr(),
        }
        relation_set(relation_id=relid,
                     relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring key provision')


@hooks.hook('client-relation-joined')
def client_relation(relid=None):
    if ceph.is_quorum():
        log('mon cluster in quorum - providing client with keys')
        service_name = None
        if relid is None:
            service_name = remote_unit().split('/')[0]
        else:
            units = related_units(relid)
            if len(units) > 0:
                service_name = units[0].split('/')[0]
        if service_name is not None:
            data = {
                'key': ceph.get_named_key(service_name),
                'auth': config('auth-supported'),
                'ceph-public-address': get_public_addr(),
            }
            relation_set(relation_id=relid,
                         relation_settings=data)
    else:
        log('mon cluster not in quorum - deferring key provision')


@hooks.hook('upgrade-charm')
def upgrade_charm():
    emit_cephconf()
    apt_install(packages=filter_installed_packages(ceph.PACKAGES), fatal=True)
    install_upstart_scripts()
    ceph.update_monfs()
    upgrade_keys()
    mon_relation_joined()


@hooks.hook('start')
def start():
    # In case we're being redeployed to the same machines, try
    # to make sure everything is running as soon as possible.
    service_restart('ceph-mon-all')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
