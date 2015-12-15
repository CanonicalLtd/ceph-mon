# Overview

Ceph is a distributed storage and network file system designed to provide
excellent performance, reliability, and scalability.

This charm deploys a Ceph cluster.

# Usage

Boot things up by using:

    juju deploy -n 3 ceph-mon

By default the ceph cluster will not bootstrap until 3 service units have been
deployed and started; this is to ensure that a quorum is achieved prior to adding
storage devices.

## Scale Out Usage

You can use the Ceph OSD and Ceph Radosgw charms:

- [Ceph OSD](https://jujucharms.com/precise/ceph-osd)
- [Ceph Rados Gateway](https://jujucharms.com/precise/ceph-radosgw)

# Contact Information

## Authors 

- Paul Collins <paul.collins@canonical.com>,
- James Page <james.page@ubuntu.com>,
- Chris MacNaughton <chris.macnaughton@canonical.com>

Report bugs on [Launchpad](http://bugs.launchpad.net/charms/+source/ceph/+filebug)

## Ceph

- [Ceph website](http://ceph.com)
- [Ceph mailing lists](http://ceph.com/resources/mailing-list-irc/)
- [Ceph bug tracker](http://tracker.ceph.com/projects/ceph)

# Technical Footnotes

This charm uses the new-style Ceph deployment as reverse-engineered from the
Chef cookbook at https://github.com/ceph/ceph-cookbooks, although we selected
a different strategy to form the monitor cluster. Since we don't know the
names *or* addresses of the machines in advance, we use the _relation-joined_
hook to wait for all three nodes to come up, and then write their addresses
to ceph.conf in the "mon host" parameter. After we initialize the monitor
cluster a quorum forms quickly, and OSD bringup proceeds.

The osds use so-called "OSD hotplugging". **ceph-disk-prepare** is used to
create the filesystems with a special GPT partition type. *udev* is set up
to mount such filesystems and start the osd daemons as their storage becomes
visible to the system (or after `udevadm trigger`).

The Chef cookbook mentioned above performs some extra steps to generate an OSD
bootstrapping key and propagate it to the other nodes in the cluster. Since
all OSDs run on nodes that also run mon, we don't need this and did not
implement it.

See [the documentation](http://ceph.com/docs/master/dev/mon-bootstrap/) for more information on Ceph monitor cluster deployment strategies and pitfalls.
