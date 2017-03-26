#!/bin/sh
#
# Copyright 2017 Didier Barvaux
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# file:        setup_perfs_env.sh
# description: add script to setup environment for testing
# author:      Didier Barvaux <didier@barvaux.org>
#

create_netns()
{
	local netns=$1
	ip netns add ${netns}
	ip netns exec ${netns} ip link set lo up
}

link_netns()
{
	local netns1=$1
	local netns1_itf=$2
	local netns2=$3
	local netns2_itf=$4
	ip link add name ${netns1_itf} type veth peer name ${netns2_itf}
	ip link set ${netns1_itf} netns ${netns1}
	ip netns exec ${netns1} ip link set ${netns1_itf} up
	ip link set ${netns2_itf} netns ${netns2}
	ip netns exec ${netns2} ip link set ${netns2_itf} up
}

for netns in ENDPOINT1 PROXY1 PROXY2 ENDPOINT2 ; do
	ip netns del ${netns}
	create_netns ${netns}
done
unset netns

link_netns  ENDPOINT1 internet   PROXY1    lan
link_netns  PROXY1    internet   PROXY2    internet
link_netns  PROXY2    lan        ENDPOINT2 internet

ip netns exec ENDPOINT1 ip -4 addr add 192.168.0.1/24 dev internet
ip netns exec ENDPOINT1 ip route add default dev internet
ip netns exec ENDPOINT2 ip -4 addr add 192.168.1.254/24 dev internet
ip netns exec ENDPOINT2 ip route add default dev internet

ip netns exec ENDPOINT1 ethtool -K internet tx off
ip netns exec ENDPOINT1 ethtool -K internet rx off
ip netns exec ENDPOINT2 ethtool -K internet rx off
ip netns exec ENDPOINT2 ethtool -K internet tx off

