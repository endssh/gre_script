#!/bin/sh
sysctl -w net.ipv4.ip_forward=1

echo "HOST_B_IP:"
read HOST_B_IP
echo "HOST_A_IP:"
read HOST_A_IP
echo "HOST_B_PRIV_IP_GRE:"
read HOST_B_PRIV_IP_GRE
echo "HOST_A_PRIV_IP_GRE:"
read HOST_A_PRIV_IP_GRE
echo "GRE:"
read GRE

ip tunnel add $GRE mode gre remote $HOST_A_IP local $HOST_B_IP ttl 225
ip addr add $HOST_B_PRIV_IP_GRE/30 dev $GRE
ip link set dev $GRE up

iptables -t nat -A POSTROUTING -s $HOST_B_PRIV_IP_GRE ! -o gre+ -j SNAT --to-source $HOST_B_IP
echo '100 GRE' >> /etc/iproute2/rt_tables
ip rule add from $HOST_B_PRIV_IP_GRE/32 table GRE
ip route add default via $HOST_A_PRIV_IP_GRE table GRE
