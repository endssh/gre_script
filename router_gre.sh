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
echo "PORT_END:"
read PORT_END
echo "PORT_MAIN:"
read PORT_MAIN
echo "ETH_NET:"
read ETH_NET
echo "ETH_IP_LINK:"
read ETH_IP_LINK

ip tunnel add $GRE mode gre remote $HOST_B_IP local $HOST_A_IP ttl 25
ip addr add $HOST_A_PRIV_IP_GRE/30 dev $GRE
ip link set dev $GRE up

iptables -t nat -A POSTROUTING -s $HOST_B_PRIV_IP_GRE ! -o gre+ -j SNAT --to-source $HOST_A_IP
echo '100 GRE' >> /etc/iproute2/rt_tables
ip rule add from $HOST_A_PRIV_IP_GRE/32 table GRE
ip route add default via $HOST_B_PRIV_IP_GRE table GRE

iptables -A INPUT -p tcp --dport $PORT_MAIN:$PORT_END -s 0/0 -d $ETH_IP_LINK -j ACCEPT
iptables -A OUTPUT -p tcp --sport $PORT_MAIN:$PORT_END -s $ETH_IP_LINK -d 0/0 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -d $ETH_IP_LINK --dport $PORT_MAIN:$PORT_END -j DNAT --to-destination $HOST_B_IP
iptables -t nat -A POSTROUTING -p tcp -d $HOST_B_IP --dport $PORT_MAIN:$PORT_END -j SNAT --to-source $ETH_IP_LINK

iptables -A INPUT -p udp --dport $PORT_MAIN:$PORT_END -s 0/0 -d $ETH_IP_LINK -j ACCEPT
iptables -A OUTPUT -p udp --sport $PORT_MAIN:$PORT_END -s $ETH_IP_LINK -d 0/0 -j ACCEPT
iptables -t nat -A PREROUTING -p udp -d $ETH_IP_LINK --dport $PORT_MAIN:$PORT_END -j DNAT --to-destination $HOST_B_IP
iptables -t nat -A POSTROUTING -p udp -d $HOST_B_IP --dport $PORT_MAIN:$PORT_END -j SNAT --to-source $ETH_IP_LINK

sudo iptables -t nat -A PREROUTING -d $ETH_IP_LINK -j DNAT --to-destination $HOST_B_PRIV_IP_GRE
sudo iptables -t nat -A PREROUTING -d $ETH_IP_LINK -j DNAT --to-destination $HOST_B_PRIV_IP_GRE
sudo iptables -t nat -A POSTROUTING -s $HOST_B_PRIV_IP_GRE -j SNAT --to-source $ETH_IP_LINK
sudo iptables -t nat -A POSTROUTING -s $HOST_B_PRIV_IP_GRE -j SNAT --to-source $ETH_IP_LINK

ip link add $ETH_NET type dummy
ip link set $ETH_NET up
ip addr add $ETH_IP_LINK/32 dev $ETH_NET
ip link set dev $ETH_NET up


