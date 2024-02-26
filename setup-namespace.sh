ip netns add ns1
ip link add veth0 type veth peer name veth1
ip link set veth1 netns ns1
ip addr add 192.168.64.1/24 dev veth0
ip -n ns1 addr add 192.168.64.2/24 dev veth1
ip link set veth0 up
ip -n ns1 link set veth1 up
ip netns exec ns1 ping -c 1 192.168.64.1

