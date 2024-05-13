# this script can be included in other testbed startup scripts
#
# topology:
#
#      +------------------+      +------------------+
#      |        r1        |      |        r2        |
#      |                  |      |                  |
#      |              i12 +------+ i21          i23 +
#      |                  |      |                  |
#      |                  |      |                  |
#      +------------------+      +------------------+
#
# addresses:
#
# r1 i12 fc12::1/64 mac 00:00:00:00:01:02
#
# r2 i21 fc12::2/64 mac 00:00:00:00:02:01
#
# To exit from the tmux session type Ctrl-b d
# To enter again the tmux session # tmux attach -t ebpf
# or #scripts/resume-tmux.sh

TMUX=ebpf

# Kill tmux previous session
tmux kill-session -t $TMUX 2>/dev/null

# Clean up previous network namespaces
ip -all netns delete

ip netns add r1
ip netns add r2

ip -netns r1 link add i12 type veth peer name i21 netns r2

###################
#### Node: r1 #####
###################
echo -e "\nNode: r1"

ip -netns r1 link set dev i12 address 00:00:00:00:01:02

ip -netns r1 link set dev lo up
ip -netns r1 link set dev i12 up

ip -netns r1 addr add fc12::1/64 dev i12
ip -netns r1 addr add 10.12.0.1/24 dev i12

ip -netns r1 -6 neigh add fc12::2 lladdr 00:00:00:00:02:01 dev i12

read -r -d '' r1_env <<-EOF
    sysctl -w net.ipv6.conf.all.forwarding=1
    sysctl -w net.ipv4.ip_forward=1
	/bin/bash
EOF

###################
#### Node: r2 #####
###################
echo -e "\nNode: r2"

ip -netns r2 link set dev i21 address 00:00:00:00:02:01

ip -netns r2 link set dev lo up
ip -netns r2 link set dev i21 up

ip -netns r2 addr add fc12::2/64 dev i21
ip -netns r2 addr add 10.12.0.2/24 dev i21

ip -netns r2 -6 neigh add fc12::1 lladdr 00:00:00:00:01:02 dev i21

read -r -d '' r2_env <<-EOF
    sysctl -w net.ipv6.conf.all.forwarding=1
    sysctl -w net.ipv4.ip_forward=1
	/bin/bash
EOF

# Create a new tmux session
sleep 1

tmux new-session -d -s $TMUX -n R1 ip netns exec r1 bash -c "${r1_env}"
tmux new-window -t $TMUX -n R2 ip netns exec r2 bash -c "${r2_env}"

# the following are used if the code is included in another script...
if [[ "$R1_EXEC" == "YES" ]] ; then CM="C-m" ; else CM="" ; fi
tmux send-keys -t $TMUX:R1   "$R1_COMMAND" $CM
if [[ "$R2_EXEC" == "YES" ]] ; then CM="C-m" ; else CM="" ; fi
tmux send-keys -t $TMUX:R2   "$R2_COMMAND" $CM
# ...until here

tmux select-window -t $TMUX:R1
tmux set-option -g mouse on
tmux attach -t $TMUX
