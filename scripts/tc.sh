#!/bin/bash

# show device
nmcli dev status

DEVICE=enp0s3
RATE=500mbit

echo "before tc:"
tc qdisc show dev $DEVICE

sudo tc qdisc add dev $DEVICE handle 1: root htb default 11
sudo tc class add dev $DEVICE parent 1: classid 1:1 htb rate $RATE
sudo tc class add dev $DEVICE parent 1:1 classid 1:11 htb rate $RATE

echo "after tc:"
tc qdisc show dev $DEVICE

# note: the above must be rerun each time the machine is restarted.
# to clear the above:
# sudo tc qdisc del dev $DEVICE root
