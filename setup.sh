#!/bin/bash

sudo ip link set up dev tun0
sudo ip addr add 10.0.0.1/24 dev tun0