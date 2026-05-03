#!/usr/bin/env bash
echo -n "x" | sudo ip netns exec testns nc -u -w1 10.0.0.1 1111
echo -n "x" | sudo ip netns exec testns nc -u -w1 10.0.0.1 2222
echo -n "x" | sudo ip netns exec testns nc -u -w1 10.0.0.1 3333
