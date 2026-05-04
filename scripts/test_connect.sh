#!/usr/bin/env bash
ip netns exec testns nc -vz 10.0.0.1 22
