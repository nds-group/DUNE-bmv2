#!/bin/bash

find logs/ -name "*.log" -exec sed -i.long '/bm_get_config/,$!d' '{}' \;
