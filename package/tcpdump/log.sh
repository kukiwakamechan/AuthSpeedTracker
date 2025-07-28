#!/bin/bash

# ログ保存のディレクトリ作成 
[ ! -d "パス" ] && mkdir -p "パス"

# 日付と時刻の取得
current_datetime=$(date +"%Y-%m-%d_%H-%M-%S")

# SSHのアクセスログを取得
sudo tcpdump -i enp1s0 -s 0 -U -w "パス/${current_datetime}.dump" 'tcp port 22'



