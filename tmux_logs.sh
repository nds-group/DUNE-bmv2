#!/bin/bash


if [ -z "${TMUX}" ]; then
	# Not inside tmux
	ACTION="new-session -d -s dune-session"
	CMD="tmux attach -t dune-session"
else
	# Inside tmux
	ACTION="new-window"
fi

ACTION="${ACTION} -n dune-logs"

tmux ${ACTION} "tail -f logs/s1.log" &&
tmux split-window -h "tail -f logs/s1_digests.log" &&
tmux split-window -h "tail -f logs/s2.log" &&
tmux split-window -h "tail -f logs/s2_digests.log" &&
tmux split-window -h "tail -f logs/s3.log" &&
tmux split-window -h "tail -f logs/s3_digests.log" &&

tmux setw -g mouse on &&
tmux select-layout tiled

${CMD}
