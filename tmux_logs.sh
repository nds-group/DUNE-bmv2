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
tmux split-window -h "tail -f logs/c1.csv" &&
tmux split-window -h "tail -f logs/s2.log" &&
tmux split-window -h "tail -f logs/c2.csv" &&
tmux split-window -h "tail -f logs/s3.log" &&
tmux split-window -h "tail -f logs/c3.csv" &&

tmux setw -g mouse on &&
tmux select-layout tiled

${CMD}
