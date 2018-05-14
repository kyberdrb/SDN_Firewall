#!/bin/bash

cleanupMininetEnv () {
    sudo mn -c
}

start_pox () {
    python $HOME/pox/pox.py forwarding.l2_learning sdnfirewall.main &
}

stop_pox () {
    sudo pkill -f pox.py
    printf "\nPOX terminated with the exit code %s\n\n" "$?"
}

COMMAND=$1

case $COMMAND in
    start)
        start_pox
        ;;
    restart)
        stop_pox
        start_pox
        ;;
    stop)
        stop_pox
        ;;
    clean)
        cleanupMininetEnv
        ;;
    *)
        printf "Unrecognized command\n"
        printf "Usage: %s {start|stop|restart}\n" "$0"
        exit 1
esac