#!/bin/bash

# odstranit duplicity -> spustanie a zastavovanie poxu dat do funkcii => 'restart' bude iba volanie funkcii 'start' a 'stop'
# zmenit spustanie poxu na "python /home/mininet/pox/pox.py forwarding.l2_learning  pox.firewall.main &"
# prerobit do switch-case

COMMAND=$1

case $COMMAND in
    start)
        #./pox.py forwarding.l2_learning pox.firewall.main &
        python /home/mininet/pox/pox.py log.level --DEBUG forwarding.l3_learning &
        ;;
    restart)
        # TODO
        ;;
    stop)
        sudo pkill -f pox.py
        printf "\nPOX terminated\n\n"
        ;;
    *)
        printf $"Usage: $0 {start|stop|restart}\n"
        exit 1
esac