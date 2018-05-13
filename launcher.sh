#!/bin/bash

# najprv zmenit spustanie POXu z "./pox.py" na defaultny prikaz "python /home/mininet/pox/pox.py log.level --DEBUG forwarding.l3_learning &"
# zmenit zastavovanie poxu prikazom "pkill -f pox.py"
# odstranit duplicity -> spustanie a zastavovanie poxu dat do funkcii => 'restart' bude iba volanie funkcii 'start' a 'stop'
# zmenit spustanie poxu na "python /home/mininet/pox/pox.py forwarding.l2_learning  pox.firewall.main &"
# prerobit do switch-case

COMMAND = $1

if [ $COMMAND == "start" ]; then
   #./pox.py forwarding.l2_learning pox.firewall.main &
   python /home/mininet/pox/pox.py log.level --DEBUG forwarding.l3_learning &

elif [ $COMMAND == "restart" ]; then
   sudo kill $(ps aux | grep 'pox.py *' | awk '{print $2}')
   ./pox.py forwarding.l2_learning pox.firewall.main &

elif [ $COMMAND == "stop" ]; then
    sudo pkill -f pox.py

else
    echo "ERROR: Unknown option"
fi
