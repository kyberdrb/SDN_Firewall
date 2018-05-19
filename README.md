# SDN_Firewall

A firewall module for [POX SDN controller](https://github.com/noxrepo/pox)

Inspiration: [SDN Firewall](https://www.youtube.com/watch?v=ydD9Qal_ZQs) by Rakesh Datta

[Firewall Guide](https://github.com/kyberdrb/FRI/tree/master/Ing/4.semester/Integracia_Sieti/semestralka)

Známe problémy:
* Platnosť jedného MAC záznamu na prepínači je cca 20 sekúnd, preto sa môže stať, že sa aktivácia pravidla oneskorí o tento čas
* TCP pravidlo blokuje aj ICMP správy??