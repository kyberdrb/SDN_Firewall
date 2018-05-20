# sdnfirewall

Firewall modul pre [POX SDN controller](https://github.com/noxrepo/pox)

Inšpirácia: [SDN Firewall](https://github.com/rakeshdatta/SDN_Firewall) autor: Rakesh Datta [(Ukážka pôvodného riešenia)](https://www.youtube.com/watch?v=ydD9Qal_ZQs)

Funkcionality SDN Firewall modulu pre POX radič:
* **Permisívny mód** - čo nie je explicitne zakázané, je povolené
* **Transparentný** - základom je modul L2 prepínača
* **Jednoduché ovládanie** - BASH skript
* Vlastné pravidlá - firewall pravidlá je možné upravovať v osobitnom súbore
* **Blokovanie prevádzky podľa rôznych parametrov**
    * Zdrojová / cieľová IP adresa (IPv4) - iba konkrétne adresy (host), nie celé sieťové rozsahy
    * Transportný protokol - [podporované porty](https://github.com/kyberdrb/sdnfirewall/blob/master/transproto.py)
    * Aplikačný protokol - [podporované porty](https://github.com/kyberdrb/sdnfirewall/blob/master/appproto.py)
* **Platnosť pravidla** - pravidlu je možné nastaviť čas, kedy jeho platnosť vyprší
* **Odloženie pravidla** - pravidlu je možné nastaviť čas, po ktorom sa uvedie do činnosti
* Jednoduchý objektový návrh
* Čitateľný a zrozumiteľný zdrojový kód
* Postavený na OpenFlow 1.0

### Nasadenie SDN firewall modulu do SDN radiča POX

Návod plynule nadväzuje na [dokumentáciu k semestrálnej práci](https://github.com/kyberdrb/FRI/tree/master/Ing/4.semester/Integracia_Sieti/semestralka)

1. Po ukončení radiča môžeme prejsť k nasadeniu firewall modulu do POX radiča. Pri vytváraní firewall modulu sme ako základ použili [už vytvorený firewall balíček pre POX radič](https://github.com/rakeshdatta/SDN_Firewall). Jeho autorom je Rakesh Datta.

    Repozitár bol skopírovaný do nášho GitHub účtu, v ktorom sme vykonávali všetky úpravy. Potom bol tento repozitár naklonovaný do adresára `~/pox/ext/`, keďže POX radič hľadá rozširujúce balíčky v podadresároch <br>`pox` a `ext` t.j. <br> `~/pox/pox/` a `~/pox/ext/`.

    Firewall balíček môže byť naklonovaný do ľubovoľného adresára pre rozširujúce balíčky pre POX radič t.j. `/pox` aj `/ext`. Nakoniec sme si vybrali adresár `/ext`, keďže [dokumentácia k POX radiču](https://github.com/att/pox/blob/master/pox/boot.py) odporúča použiť spomenutý adresár pred adresárom `/pox` na vlastné rozširujúce balíčky.

    Predpokladáme, že POX radič, konkrétne súbor `pox.py` je umiestnený v domovskom adresári používateľa, t.j. `$HOME/pox/` resp. `~/pox/`. V opačnom prípade spúšťací skript nebude pracovať správne.

    Naklonujeme repozitár do príslušného adresára na Mininet VM:

        cd ~/pox/ext/
        git clone https://github.com/kyberdrb/sdnfirewall.git

1. V POX SSH relácií sa presunieme do adresára firewall balíčka pre POX radič, zresetujeme Mininet prostredie, aby sme predišli neočakávaným chybám a spustíme radič.

        cd ~/pox/ext/sdnfirewall
        ./launcher.sh clean
        ./launcher.sh start
1. V Miniedit SSH relácií spustíme Miniedit GUI a otvoríme v ňom súbor s Mininet topológiou `semkaTOPO.mn`. Miniedit spúšťame až po vyčistení Mininet prostredia príkazom `./launcher.sh clean`, inak sa môžu vyskytnúť neočakávané komplikácie v Mininet/Miniedit prostredí.

        sudo ~/mininet/examples/miniedit.py

1. Prvotnú konektivitu otestujeme príkazom 

        pingall
    z Mininet príkazového riadku `mininet>`. Výstup príkazu závisí od pravidiel definovaných v súbore s firewall pravidlami.

1. Terminály všetkých koncových zariadení otvoríme z príkazového riadku `mininet>` príkazom

        xterm h1 h2 h3

1. Povedzme, že súbor s pravidlami má takýto obsah:

        #src,dst,trans_proto,app_proto,expiration,delay
        10.0.0.2,10.0.0.3,icmp,any,60,30

    Toto pravidlo bude blokovať ICMP komunikáciu ľubovoľnej aplikácie medzi zariadeniami 10.0.0.2 a 10.0.0.3. Komunikácia bude blokovaná 60 sekúnd, pričom pravidlo bude aktívne po 30 sekundách od spustenia radiča.

1. Pokiaľ súbor s firewall pravidlami zmeníme pri spustenom radiči, musíme reštartovať radič príkazom

        ./launcher.sh restart

    Prevádzka bude mať na okamih vyššie, ale zanedbateľné oneskorenie (<1ms).

1. Po reštarte radiča sa v príkazovom riadku budú objavovať správy o činnostiach, ktoré firewall vykonáva, spolu s výpisom 

1. Okamžite po reštarte radiča otestujeme konektivitu medzi všetkými zariadeniami

        pingall

1. Zároveň otestujeme konektivitu medzi koncovými zariadeniami h2 a h3

        h2 ping h3 -c 2

    *Ping* by mal úspešne prebehnúť a 

1. Ďalej necháme nečinne a sledujeme výstup. Po 30 sekundách od spustenia radiča sa pravidlo aktivuje. Log správy zobrazia udalosť, že pravidlo bolo pridané, spolu so zoznamom všetkých aktívnych firewall pravidiel.

1. Po zobrazení pridaného firewall pravidla znova vykonáme príkaz

        h2 ping h3

    resp.

        pingall

    Prvý príkaz dokazuje, že pravidlo naozaj blokuje uvedenú prevádzku medzi koncovými zariadeniami h2 a h3 na 60 sekúnd.

    Druhý príkaz dokazuje, že toto pravidlo nemá vplyv na žiadne ďalšie koncové zariadenia.

1. Po uplynutí 60 sekúnd sa pravidlo odstráni a prevádzka medzi h2 a h3 sa obnoví, čo overíme rovnakými príkazmi ako v predchádzajúcom kroku.

1. Po skončení práce s POX radičom ho ukončíme pomocou spúšťacieho skriptu príkazom

        ./launcher.sh stop

1. Aktualizácia firewall balíčka vykonáme stiahnutím najnovšej verzie z nášho GitHub repozitára:

        git -C ~/pox/ext/sdnfirewall pull
        ~/pox/ext/sdnfirewall/launcher.sh restart

    resp. najprv sa navigujeme do adresára s SDN firewall modulom 

        cd ~/pox/ext/sdnfirewall
    a vykonáme príkazy

        git pull
        ./launcher.sh restart

    čím stiahneme najnovšiu verziu modulu z repozitára a reštartujeme radič, aby sa všetky zmeny prejavili.

## Známe problémy:
* Platnosť jedného MAC záznamu na prepínači je cca 20 sekúnd, preto sa môže stať, že sa aktivácia pravidla oneskorí o tento čas
* TCP pravidlo blokuje aj ICMP správy??

## TODO
* Aktualizácia pravidiel pri spustenom kontroléri metódou "polling" - dotazovania sa na posledný čas zmeny súboru s firewall pravidlami napr. každú sekundu -> potom vymazať všetky existujúce pravidlá a nahrať nové pravidlá, ideálne pridať a odstrániť iba tie pravidlá, ktoré sú rôzne od práve načítaných
* Prerobenie súboru s pravidlami z CSV do JSON, kvôli lepšej čitateľnosti a flexibilitu pri načítavaní pravidiel zo súboru
* Reštriktívny firwall mód