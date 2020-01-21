<?php

/* 
Kada je register_globals uključen, PHP sam generiše promenljive na osnovu Request parametara,
 *  čak i ako nismo predvideli njihov ulazak u aplikaciju. 
 * Na primer, ako je register_globals aktiviran i strana bude otvorena na sledeći način:
 mojaPhpStrana.php?mojParametar=10

    U kodu će biti generisana promenljiva $mojParametar čija će vrednost biti 10. Tako da, kada bi naš kod glasio:
    echo $mojParametar;
        Bila bi emitovana vrednost 10 na strani, iako nigde u kodu nismo eksplicitno definisali ovu vrednost.
 
 DAKLE PROSTO Register_globals NEMOZES KORISTITI VISE NA NOVIJIM PHP SERVERIMA
 */
    //SAD KADA SAM POKUSAO u init.php da ipak stavim Register_globals na  on  nisam uspeo ni da pokrenen APACHE ni posle restart servera

    echo $mojParametar;