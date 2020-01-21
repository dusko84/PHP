<?php

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */



    function ocisti($p)
    {
     $p = str_replace("<","&lt;",$p);
     $p = str_replace(">","&gt;",$p);
     return $p; 
    }
    $tekst ='Ovaj teks <script>ima gomilu<><opasnog</scrtipt> teksta';
   $cisto= ocisti($tekst);
   echo $cisto;
    echo '<br/><hr>';
/*
        Sličan efekat možemo postići i ugrađenom funkcijom strip_tags(). 
        Ova funkcija eliminiše tagove, ali i njihove nazive. Sledeća linija:

    */
    echo strip_tags("<abc>tekst");

    echo '<br/><hr>';


//Funkcija htmlentities() konvertuje HTML oznake u HTML kodove:

    echo htmlentities("<abc>tekst");

    echo '<br/><hr>';


//Identičan izlaz ima i funkcija: htmlspecialchars

    echo htmlspecialchars("<abc>tekst");
    echo '<br/><hr>';
