<?php

/* 
 * To je ustvari mogucnost da postavis filtere preko $callbackf funkcije
 */
/*
        ID              Name            Options                           Flags             Description
FILTER_CALLBACK     "callback"      callable function or method          ==========     Call user-defined function to filter data.

 *  */
/*Primer*/

/**
* Ukloni whitespace (or other non-printable characters) from the beginning and end of a string
* @param string $value = dakle to je parametar koji dolazi
*/
//dakle ova metoda ce ustavri biti callbackf funckjia
function trimString($value)
{
    return trim($value); //metoda koja Odseca belinu s početka i kraja znakovnog niza i vraca izmenjeni niz. Znakovi "beline" koji se trenutno uklanjaju jesu: "\n", "V", "V", '\v", '\0" i običan razmak. Pogledajte i chop(), rtrim() i ltrim().
}

/*$loginame ce nositi objekat sa vrdnosu koju vraca $callbacks funkcija*/
$loginname = filter_input(INPUT_POST, 'loginname', FILTER_CALLBACK, array('options' => 'trimString'));
//filter_input  jenda od ugradjenih PHP filtera
//function filter_var ($variable, $filter = 'FILTER_DEFAULT', $options = null) {}
        /*dakle zahteva 
            $variable - to je ta vrednsot za koju zelimo da filtriramo  u nasem slucaju  VALLJDA = INPUT_POST, 'loginname'
         *  $filter-  filter koji proimenjujemo u nasem slucaju   FILTER_CALLBACK, (dakle prpada ovom tipu http://php.net/manual/en/filter.filters.misc.php)
         *  array = on je stavio kao NIZ koji ce pozivati $callbacks funkcije
         *      znaci ako imamo jos neku fliter $callback funkcjiu koju zelimo da uvrstimo verovatno samo dodamo  'options' => 'josNekaCalllbackFunkcjia'                                                                            (posotje jos filtere za validaciju, sanitizaciju)         

         *          */