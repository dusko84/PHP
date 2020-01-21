<?php

/*Podesavanje OTION pogledaj primer PodesavanjeOption_ZaFiltere
        dakle imamo niz $option koji cemo koristii za konfigurisanje FILTERA i taj niz  U SEBI SADRZI CLAN :
            1. 'option' koji u sebi sadrzi niz sa atributima  'default' => 3,  'min_range' => 0  ostali  NJIH MOZES NACI U TABELAMA TIPOVI FILTEREA POD OPTION
            2.  'flags' => FILTER_FLAG_ALLOW_OCTAL,

  */
        $options =  array(
            'options' => array(
                    'default' => 3, // defaul vrednost koja se vraca ako nesto nije ok sa filtereom
                    // other options here
                    'min_range' => 0
                    ),
            'flags' => FILTER_FLAG_ALLOW_OCTAL,
            );
        
/* i onda postavljamo PROMENLJIVU/FUNKCIJU koja ce obavaljti FILTRIRANJ po zadatom $option 
 */
$var = filter_var('7da505', FILTER_VALIDATE_INT, $options);
print_r($var); //vraca int ili 3 ako nije prosledjen int //pogledaj sta se zbiva ako se stavi 0 na prvomo mestu...jer to onda nije prvi int, ili stavi string izbacice 3
echo '<br/><hr>';

/*
ZATIM POSTAVLAJENJE FLAGS bez OPTION...  
    znaci mogu se direktno proslediti TO se uglavnoim primnjuje kod filtera koji prihvataju samo flags...
 * Mozes pogledati mednju Filterima Other,Sanitize,Validation koji mogu imati Flags a koji ne mogu!
    TAKODJE AKO POGLEDAS OBA DRAJVERA(FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)  IMAS U TipoviFiltera /FLAGS
 * */

$var = filter_var('true', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);  //FILTER_NULL_ON_FAILURE  Returns NULL for unrecognized boolean values. 
    var_dump($var); //stavi nesto drugo sem true
echo '<br/><hr>';

/*ZATIM POSTAVLJNJE filtera koji samo prihvataju FLAGSE...TAKODJE MOZETE PRODLEITI FLAGS I PREKO NIZA
 */ 
$var = filter_var('oops', FILTER_VALIDATE_BOOLEAN,
                  array('flags' => FILTER_NULL_ON_FAILURE));

var_dump($var);
echo '<br/><hr>';
//die();
/*ZATIM PRAVIMO CALLBACK funkciju koja ce obavaljati FILTRIRANJE
    dakle imamo neku callbacks funkciju koaj prima vrednsoti function foo($value).
        INACE -ocekujemo na ulau da primamo format: Surname, GivenNames
        Zatim postavaljmo separator i formiramo niz
        SA list metodom 1elemnt ce imati vrednost $surname  2. a drugi $givennames.DAKLE dodaljeuje vrednosti dolazecem nizu
        explode(", ", $value, 2); Nam omogucava da razbijemo taj niz u ovom slucaju na dve promenljive
        promenljvu $emty koja ce postojati i imati vrednost ako je ndeki od elemenata prazan
        Takodje dodajemo i promenljivu koja ce proveravati da li su stringovi
  */

function foo($value){
    if (strpos($value, ", ") === false) return false;//dakle ako se ne pronadje zarez u dolazecem stringu rezultat unutar if ce biti FALSE===FALSE i vratice return false
    //u suprotnom  taj dolazeci string ce se podeliti tamo gde je ", "  i dobicemo novi niz sa 2 elemnta. DAKLE PROSTO smestanja dolazece teksta u niz, sa separatormo (,)
    list($surname, $givennames) = explode(", ", $value, 2); 
    $empty = (empty($surname) || empty($givennames));
    $notstrings = (!is_string($surname) || !is_string($givennames));
    //i ako ni jedna od te dve nove promenljive nije true vratice znaci filtrirani $VALUE
    if ($empty || $notstrings) {//u usprtotnom vratice false
        return false;
    } else {
        return $value; 
    }
}
$var = filter_var('Doe, Jane Sue', FILTER_CALLBACK, array('options' => 'foo'));
echo '<br/>OVO VRACA SA callbacks funkcjiom <br/><hr>';
print_r($var);


echo '<br/><br/><hr>PRIEMR ZA EXPLODE<hr>';

$pizza = "parčel parče2 parče3 parče4 parče5 parče6";
$delovi = explode (" ", $pizza);
print_r($delovi);


/*NAPOMENEEE

Pay attention that the function will not validate "not latin" domains.

if (filter_var('уникум@из.рф', FILTER_VALIDATE_EMAIL)) { 
    echo 'VALID'; 
} else {
    echo 'NOT VALID';
}
 * 
 * */


/*

 * I found some addresses that FILTER_VALIDATE_EMAIL rejects, but RFC5321 permits:
<?php
foreach (array(
        'localpart.ending.with.dot.@example.com',
        '(comment)localpart@example.com',
        '"this is v@lid!"@example.com', 
        '"much.more unusual"@example.com',
        'postbox@com',
        'admin@mailserver1',
        '"()<>[]:,;@\\"\\\\!#$%&\'*+-/=?^_`{}| ~.a"@example.org',
        '" "@example.org',
    ) as $address) {
    echo "<p>$address is <b>".(filter_var($address, FILTER_VALIDATE_EMAIL) ? '' : 'not')." valid</b></p>";
}



 *  */
