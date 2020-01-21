<?php
//obezbedujemo prikaz gresaka
error_reporting(E_ALL | E_STRICT);

/*sada sebi pravim niz kako bi trebalo da izlgeda u URL kako bi mogao da vezbam ovaj primer :
    http://localhost/Greske-Error/FiltritanejPodataka/FilterFunctions/filter_input_array/primer1.php?array[product_id]
        
        //to NIKAKO NEUSPEVAM
 *  */

//to NIKAKO NEUSPEVAM
print_r($_POST);

die();

/* data actually came from POST
$_POST = array(
    'product_id'    => 'libgd<script>',
    'component'     => '10',
    'versions'      => '2.0.33',
    'testscalar'    => array('2', '23', '10', '12'),
    'testarray'     => '2',
);
*/

/*POKUSACU DA OBJEASNIM ONAKO MOJJOM LOGIKOM ista je logika kao i u filter_var_array
 */

/* 1. Dakle stize neki niz $_POST sa URL */
$_POST = array(
    'product_id'    => 'libgd<script>',
    'component'     => '10',
    'versions'      => '2.0.33',
    'testscalar'    => array('2', '23', '10', '12'),
    'testarray'     => '2',
);

/* 2. Onda mi pravimo SVOJU PROMENLJIVU u ovmo slucaju $args 
        i u njoj za $key vrednosti UBACUJEMO ID filtera koji zelimo da se obavim nad teim clanom niza
   3. ZA VALUE pored filtere mozemo ubaciti i ostale atribute onda bi value = bio niz   
                array(  'filter'    => FILTER_VALIDATE_INT,
                        'flags'     => FILTER_REQUIRE_ARRAY, 
                        'options'   => array('min_range' => 1, 'max_range' => 10)
*                   ),
  */
$args = array(
    'product_id'   => FILTER_SANITIZE_ENCODED,
    'component'    => array('filter'    => FILTER_VALIDATE_INT,
                            'flags'     => FILTER_REQUIRE_ARRAY, 
                            'options'   => array('min_range' => 1, 'max_range' => 10)
                           ),
    'versions'     => FILTER_SANITIZE_ENCODED,
    'doesnotexist' => FILTER_VALIDATE_INT,
    'testscalar'   => array(
                            'filter' => FILTER_VALIDATE_INT,
                            'flags'  => FILTER_REQUIRE_SCALAR,
                           ),
    'testarray'    => array(
                            'filter' => FILTER_VALIDATE_INT,
                            'flags'  => FILTER_REQUIRE_ARRAY,
                           )

);
/*
4.Onda nakon to ga sledi Callback funkcija   $myinputs = filter_input_array(INPUT_POST, $args); 
 koja ponasa kao Callbaks tj. sve clanove niza(pod uslovom da je niz) koji dolazi sa $data provlaci kroz taj nas gore napravljen niz  $args                                                                               
     INACE dakle potrebno je znati koji elementi niza dolaze kao $key kako bi znali kako da postavimo nas niz $args

  */
$myinputs = filter_input_array(INPUT_POST, $args);
// 5.na kraju $myinputs sadrzi niz sa filtriranim value vrednostima
var_dump($myinputs);
echo "\n";

