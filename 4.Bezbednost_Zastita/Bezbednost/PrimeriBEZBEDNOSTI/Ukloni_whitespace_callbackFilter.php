<?php

/**
* Ukloni whitespace (or other non-printable characters) from the beginning and end of a string
* @param string $value = dakle to je parametar koji dolazi
*/
/*dakle ova metoda ce ustavri biti callbackf funckjia
    koja ce ukoniti sva space mesta u stringu, takodje i sa pocetka i sa kraja
  */
function trimString($value)
{
    return trim($value); //metoda koja Odseca belinu s početka i kraja znakovnog niza i vraca izmenjeni niz. Znakovi "beline" koji se trenutno uklanjaju jesu: "\n", "V", "V", '\v", '\0" i običan razmak. Pogledajte i chop(), rtrim() i ltrim().
}

/*$loginame ce nositi objekat sa vrdnosu koju vraca $callbacks funkcija
    to za objeakta je lepo obajsnjeno u Callable
  */
$loginname = filter_input(INPUT_POST, 'loginname', FILTER_CALLBACK, array('options' => 'trimString'));

