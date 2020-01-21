<?php
/*
Warning
When using one of these filters as a default filter either through your ini file or through your web server's configuration, the default flags is set to FILTER_FLAG_NO_ENCODE_QUOTES. 
 * You need to explicitly set filter.default_flags to 0 to have quotes encoded by default. Like this:

 * 
  
 
   UPOZORENJE: Kada koristimo jedan od ovih filtere kao podrazumevani(default) filter ili kroz php ili ako ga konfigurisemo na webServeru initFajl Onda default flags treba biti postavlajn na FILTER_FLAG_NO_ENCODE_QUOTES.
        ONDA JE potrebno postaviti filter.default_flags to 0   
 
 NPR:  Postavaljanje defult  htmlspecialchars filtera unutar init 
    filter.default = full_special_chars
    filter.default_flags = 0
 *  */



/* IME za sta se odnosi              ID                                    FLAG                        OPIS

 * 1.   "email"             FILTER_SANITIZE_EMAIL                                                   Uklasnja sve karaktere OSIM slova, brojeva i !#$%&'*+-=?^_`{|}~@.[].
 *                                                                                                          
 * 

 * 
 * 2.  "encoded"            FILTER_SANITIZE_ENCODED                 FILTER_FLAG_STRIP_LOW,          Sifruje string  optionally strip or encode special characters.
 *                                                                  FILTER_FLAG_STRIP_HIGH, 
 *                                                                  FILTER_FLAG_ENCODE_LOW, 
 *                                                                  FILTER_FLAG_ENCODE_HIGH
 * 
 * 
 * 3.   "magic_quotes"      FILTER_SANITIZE_MAGIC_QUOTES                                            Primenjuje  addslashes().  TJ, dodaje \ ispred karaktera  ('), double quote ("), backslash (\) and NUL (the NULL byte).  da bi se mogli koristiti npr za unos u bazu  jer samo se tako mogu uneti '"\
 *                                                            
 * 
 * 4.  "number_float        FILTER_SANITIZE_NUMBER_FLOAT            FILTER_FLAG_ALLOW_FRACTION,     Uklanja sve karaktere osim brojeva, +- and optionally .,eE.
 *                                                                  FILTER_FLAG_ALLOW_THOUSAND, 
 *                                                                  FILTER_FLAG_ALLOW_SCIENTIFIC
 *                                                             
 *                                                            
 * 
 *      
 * 5.  "number_int"         FILTER_SANITIZE_NUMBER_INT                                             Uklanja sve osim brojeva, plus and minus znakova.

 * 
 * 
 * 
 * 
 * 6.  "special_chars"      FILTER_SANITIZE_SPECIAL_CHARS           FILTER_FLAG_STRIP_LOW,          HTML-escape '"<>& and characters with ASCII value less than 32, optionally strip or encode other special characters.
 *                                                                  FILTER_FLAG_STRIP_HIGH, 
 *                                                                  FILTER_FLAG_ENCODE_HIGH      
 *                                                                          
 *                                                                          
 *                                                                          
 * 
 * 7. "full_special_chars"  FILTER_SANITIZE_FULL_SPECIAL_CHARS      FILTER_FLAG_NO_ENCODE_QUOTES,       Radi isto sto i metoda htmlspecialchars() pod uslovom da je  ENT_QUOTES set.   htmlspecialchars() //http://qw.in.rs/php/index1e49.html?expandalpha=1&action=prikazi_funkciju&id=391&shownode=H
 *                                                                                                      Encoding quotes can be disabled by setting FILTER_FLAG_NO_ENCODE_QUOTES. Like htmlspecialchars(), 
 *                                                                                                      this filter is aware of the default_charset and if a sequence of bytes is detected that makes up an invalid character in the current character set then the entire string is rejected resulting in a 0-length string.
 *                                                                                                       When using this filter as a default filter, see the warning below about setting the default flags to 0.    
 * 
 * 
 * 
 * 
 * 8. "string"              FILTER_SANITIZE_STRING                  FILTER_FLAG_NO_ENCODE_QUOTES,      Strip tags, optionally strip or encode special characters.
 *                                                                  FILTER_FLAG_STRIP_LOW, 
 *                                                                  FILTER_FLAG_STRIP_HIGH, 
 *                                                                  FILTER_FLAG_ENCODE_LOW, 
 *                                                                  FILTER_FLAG_ENCODE_HIGH, 
 *                                                                  FILTER_FLAG_ENCODE_AMP
 * 
 *                                                              
 * 9.   "stripped"          FILTER_SANITIZE_STRIPPED                                                    Alias of "string" filter.
 *    
 * 
 * 
 * 
 * 
 * 10.  "url"               FILTER_SANITIZE_URL                                                         Remove all characters except letters, digits and $-_.+!*'(),{}|\\^~[]`<>#%";/?:@&=.
     
 * 
 * 
 * 
 * 
 * 11. "unsafe_raw"           FILTER_UNSAFE_RAW                     FILTER_FLAG_STRIP_LOW,              Do nothing, optionally strip or encode special characters. This filter is also aliased to FILTER_DEFAULT.
 *                                                                  FILTER_FLAG_STRIP_HIGH, 
 *                                                                  FILTER_FLAG_ENCODE_LOW, 
 *                                                                  FILTER_FLAG_ENCODE_HIGH,
 *                                                                  FILTER_FLAG_ENCODE_AMP
                                                                     
 *  */



/*NAPOMENE

 * Remember to trim() the $_POST before your filters are applied: !!!!!

<?php

// We trim the $_POST data before any spaces get encoded to "%20"

// Trim array values using this function "trim_value"
function trim_value(&$value)
{
    $value = trim($value);    // this removes whitespace and related characters from the beginning and end of the string
}
array_filter($_POST, 'trim_value');    // the data in $_POST is trimmed

$postfilter =    // set up the filters to be used with the trimmed post array
    array(
            'user_tasks'                        =>    array('filter' => FILTER_SANITIZE_STRING, 'flags' => !FILTER_FLAG_STRIP_LOW),    // removes tags. formatting code is encoded -- add nl2br() when displaying
            'username'                            =>    array('filter' => FILTER_SANITIZE_ENCODED, 'flags' => FILTER_FLAG_STRIP_LOW),    // we are using this in the url
            'mod_title'                            =>    array('filter' => FILTER_SANITIZE_ENCODED, 'flags' => FILTER_FLAG_STRIP_LOW),    // we are using this in the url
        );

$revised_post_array = filter_var_array($_POST, $postfilter);    // must be referenced via a variable which is now an array that takes the place of $_POST[]
echo (nl2br($revised_post_array['user_tasks']));    //-- use nl2br() upon output like so, for the ['user_tasks'] array value so that the newlines are formatted, since this is our HTML <textarea> field and we want to maintain newlines
 * 
 * 
 *  */
