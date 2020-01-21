<?php


// http://php.net/manual/en/filter.filters.validate.php
//When default is set to option, default's value is used if value is not validated.


/* IME za sta se odnosi          ID                        OPTIONS               FLAG                        OPIS

 * 1.   "boolean"           FILTER_VALIDATE_BOOLEAN           default       FILTER_NULL_ON_FAILURE          Vraca TRUE za ("1", "true", "on","yes")  za ostalo vraca FALSE 
 *                                                                                                          Ako ima postavljen flag FILTER_NULL_ON_FAILURE  vraca ce FALSE za ("0", "false", "off", "no",") i NULL ce vratiti za sve vrednosti koje nisu boolean
 * 

 * 
 * 2.   "validate_email"    FILTER_VALIDATE_EMAIL             default         ==============              Potvrdjuje da li je e-mali adresa validna    bori se protvi komentara i praznim mesta  against the syntax in RFC 822, 
 * 
 * 
 * 
 * 3.    "float"            FILTER_VALIDATE_FLOAT             default,     FILTER_FLAG_ALLOW_THOUSAND     Potvrdjuej vrednosti da je FLOAT i konveruje ih u float ako je potrebno tj. ako nije bilo float
 *                                                            decimal  
 * 
 * 
 * 
 * 4.     "int"            FILTER_VALIDATE_INT                 default,    FILTER_FLAG_ALLOW_OCTAL,       Potvrdjuej vrednosti da je INT i konveruje ih u INT ako nisu bilie int. Ima opcionu mogucnos da se definise opseg
 *                                                             min_range,  FILTER_FLAG_ALLOW_HEX
 *                                                             max_range
 * 
 * 
 * 
 * 5.     "validate_ip"     FILTER_VALIDATE_IP                  default,    FILTER_FLAG_IPV4,           Potvrdjuje da su IP adres to sto jesu :D  OPciono moze da se postavi za IPV4 IPV6 kao i za odredjene "privatne" ili "rezervisane" ip adresa
 *                                                                          FILTER_FLAG_IPV6,
 *                                                                          FILTER_FLAG_NO_PRIV_RANGE,
 *                                                                          FILTER_FLAG_NO_RES_RANGE
 * 
 * 6. "validate_mac_address"  FILTER_VALIDATE_MAC               default,      ======================    Paotvrdjuje vredonsti da su MAC adrese
 * 
 * 
 * 
 * 
 * 7. "validate_regexp"     FILTER_VALIDATE_REGEXP              default,      ====================      Validates value against regexp, a Perl-compatible regular expression.
 *                                                              regexp
 * 
 * 
 * 
 * 
 * 8.   "validate_url"      FILTER_VALIDATE_URL                 default,        FILTER_FLAG_PATH_REQUIRED,      Validates value as URL (according to » http://www.faqs.org/rfcs/rfc2396), optionally with required components. Beware a valid URL may not specify the HTTP protocol http:// so further validation may be required to determine the URL uses an expected protocol, e.g. ssh:// or mailto:. Note that the function will only find ASCII URLs to be valid; internationalized domain names (containing non-ASCII characters) will fail.
 *                                                                              FILTER_FLAG_QUERY_REQUIRED
 *  */



//Note:

/*As of PHP 5.4.11, the numbers +0 and -0 validate as both integers as well as floats (using FILTER_VALIDATE_FLOAT and FILTER_VALIDATE_INT). 
 * Before PHP 5.4.11 they only validated as floats (using FILTER_VALIDATE_FLOAT).
*/


/*
http://php.net/manual/en/filter.filters.validate.php
 * 
FILTER_VALIDATE_URL does not work with URNs, examples of valid URIs according to RFC3986 and if they are accepted by FILTER_VALIDATE_URL: 

[PASS] ftp://ftp.is.co.za.example.org/rfc/rfc1808.txt 
[PASS] gopher://spinaltap.micro.umn.example.edu/00/Weather/California/Los%20Angeles 
[PASS] http://www.math.uio.no.example.net/faq/compression-faq/part1.html 
[PASS] mailto:mduerst@ifi.unizh.example.gov 
[PASS] news:comp.infosystems.www.servers.unix 
[PASS] telnet://melvyl.ucop.example.edu/ 
[PASS] http://www.ietf.org/rfc/rfc2396.txt 
[PASS] ldap://[2001:db8::7]/c=GB?objectClass?one 
[PASS] mailto:John.Doe@example.com 
[PASS] news:comp.infosystems.www.servers.unix 
[FAIL] tel:+1-816-555-1212 
[PASS] telnet://192.0.2.16:80/ 
[FAIL] urn:oasis:names:specification:docbook:dtd:xml:4.1.2
 * 
 * 
 * 
 */