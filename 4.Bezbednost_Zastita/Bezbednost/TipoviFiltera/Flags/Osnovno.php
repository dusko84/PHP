<?php

/* 
 
                                List of filter flags
 * 
 * 
    ID                                      Used with                                           Description
FILTER_FLAG_STRIP_LOW               FILTER_SANITIZE_ENCODED,                    Strips characters that have a numerical value <32.
 *                                  FILTER_SANITIZE_SPECIAL_CHARS, 
 *                                  FILTER_SANITIZE_STRING, 
 *                                  FILTER_UNSAFE_RAW	


FILTER_FLAG_STRIP_HIGH              FILTER_SANITIZE_ENCODED,                    Strips characters that have a numerical value >127.
 *                                  FILTER_SANITIZE_SPECIAL_CHARS,  
 *                                  FILTER_SANITIZE_STRING, 
 *                                  FILTER_UNSAFE_RAW	


FILTER_FLAG_ALLOW_FRACTION          FILTER_SANITIZE_NUMBER_FLOAT                Allows a period (.) as a fractional separator in numbers.

 * 
FILTER_FLAG_ALLOW_THOUSAND          FILTER_SANITIZE_NUMBER_FLOAT,               Allows a comma (,) as a thousands separator in numbers.
 *                                  FILTER_VALIDATE_FLOAT               

 * 
FILTER_FLAG_ALLOW_SCIENTIFIC        FILTER_SANITIZE_NUMBER_FLOAT            Allows an e or E for scientific notation in numbers.

 * 
FILTER_FLAG_NO_ENCODE_QUOTES        FILTER_SANITIZE_STRING                  If this flag is present, single (') and double (") quotes will not be encoded.


 * 
FILTER_FLAG_ENCODE_LOW              FILTER_SANITIZE_ENCODED,                Encodes all characters with a numerical value <32.
 *                                  FILTER_SANITIZE_STRING, 
 *                                  FILTER_SANITIZE_RAW	

 * 
FILTER_FLAG_ENCODE_HIGH             FILTER_SANITIZE_ENCODED,               Encodes all characters with a numerical value >127.
 *                                  FILTER_SANITIZE_SPECIAL_CHARS, 
 *                                  FILTER_SANITIZE_STRING, 
 *                                  FILTER_SANITIZE_RAW

 * 
FILTER_FLAG_ENCODE_AMP              FILTER_SANITIZE_STRING,                 Encodes ampersands (&).
 *                                  FILTER_SANITIZE_RAW	

 * 
FILTER_NULL_ON_FAILURE              FILTER_VALIDATE_BOOLEAN                 Returns NULL for unrecognized boolean values.

 * 
FILTER_FLAG_ALLOW_OCTAL             FILTER_VALIDATE_INT                     Regards inputs starting with a zero (0) as octal numbers. This only allows the succeeding digits to be 0-7.

 * 
FILTER_FLAG_ALLOW_HEX               FILTER_VALIDATE_INT                     Regards inputs starting with 0x or 0X as hexadecimal numbers. This only allows succeeding characters to be a-fA-F0-9.

 * 
FILTER_FLAG_IPV4                    FILTER_VALIDATE_IP                      Allows the IP address to be in IPv4 format.

 * 
FILTER_FLAG_IPV6                    FILTER_VALIDATE_IP                      Allows the IP address to be in IPv6 format.

 * 
FILTER_FLAG_NO_PRIV_RANGE           FILTER_VALIDATE_IP                      Fails validation for the following private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
                                                                            Fails validation for the IPv6 addresses starting with FD or FC.


 * 
FILTER_FLAG_NO_RES_RANGE            FILTER_VALIDATE_IP                      Fails validation for the following reserved IPv4 ranges: 0.0.0.0/8, 169.254.0.0/16, 192.0.2.0/24 and 224.0.0.0/4. This flag does not apply to IPv6 addresses.

 * 
FILTER_FLAG_PATH_REQUIRED           FILTER_VALIDATE_URL                     Requires the URL to contain a path part.

 * 
FILTER_FLAG_QUERY_REQUIRED          FILTER_VALIDATE_URL                         Requires the URL to contain a query string.
 */



/*

 * Please note that FILTER_FLAG_HOST_REQUIRED and FILTER_FLAG_SCHEME_REQUIRED have disappeared. They were previously mentioned in the constants page but it seems that host and scheme are now required by default for the validate_url filter.
 * 
 *  */