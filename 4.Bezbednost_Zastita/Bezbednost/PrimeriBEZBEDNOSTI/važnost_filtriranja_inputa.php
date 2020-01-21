<?php
// podaci sa forme
$ime = $_POST['ime'];
$email = $_POST['email'];
$tekst = $_POST['tekst'];
 
// Heder za ispis pošaljioca u mail klijentu
$heder = "From: $ime <$email> \n\r";
 
// slanje email-a na našu adresu
mail('kontakt@example.com', $tekst, $heder);


/* 
Ova skripta će svakako raditi očekivano, 
    ali samo ukoliko verujemo korisniku da će zaista uneti ispravne podatke. 
    Pošto mu ne smemo verovati, napadač veoma lako može iskoristiti ovakvu skriptu za slanje SPAM poruka sa našeg servera.
    Dovoljno je da umesto svog imena, ili email adrese unese nešto ovako:
 
    example@example.com> \n\r To: <example2@example.com> \n\r Bcc: <example3@example.com
 
 Jasno je da će se vrednost iz $email direktno kopirati u $header,
     i da će poruka biti poslata na onoliko adresa koliko napadač želi. 
    Važnost zaštite u ovom slučaju je veoma velika, svakako ne bi želeli da se sa našeg servera šalju SPAM poruke, 
 *  zbog kojih možemo biti označeni kao maliciozni i završiti na nekoj “crnoj listi”.
 */