<?php
/*
  Konkretno, ukoliko imamo stranicu koja na osnovu URL komande, odnosno zadatog ID parametra, ispisuje informacije o proizvodu i ukoliko nismo proverili da se zaista radi o ID parametru koji je brojčana vrednost (u najvećim slučajevima jeste), napadač lako može izazvati greške u radu aplikacije, pa čak i SQL injection, odnosno izmenu samog upita za “dohvatanje” informacija o proizvodu i tako ugroziti sigurnost aplikacije.
                Primer takvog kôda može izgledati ovako:
  */

                        // www.example.com/proizvod.php?id=15';DELETE FROM proizvodi;--

                        $id = $_GET['id'];
                        $sql = "SELECT * FROM proizvodi WHERE id= '$id'";

                        //...

//Jasno je da bi se umesto jednog, izvršila dva upita i $sql promenjiva bi izgledala ovako:

//SELECT * FROM proizvodi WHERE id = '15'; DELETE FROM proizvodi; --'
//SELECT * FROM proizvodi WHERE id = '15'; DELETE FROM proizvodi; 