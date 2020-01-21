<?php
// www.example.com/proizvod.php?id=15';DELETE FROM proizvodi;--
 
// Prvo proveramo da li je uopšte zadat obezan parametar
if(empty($_GET['id'])) {
    // prikaži 404
}
 
// kastovanje
$id = (int) $_GET['id']; // 15
 
// optimizacija: sprečavamo nepotreban upit
if($id <= 0) {
   // prikaži 404
}
 
// sada je upit siguran
$sql = "SELECT * FROM proizvodi WHERE id= '$id'";
 
//...
