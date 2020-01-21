<?php
/* 
Vraca imena ID za filtere
 * int filter_id ( string $filtername )
 */

// filter_list();   metoda koja vraca listu svih ID filtera
$filters = filter_list(); 

foreach($filters as $filter_name) { 
    echo $filter_name .": ".filter_id($filter_name) ."<br>"; 
} 