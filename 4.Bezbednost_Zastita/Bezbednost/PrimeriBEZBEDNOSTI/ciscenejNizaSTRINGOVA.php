<?php
/*dakl ova metoda citi niz stringova tako sto proverava da li su samo slovni karakteri i vraca ih */

    $strings = array('KjgWZC', 'arf12');
        foreach ($strings as $testcase) {
        if (ctype_alpha($testcase)) {
        echo "The string $testcase consists of all letters.\n";
        } else {
            echo "The string $testcase does not consist of all letters.\n";
        }
        }


