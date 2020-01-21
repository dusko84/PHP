<?php
/*cicenje niza, tj. vraca samo brojne karaktere*/
$tests = array(
    "42",
    1337,
    0x539,
    02471,
    0b10100111001,
    1337e0,
    "not numeric",
    array(),
    9.1
);

foreach ($tests as $element) {
    if (is_numeric($element)) {
        echo "</br>'{$element}' is numeric", PHP_EOL;
    } else {
        echo "</br>'{$element}' is NOT numeric", PHP_EOL;
    }
}
