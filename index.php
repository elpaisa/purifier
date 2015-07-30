<?php
/**
 * Created by PhpStorm.
 * User: jdiaz
 * Date: 7/30/15
 * Time: 9:16 AM
 */

require_once 'classes/Purifier.php';

$purifier = new Purifier();

$inputPass  = 'testUser123$%';
$saltedPass = $purifier->encryptPassword($inputPass);

echo "<strong>Input pass:</strong> $inputPass <br />";
echo "<strong>Salted pass:</strong> $saltedPass \n";

