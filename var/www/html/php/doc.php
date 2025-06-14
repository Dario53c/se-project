<?php
require("../vendor/autoload.php");

// Scan the directory containing your Controller.php
$openapi = \OpenApi\Generator::scan([
    __DIR__ . '/../php'  // Directory containing Controller.php
]);

header('Content-Type: application/json');
echo $openapi->toJson();