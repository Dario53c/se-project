<?php
require("../vendor/autoload.php");

require __DIR__ . '/swagger-base.php';

header('Content-Type: application/json');
$openapi = \OpenApi\Generator::scan(['/var/www/html/php']);

header('Content-Type: application/json');
echo $openapi->toJson();