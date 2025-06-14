<?php
require("../vendor/autoload.php");

$openapi = \OpenApi\Generator::scan(['C:\xampp\htdocs\se-project\php']);

header('Content-Type: application/json');
echo $openapi->toJson();