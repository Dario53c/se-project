<?php
require("../vendor/autoload.php");

$openapi = \OpenApi\Generator::scan(['https://se-project-7kfh.onrender.com/php']);

header('Content-Type: application/json');
echo $openapi->toJson();