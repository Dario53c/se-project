<?php
require __DIR__ . '/../vendor/autoload.php';

/**
 * @OA\Info(
 *     title="SE Project API",
 *     version="1.0.0",
 *     description="Fitness Tracker API Documentation"
 * )
 * @OA\Server(
 *     url="https://se-project-7kfh.onrender.com",
 *     description="Production Server"
 * )
 */

$openapi = \OpenApi\Generator::scan([__DIR__ . '/../php']); // Path to your controllers
header('Content-Type: application/json');
echo $openapi->toJson();