<?php

/**
 * @OA\Info(
 *     title="SE Project API",
 *     version="1.0.0",
 *     description="Fitness Tracker API Documentation"
 * )
 * @OA\Server(
 *     url=($_SERVER['HTTP_HOST'] === 'localhost' ? 'http://localhost' : 'https://se-project-7kfh.onrender.com'),
 *     description=($_SERVER['HTTP_HOST'] === 'localhost' ? 'Local Development' : 'Production Server')
 * )
 * @OA\SecurityScheme(
 *     securityScheme="sessionAuth",
 *     type="apiKey",
 *     in="cookie",
 *     name="PHPSESSID"
 * )
 */