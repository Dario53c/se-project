<?php
/**
 * @OA\Info(
 *     title="SE Project API",
 *     version="1.0.0",
 *     description="Fitness Tracker API Documentation"
 * )
 * @OA\Server(
 *     url="https://se-project-7kfh.onrender.com",
 *     description="Production server"
 * )
 * @OA\SecurityScheme(
 *     securityScheme="sessionAuth",
 *     type="apiKey",
 *     in="cookie",
 *     name="PHPSESSID"
 * )
 */