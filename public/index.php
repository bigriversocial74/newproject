<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

echo json_encode([
    'service' => 'VP3.me',
    'phase' => 2,
    'status' => 'foundation-ready',
    'endpoints' => [
        'register' => '/api/auth/register.php',
        'login' => '/api/auth/login.php',
    ],
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
