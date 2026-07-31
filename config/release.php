<?php

declare(strict_types=1);

return [
    'format' => 'vp3-platform-release-v2',
    'version' => '34.0.0',
    'schema_level' => 34,
    'minimum_php' => '8.2.0',
    'supported_databases' => [
        'mysql' => '8.0.0',
        'mariadb' => '10.11.0',
    ],
    'migration_tail' => 'migrations/20260731_phase34_release_deployment_control_center.sql',
    'installer_path' => 'database/vp3-single-install.sql',
    'migration_manifest_path' => 'database/single-install-manifest.txt',
];
