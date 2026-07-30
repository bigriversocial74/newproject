<?php

declare(strict_types=1);

use Vp3\Http\ControlCenterEndpoint;
use Vp3\Http\JsonResponse;

$container = require __DIR__ . '/_bootstrap.php';
ControlCenterEndpoint::requireMethod('POST');

try {
    $payload = ControlCenterEndpoint::payload();
    $account = ControlCenterEndpoint::accountContext($container, $payload);
    $action = strtolower(trim((string) ($payload['action'] ?? '')));
    $service = $container['pod_provisioning'];
    $pdo = $container['database']->pdo();

    if ($action === 'provision') {
        $statement = $pdo->prepare(
            "SELECT d.id AS domain_id,l.id AS license_id
             FROM domain_registrations d
             JOIN licenses l ON l.domain_registration_id=d.id AND l.product_type='pod'
             WHERE d.account_id=:account AND d.public_id=:domain
               AND d.status IN ('active','grace') AND l.status IN ('active','grace')
             LIMIT 1"
        );
        $statement->execute([
            'account' => $account['account_id'],
            'domain' => trim((string) ($payload['domain_public_id'] ?? '')),
        ]);
        $target = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($target)) {
            throw new RuntimeException('An eligible licensed Domain was not found for POD provisioning.');
        }
        $result = $service->enqueue(
            $account['account_id'],
            (int) $target['domain_id'],
            (int) $target['license_id'],
            ControlCenterEndpoint::requestId($payload),
            ControlCenterEndpoint::idempotencyKey($payload)
        );
        JsonResponse::send(['data' => $result]);
    }

    if (in_array($action, ['pause', 'resume', 'retry'], true)) {
        $statement = $pdo->prepare(
            'SELECT id,public_id FROM pod_provisioning_jobs WHERE account_id=:account AND public_id=:public LIMIT 1'
        );
        $statement->execute([
            'account' => $account['account_id'],
            'public' => trim((string) ($payload['job_public_id'] ?? '')),
        ]);
        $job = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($job)) {
            throw new RuntimeException('The POD provisioning job was not found.');
        }
        $requestId = ControlCenterEndpoint::requestId($payload);
        match ($action) {
            'pause' => $service->pause($account['account_id'], (int) $job['id'], $requestId),
            'resume' => $service->resume($account['account_id'], (int) $job['id'], $requestId),
            'retry' => $service->retry($account['account_id'], (int) $job['id'], $requestId),
        };
        $status = $pdo->prepare('SELECT status,current_stage,attempts,updated_at FROM pod_provisioning_jobs WHERE id=:id');
        $status->execute(['id' => $job['id']]);
        JsonResponse::send(['data' => ['job_public_id' => (string) $job['public_id'], ...$status->fetch(PDO::FETCH_ASSOC)]]);
    }

    if ($action === 'rollback') {
        if (($payload['confirmation'] ?? '') !== 'ROLLBACK') {
            throw new RuntimeException('POD rollback requires the exact confirmation ROLLBACK.');
        }
        $statement = $pdo->prepare(
            'SELECT id,public_id FROM pod_deployments WHERE account_id=:account AND public_id=:public LIMIT 1'
        );
        $statement->execute([
            'account' => $account['account_id'],
            'public' => trim((string) ($payload['deployment_public_id'] ?? '')),
        ]);
        $deployment = $statement->fetch(PDO::FETCH_ASSOC);
        if (!is_array($deployment)) {
            throw new RuntimeException('The POD deployment was not found.');
        }
        $result = $service->enqueueRollback(
            $account['account_id'],
            (int) $deployment['id'],
            ControlCenterEndpoint::requestId($payload),
            ControlCenterEndpoint::idempotencyKey($payload)
        );
        JsonResponse::send(['data' => $result]);
    }

    throw new RuntimeException('The requested POD action is not supported.');
} catch (Throwable $exception) {
    ControlCenterEndpoint::sendException($exception);
}
