<?php
require dirname(__DIR__) . '/assets/staging-policy.php';
require dirname(__DIR__) . '/assets/staging-flag.php';

function expect(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

// A new staging copy: everything outside is off, and the flag says so.
$off = (new CloudPanelCompanionStagingFlag(new CloudPanelCompanionStagingPolicy()))->lines();
expect(in_array('Emails are not sent.', $off, true), 'Mail off');
expect(in_array('Requests to other websites are blocked.', $off, true), 'Requests blocked');
expect(in_array('WooCommerce webhooks are not delivered.', $off, true), 'Webhooks off');
expect(count(preg_grep('/^Payments are switched off/', $off)) === 1, 'Payments off');
expect(count(preg_grep('/^Scheduled tasks/', $off)) === 1, 'Scheduled tasks off');

// Allowances are listed exactly as the policy holds them, one entry per address with its methods.
$on = (new CloudPanelCompanionStagingFlag(new CloudPanelCompanionStagingPolicy([
    'mail_enabled' => true, 'mail_recipients' => ['test@example.com'],
    'http_enabled' => true, 'http_rules' => [
        ['host' => 'api.example.com', 'path' => '/v3/', 'methods' => ['GET']],
        ['host' => 'api.example.com', 'path' => '/v3', 'methods' => ['POST']],
        ['host' => 'broken'],
    ],
    'webhooks_enabled' => false, 'webhook_rules' => [['host' => 'hooks.example.com', 'path' => '/in', 'methods' => ['POST']]],
])))->lines();
expect(in_array('Emails are not sent. Those to test@example.com are kept in the Companion\'s test inbox.', $on, true), 'Test inbox named');
expect(in_array('Requests to other websites are blocked, except: api.example.com/v3 (GET, POST).', $on, true), 'Allowed requests listed and merged');
expect(in_array('WooCommerce webhooks are not delivered.', $on, true), 'Webhook rules ignored while webhooks are off');

// Switching a kind off hides its saved rules, as the guard does.
$saved = (new CloudPanelCompanionStagingFlag(new CloudPanelCompanionStagingPolicy([
    'http_enabled' => false, 'http_rules' => [['host' => 'api.example.com', 'path' => '/v3', 'methods' => ['GET']]],
])))->lines();
expect(in_array('Requests to other websites are blocked.', $saved, true), 'Saved rules not listed while off');
echo "PASS: staging flag lists what is off and exactly what the policy allows\n";
