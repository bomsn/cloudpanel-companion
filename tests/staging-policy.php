<?php
require dirname(__DIR__) . '/assets/staging-policy.php';

function expect(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
$off = new CloudPanelCompanionStagingPolicy();
expect(!$off->allowsMail(['to' => 'test@example.com']), 'Mail defaults off');
expect(!$off->allowsHttp('https://example.com/api', 'GET'), 'HTTP defaults off');
expect(!$off->webhooksEnabled(), 'Webhooks default off');
$on = new CloudPanelCompanionStagingPolicy([
    'mail_enabled' => true, 'mail_recipients' => ['test@example.com'],
    'http_enabled' => true, 'http_rules' => [['host' => 'example.com', 'path' => '/api', 'methods' => ['GET']]],
]);
expect($on->allowsMail(['to' => 'Tester <test@example.com>']), 'Approved test recipient');
expect(!$on->allowsMail(['to' => 'test@example.com', 'headers' => 'Bcc: customer@example.com']), 'Unapproved Bcc blocked');
expect(!$on->allowsMail(['to' => 'test@example.com,customer@example.com']), 'Mixed recipient list blocked');
expect($on->allowsHttp('https://example.com/api/items', 'GET'), 'Approved read');
foreach (['https://example.com/api/items/../live', 'https://example.com/api/%2e%2e/live',
          'https://example.com/api-other', 'https://other.example.com/api',
          'https://user:pass@example.com/api', 'http://example.com/api'] as $url) {
    expect(!$on->allowsHttp($url, 'GET'), 'Unapproved URL blocked');
}
expect(!$on->allowsHttp('https://example.com/api', 'POST'), 'Unapproved write blocked');
$webhooks = new CloudPanelCompanionStagingPolicy([
    'webhooks_enabled' => true,
    'webhook_rules' => [['host' => 'test.example.com', 'path' => '/hook', 'methods' => ['POST']]],
]);
expect($webhooks->allowsHttp('https://test.example.com/hook', 'POST'), 'Webhook target independent of general HTTP');
expect(!$webhooks->allowsHttp('https://example.com/api', 'GET'), 'Webhook permission does not enable general HTTP');
echo "PASS: staging defaults, recipient controls, Bcc, destination/method limits and separate webhooks\n";
