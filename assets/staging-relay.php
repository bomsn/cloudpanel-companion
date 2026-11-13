<?php
/** Bounded client for the separately isolated staging transport. */
final class CloudPanelCompanionStagingRelay
{
    private static function call(array $request): array
    {
        $path = defined('CLOUDPANEL_COMPANION_STAGING_RELAY') ? CLOUDPANEL_COMPANION_STAGING_RELAY : '';
        if (!is_string($path) || !preg_match('~^/run/cloudpanel-companion-relay/[a-z][a-z0-9-]{2,30}/transport\.sock$~D', $path)) {
            throw new RuntimeException('Staging transport is not configured.');
        }
        $encoded = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
        if (strlen($encoded) > 1048576) {
            throw new RuntimeException('The staging test request exceeds the size limit.');
        }
        $connection = @stream_socket_client('unix://' . $path, $errno, $error, 2);
        if (!$connection) {
            throw new RuntimeException('Staging transport is unavailable.');
        }
        try {
            stream_set_timeout($connection, 20);
            $offset = 0;
            while ($offset < strlen($encoded)) {
                $written = fwrite($connection, substr($encoded, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Staging transport could not receive this request.');
                }
                $offset += $written;
            }
            $raw = fgets($connection, 4194306);
            if (!is_string($raw) || strlen($raw) > 4194304 || !str_ends_with($raw, "\n")) {
                throw new RuntimeException('Staging transport returned an invalid response.');
            }
            $response = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (($response['ok'] ?? false) !== true || !is_array($response['result'] ?? null)) {
                throw new RuntimeException('This test request was blocked or could not complete.');
            }
            return $response['result'];
        } finally {
            fclose($connection);
        }
    }

    public static function http(string $url, array $arguments): array|WP_Error
    {
        try {
            if (isset($arguments['stream']) && $arguments['stream']) {
                throw new RuntimeException('File-streaming requests are not supported by the staging relay.');
            }
            $headers = $arguments['headers'] ?? [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers = $headers->getAll();
            }
            if (!is_array($headers)) {
                throw new RuntimeException('Use structured request headers for staging tests.');
            }
            $body = $arguments['body'] ?? '';
            if (is_array($body)) {
                $body = http_build_query($body, '', '&');
                if (!array_filter(array_keys($headers), static fn($name) => strtolower((string) $name) === 'content-type')) {
                    $headers['Content-Type'] = 'application/x-www-form-urlencoded';
                }
            }
            if (!is_string($body)) {
                throw new RuntimeException('Unsupported staging request body.');
            }
            $result = self::call(['operation' => 'http', 'url' => $url,
                'method' => strtoupper($arguments['method'] ?? 'GET'), 'headers' => (object) $headers,
                'body' => base64_encode($body)]);
            $body = base64_decode($result['body'], true);
            if (!is_string($body)) {
                throw new RuntimeException('Invalid staging response body.');
            }
            $headers = [];
            $cookies = [];
            foreach ($result['headers'] as [$name, $value]) {
                $key = strtolower($name);
                if ($key === 'set-cookie') {
                    $cookies[] = new WP_Http_Cookie($value, $url);
                }
                $headers[$key] = isset($headers[$key]) ? $headers[$key] . ', ' . $value : $value;
            }
            return ['headers' => new \WpOrg\Requests\Utility\CaseInsensitiveDictionary($headers),
                'body' => $body, 'response' => ['code' => (int) $result['status'], 'message' => $result['reason']],
                'cookies' => $cookies, 'filename' => null];
        } catch (Throwable $error) {
            return new WP_Error('companion_staging_transport', 'The approved staging request could not complete. Check the staging controls and endpoint.');
        }
    }

    public static function mail(array $attributes): bool
    {
        try {
            if (!empty($attributes['attachments'])) {
                throw new RuntimeException('Email attachments are not supported in capture mode.');
            }
            $recipients = [];
            foreach ((array) ($attributes['to'] ?? []) as $line) {
                $recipients = array_merge($recipients, explode(',', $line));
            }
            $headers = $attributes['headers'] ?? [];
            $headers = is_array($headers) ? $headers : preg_split('/\r?\n/', (string) $headers);
            foreach ($headers as $header) {
                if (preg_match('/^\s*(?:cc|bcc)\s*:(.*)$/i', $header, $match)) {
                    $recipients = array_merge($recipients, explode(',', $match[1]));
                }
            }
            $result = self::call(['operation' => 'mail', 'recipients' => array_map('trim', $recipients),
                'subject' => (string) ($attributes['subject'] ?? ''), 'body' => (string) ($attributes['message'] ?? '')]);
            return ($result['captured'] ?? false) === true;
        } catch (Throwable $error) {
            return false;
        }
    }
}
