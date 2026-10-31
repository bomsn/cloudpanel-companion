<?php
/** Staging permissions. Invalid or missing policy always denies external work. */
final class CloudPanelCompanionStagingPolicy
{
    public function __construct(private array $settings = []) {}

    public static function load(): self
    {
        $path = defined('CLOUDPANEL_COMPANION_STAGING_POLICY') ? CLOUDPANEL_COMPANION_STAGING_POLICY : '';
        if (!is_string($path) || !preg_match('~^/etc/cloudpanel-companion/sites/[a-z0-9-]+\.json$~D', $path) ||
            is_link($path) || !is_file($path) || realpath($path) !== $path ||
            fileowner($path) !== 0 || (fileperms($path) & 0022) !== 0 || filesize($path) > 65536) {
            return new self();
        }
        $data = json_decode((string) file_get_contents($path), true);
        return new self(is_array($data) ? $data : []);
    }

    public function webhooksEnabled(): bool
    {
        return ($this->settings['webhooks_enabled'] ?? false) === true;
    }

    public function allowsHttp(string $url, string $method): bool
    {
        if (preg_match('/[\x00-\x20\x7f]/', $url)) {
            return false;
        }
        $parts = parse_url($url);
        if (!$parts || strtolower($parts['scheme'] ?? '') !== 'https' ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) ||
            ($parts['port'] ?? 443) !== 443 || empty($parts['host'])) {
            return false;
        }
        $rules = [];
        if (($this->settings['http_enabled'] ?? false) === true) {
            $rules = is_array($this->settings['http_rules'] ?? null) ? $this->settings['http_rules'] : [];
        }
        if ($this->webhooksEnabled()) {
            $rules = array_merge($rules, is_array($this->settings['webhook_rules'] ?? null) ? $this->settings['webhook_rules'] : []);
        }
        $host = strtolower($parts['host']);
        $path = $parts['path'] ?? '/';
        // Encoded separators and dot segments can defeat a path allowlist when
        // the receiving server normalizes them. Require unambiguous paths.
        if (str_contains($path, '%') || str_contains($path, '\\') || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path)) {
            return false;
        }
        foreach ($rules as $rule) {
            if (!is_array($rule) || !is_string($rule['host'] ?? null) ||
                !is_string($rule['path'] ?? null) || !is_array($rule['methods'] ?? null)) {
                continue;
            }
            $prefix = rtrim($rule['path'], '/');
            if ($rule['host'] === $host && str_starts_with($rule['path'], '/') &&
                in_array(strtoupper($method), $rule['methods'], true) &&
                ($path === $prefix || str_starts_with($path, $prefix . '/'))) {
                return true;
            }
        }
        return false;
    }

    public function allowsMail(array $attributes): bool
    {
        if (($this->settings['mail_enabled'] ?? false) !== true ||
            !is_array($this->settings['mail_recipients'] ?? null)) {
            return false;
        }
        $recipients = (array) ($attributes['to'] ?? []);
        $headers = $attributes['headers'] ?? [];
        $headers = is_array($headers) ? $headers : preg_split('/\r?\n/', (string) $headers);
        foreach ($headers as $header) {
            if (!is_string($header) || str_contains($header, "\r") || str_contains($header, "\n")) {
                return false;
            }
            if (preg_match('/^\s*(?:cc|bcc)\s*:(.*)$/i', (string) $header, $match)) {
                $recipients[] = $match[1];
            }
        }
        if (!$recipients) {
            return false;
        }
        foreach ($recipients as $line) {
            if (!is_string($line) || str_contains($line, "\r") || str_contains($line, "\n")) {
                return false;
            }
            foreach (explode(',', $line) as $recipient) {
                $recipient = trim($recipient);
                if (preg_match('/^[^<>]*<([^<>]+)>$/D', $recipient, $match)) {
                    $recipient = trim($match[1]);
                }
                if (!filter_var($recipient, FILTER_VALIDATE_EMAIL) ||
                    !in_array(strtolower($recipient), $this->settings['mail_recipients'], true)) {
                    return false;
                }
            }
        }
        return true;
    }
}
