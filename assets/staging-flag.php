<?php
/**
 * The "Staging" flag in the admin bar. Hovering it lists what this copy does not do, in
 * plain words. Everything listed is read from the policy the guard enforces, or is one of
 * the guard's fixed safeguards, so the flag always matches what is really switched off.
 */
final class CloudPanelCompanionStagingFlag
{
    private const NODE = 'companion-staging';

    public function __construct(private CloudPanelCompanionStagingPolicy $policy) {}

    public function register(): void
    {
        add_action('admin_bar_menu', [$this, 'addNodes'], 1000);
        add_action('admin_bar_init', [$this, 'addStyle']);
    }

    /** @return string[] One sentence per safeguard. */
    public function lines(): array
    {
        $recipients = $this->policy->mailRecipients();
        $lines = [
            $recipients
                ? 'Emails are not sent. Those to ' . implode(', ', $recipients) . ' are kept in the Companion\'s test inbox.'
                : 'Emails are not sent.',
            $this->allowedList('Requests to other websites are blocked', $this->policy->httpRules()),
            $this->allowedList('WooCommerce webhooks are not delivered', $this->policy->webhookRules()),
        ];
        // The guard's fixed safeguards (000-companion-staging.php).
        $lines[] = 'Payments are switched off: checkout offers no payment method.';
        $lines[] = 'Scheduled tasks and background jobs do not run on their own.';
        $lines[] = 'Search engines are asked not to index this copy.';
        return $lines;
    }

    public function addNodes(WP_Admin_Bar $bar): void
    {
        $bar->add_node(['id' => self::NODE, 'title' => 'Staging', 'parent' => 'top-secondary',
            'meta' => ['title' => 'A staging copy with safeguards: hover for what it does not do.']]);
        foreach ($this->lines() as $number => $line) {
            $bar->add_node(['id' => self::NODE . '-' . $number, 'parent' => self::NODE, 'title' => esc_html($line)]);
        }
    }

    public function addStyle(): void
    {
        $node = '#wpadminbar #wp-admin-bar-' . self::NODE;
        wp_add_inline_style('admin-bar', $node . ' > .ab-item { background: #dba617; color: #1d2327; font-weight: 600; }'
            . $node . ':hover > .ab-item, ' . $node . '.hover > .ab-item { background: #c08f00; color: #1d2327; }'
            . $node . ' .ab-submenu .ab-item { width: 380px; height: auto; white-space: normal; line-height: 1.5; padding-top: 4px; padding-bottom: 4px; }');
    }

    /** "<what is blocked>." or "<what is blocked>, except: host/path (methods); ...". */
    private function allowedList(string $blocked, array $rules): string
    {
        $allowed = [];
        foreach ($rules as $rule) {
            $target = $rule['host'] . rtrim($rule['path'], '/');
            $allowed[$target] = array_unique(array_merge($allowed[$target] ?? [], $rule['methods']));
        }
        if (!$allowed) {
            return $blocked . '.';
        }
        $items = [];
        foreach ($allowed as $target => $methods) {
            $items[] = $target . ' (' . implode(', ', $methods) . ')';
        }
        return $blocked . ', except: ' . implode('; ', $items) . '.';
    }
}
