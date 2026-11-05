<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
session_start();

function e(string|int|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verify_csrf(): void
{
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
        http_response_code(419);
        exit('Invalid form token.');
    }
}

function user(): ?array
{
    static $current;
    if ($current === false) return null;
    if ($current === null && isset($_SESSION['user_id'])) {
        $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        $current = $stmt->fetch() ?: false;
    }
    return $current ?: null;
}

function require_login(): array
{
    $current = user();
    if (!$current) {
        header('Location: index.php?page=login');
        exit;
    }
    return $current;
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'] = compact('type', 'message');
}

function consume_flash(): ?array
{
    $value = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $value;
}

function audit(int $userId, string $action, ?int $itemId = null, ?string $details = null): void
{
    db()->prepare('INSERT INTO activity_logs (user_id, action, item_id, details, ip_address) VALUES (?, ?, ?, ?, ?)')
        ->execute([$userId, $action, $itemId, $details, $_SERVER['REMOTE_ADDR'] ?? null]);
}

function format_bytes(int $bytes): string
{
    if ($bytes < 1024) return $bytes . ' B';
    $units = ['KB', 'MB', 'GB', 'TB'];
    $power = min((int) floor(log($bytes, 1024)), count($units));
    return number_format($bytes / (1024 ** $power), $power > 1 ? 1 : 0) . ' ' . $units[$power - 1];
}

function redirect_home(): never
{
    header('Location: index.php');
    exit;
}
