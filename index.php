<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

$page = $_GET['page'] ?? 'dashboard';
$current = user();

if ($page === 'logout') {
    session_destroy();
    header('Location: index.php?page=login');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'login') {
        $stmt = db()->prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
        $stmt->execute([trim($_POST['email'] ?? '')]);
        $candidate = $stmt->fetch();
        if ($candidate && password_verify($_POST['password'] ?? '', $candidate['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $candidate['id'];
            audit((int) $candidate['id'], 'login');
            redirect_home();
        }
        flash('error', 'The email or password is not correct.');
        header('Location: index.php?page=login');
        exit;
    }

    if ($action === 'register') {
        $name = trim($_POST['name'] ?? '');
        $email = strtolower(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';
        if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            flash('error', 'Enter a name, valid email, and password with at least 8 characters.');
        } else {
            try {
                db()->prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
                    ->execute([$name, $email, password_hash($password, PASSWORD_DEFAULT)]);
                flash('success', 'Account created. You can now sign in.');
                header('Location: index.php?page=login');
                exit;
            } catch (PDOException $exception) {
                flash('error', $exception->getCode() === '23000' ? 'That email is already registered.' : 'Unable to create account.');
            }
        }
        header('Location: index.php?page=register');
        exit;
    }

    $current = require_login();
    if ($action === 'create_folder') {
        $name = trim($_POST['name'] ?? '');
        $parent = (int) ($_POST['parent_id'] ?? 0);
        if ($name !== '' && preg_match('/^[^\/\\\\]{1,120}$/', $name)) {
            db()->prepare('INSERT INTO items (user_id, parent_id, name, item_type) VALUES (?, NULLIF(?, 0), ?, "folder")')
                ->execute([$current['id'], $parent, $name]);
            audit((int) $current['id'], 'folder_created', (int) db()->lastInsertId(), $name);
            flash('success', 'Folder created.');
        } else flash('error', 'Use a valid folder name.');
        redirect_home();
    }
    if ($action === 'toggle_star') {
        $stmt = db()->prepare('UPDATE items SET is_starred = NOT is_starred WHERE id = ? AND user_id = ? AND deleted_at IS NULL');
        $stmt->execute([(int) $_POST['item_id'], $current['id']]);
        audit((int) $current['id'], 'star_toggled', (int) $_POST['item_id']);
        redirect_home();
    }
    if ($action === 'trash') {
        $stmt = db()->prepare('UPDATE items SET deleted_at = NOW() WHERE id = ? AND user_id = ?');
        $stmt->execute([(int) $_POST['item_id'], $current['id']]);
        audit((int) $current['id'], 'moved_to_trash', (int) $_POST['item_id']);
        redirect_home();
    }
    if ($action === 'restore') {
        db()->prepare('UPDATE items SET deleted_at = NULL WHERE id = ? AND user_id = ?')->execute([(int) $_POST['item_id'], $current['id']]);
        audit((int) $current['id'], 'restored_item', (int) $_POST['item_id']);
        redirect_home();
    }
    if ($action === 'upload') {
        $file = $_FILES['file'] ?? null;
        if (!$file || $file['error'] !== UPLOAD_ERR_OK || $file['size'] > MAX_UPLOAD_BYTES) {
            flash('error', 'Upload failed. Files must be smaller than 50 MB.');
        } else {
            $name = basename($file['name']);
            $safeName = preg_replace('/[^A-Za-z0-9._ -]/', '_', $name) ?: 'file';
            $stored = bin2hex(random_bytes(18)) . '_' . $safeName;
            $target = STORAGE_ROOT . $stored;
            if (move_uploaded_file($file['tmp_name'], $target)) {
                $mime = (new finfo(FILEINFO_MIME_TYPE))->file($target) ?: 'application/octet-stream';
                db()->prepare('INSERT INTO items (user_id, parent_id, name, item_type, stored_name, mime_type, size_bytes) VALUES (?, NULLIF(?, 0), ?, "file", ?, ?, ?)')
                    ->execute([$current['id'], (int) $_POST['parent_id'], $safeName, $stored, $mime, $file['size']]);
                audit((int) $current['id'], 'file_uploaded', (int) db()->lastInsertId(), $safeName);
                flash('success', 'File uploaded.');
            } else flash('error', 'The server could not save the upload.');
        }
        redirect_home();
    }
}

if ($page === 'download') {
    $current = require_login();
    $stmt = db()->prepare('SELECT * FROM items WHERE id = ? AND user_id = ? AND item_type = "file" AND deleted_at IS NULL');
    $stmt->execute([(int) ($_GET['id'] ?? 0), $current['id']]);
    $item = $stmt->fetch();
    if (!$item || !is_file(STORAGE_ROOT . $item['stored_name'])) { http_response_code(404); exit('File not found.'); }
    audit((int) $current['id'], 'file_downloaded', (int) $item['id']);
    header('Content-Type: ' . $item['mime_type']);
    header('Content-Length: ' . $item['size_bytes']);
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $item['name']) . '"');
    readfile(STORAGE_ROOT . $item['stored_name']);
    exit;
}

if ($page === 'share') {
    $token = $_GET['token'] ?? '';
    $stmt = db()->prepare('SELECT s.*, i.name, i.mime_type, i.size_bytes, i.stored_name FROM shares s JOIN items i ON i.id = s.item_id WHERE s.token = ? AND s.expires_at > NOW()');
    $stmt->execute([$token]);
    $share = $stmt->fetch();
    if (!$share) { http_response_code(404); exit('This share link is unavailable or expired.'); }
    $unlocked = !$share['password_hash'];
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $unlocked = password_verify($_POST['share_password'] ?? '', $share['password_hash'] ?? '');
        if (!$unlocked) exit('Incorrect password.');
        $_SESSION['share_unlocked'][$token] = true;
    }
    $downloadUrl = 'index.php?page=shared_download&token=' . urlencode($token);
    require __DIR__ . '/views/share.php';
    exit;
}

if ($page === 'shared_download') {
    $token = $_GET['token'] ?? '';
    $stmt = db()->prepare('SELECT s.*, i.name, i.mime_type, i.size_bytes, i.stored_name FROM shares s JOIN items i ON i.id = s.item_id WHERE s.token = ? AND s.expires_at > NOW()');
    $stmt->execute([$token]);
    $share = $stmt->fetch();
    if (!$share || ($share['password_hash'] && !($_SESSION['share_unlocked'][$token] ?? false))) {
        http_response_code(403);
        exit('This share link requires authentication.');
    }
    if (!is_file(STORAGE_ROOT . $share['stored_name'])) { http_response_code(404); exit('File not found.'); }
    header('Content-Type: ' . $share['mime_type']);
    header('Content-Length: ' . $share['size_bytes']);
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $share['name']) . '"');
    readfile(STORAGE_ROOT . $share['stored_name']);
    exit;
}

$flash = consume_flash();
if ($page === 'login' || $page === 'register') {
    require __DIR__ . '/views/layout.php';
    exit;
}

$current = $current ?: require_login();
$folderId = (int) ($_GET['folder'] ?? 0);
$view = $_GET['view'] ?? 'all';
$search = trim($_GET['q'] ?? '');
$where = ['user_id = ?', 'deleted_at IS NULL'];
$params = [$current['id']];
if ($view === 'trash') $where = ['user_id = ?', 'deleted_at IS NOT NULL'];
if ($view === 'starred') { $where[] = 'is_starred = 1'; }
if ($view === 'recent') { $where[] = 'created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)'; }
if ($folderId > 0 && $view === 'all') { $where[] = 'parent_id = ?'; $params[] = $folderId; }
if ($search !== '') { $where[] = 'name LIKE ?'; $params[] = '%' . $search . '%'; }
$stmt = db()->prepare('SELECT * FROM items WHERE ' . implode(' AND ', $where) . ' ORDER BY item_type DESC, name ASC');
$stmt->execute($params);
$items = $stmt->fetchAll();
$statsStmt = db()->prepare('SELECT COUNT(*) item_count, COALESCE(SUM(size_bytes), 0) used_bytes FROM items WHERE user_id = ? AND item_type = "file" AND deleted_at IS NULL');
$statsStmt->execute([$current['id']]);
$stats = $statsStmt->fetch();
$flash = consume_flash();
require __DIR__ . '/views/layout.php';
