# Nimbus Vault

Nimbus Vault is a native PHP 8.3 + MySQL file storage starter for XAMPP, cPanel, or a conventional Apache host.

## Setup

1. Start Apache and MySQL in XAMPP.
2. Import [`database.sql`](./database.sql) in phpMyAdmin.
3. Confirm the database values in [`config.php`](./config.php).
4. Ensure `storage/` is writable by Apache.
5. Open `http://localhost/storage_system/`.

The application stores generated names on disk and keeps the original filename in MySQL. Authentication uses PHP sessions, password hashing, prepared statements, CSRF tokens, MIME detection, and per-user ownership checks.
