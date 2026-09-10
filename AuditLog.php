<?php

namespace dokuwiki\plugin\statistics;

use dokuwiki\plugin\sqlite\SQLiteDB;
use helper_plugin_statistics;

/**
 * Persists audit rows captured from DokuWiki's native Logger
 *
 * Deliberately independent of the statistics Logger, which refuses bots and
 * sessionless requests. Audit events from API calls and CLI runs must still land.
 */
class AuditLog
{
    protected SQLiteDB $db;

    public function __construct(helper_plugin_statistics $hlp)
    {
        $this->db = $hlp->getDB();
    }

    /**
     * Insert one audit row
     *
     * @param array $row keys: dt (unix int), facility, user, ip, action, subject, message, details, file, line
     */
    public function store(array $row): void
    {
        $this->db->exec(
            'INSERT INTO audit (
                dt, facility, user, ip, action, subject, message, details, file, line
             ) VALUES (
                DATETIME(:dt, \'unixepoch\'), :facility, :user, :ip, :action, :subject, :message, :details, :file, :line
             )',
            [
                'dt' => (int)$row['dt'],
                'facility' => (string)$row['facility'],
                'user' => (string)$row['user'],
                'ip' => (string)$row['ip'],
                'action' => (string)$row['action'],
                'subject' => (string)$row['subject'],
                'message' => (string)$row['message'],
                'details' => (string)$row['details'],
                'file' => (string)($row['file'] ?? ''),
                'line' => (int)($row['line'] ?? 0),
            ]
        );
    }

    /**
     * Delete rows older than the given number of days
     */
    public function prune(int $days): void
    {
        if ($days <= 0) return;
        $this->db->exec("DELETE FROM audit WHERE dt < datetime('now', '-$days days')");
    }
}
