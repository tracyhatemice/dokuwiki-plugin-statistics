<?php

namespace dokuwiki\plugin\statistics\test;

use dokuwiki\plugin\statistics\AuditLog;
use DokuWikiTest;
use helper_plugin_statistics;

/**
 * @group plugin_statistics
 * @group plugins
 */
class AuditLogTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    /** @var helper_plugin_statistics */
    protected $helper;

    public function setUp(): void
    {
        parent::setUp();
        $this->helper = plugin_load('helper', 'statistics');
        $this->helper->getDB()->exec('DELETE FROM audit');
    }

    protected function row(array $overrides = []): array
    {
        return array_merge([
            'dt' => time(),
            'facility' => 'unit_audit',
            'user' => 'alice',
            'ip' => '192.0.2.1',
            'action' => 'item_created',
            'subject' => 'abc123',
            'message' => 'alice item_created',
            'details' => '{"user":"alice","action":"item_created","itemId":"abc123"}',
            'file' => '',
            'line' => 0,
        ], $overrides);
    }

    public function testSchemaHasAuditTable()
    {
        $columns = array_column(
            $this->helper->getDB()->queryAll('PRAGMA table_info(audit)'),
            'name'
        );
        $this->assertSame(
            ['id', 'dt', 'facility', 'user', 'ip', 'action', 'subject', 'message', 'details', 'file', 'line'],
            $columns
        );
    }

    public function testHelperReturnsAuditLog()
    {
        $this->assertInstanceOf(AuditLog::class, $this->helper->getAuditLog());
        $this->assertSame($this->helper->getAuditLog(), $this->helper->getAuditLog());
    }

    public function testStoreWritesUtcTimestamp()
    {
        $this->helper->getAuditLog()->store($this->row(['dt' => 1_700_000_000]));

        $stored = $this->helper->getDB()->queryRecord('SELECT * FROM audit');
        $this->assertSame('2023-11-14 22:13:20', $stored['dt']);
        $this->assertSame('unit_audit', $stored['facility']);
        $this->assertSame('alice', $stored['user']);
        $this->assertSame('192.0.2.1', $stored['ip']);
        $this->assertSame('item_created', $stored['action']);
        $this->assertSame('abc123', $stored['subject']);
        $this->assertSame('alice item_created', $stored['message']);
        $this->assertSame('{"user":"alice","action":"item_created","itemId":"abc123"}', $stored['details']);
        $this->assertSame('', $stored['file']);
        $this->assertSame(0, (int)$stored['line']);
    }

    public function testPruneRemovesOnlyOldRows()
    {
        $log = $this->helper->getAuditLog();
        $log->store($this->row(['dt' => time() - 40 * 86400, 'message' => 'old']));
        $log->store($this->row(['dt' => time() - 10 * 86400, 'message' => 'recent']));
        $log->store($this->row(['dt' => time(), 'message' => 'now']));

        $log->prune(30);

        $messages = array_column(
            $this->helper->getDB()->queryAll('SELECT message FROM audit ORDER BY dt'),
            'message'
        );
        $this->assertSame(['recent', 'now'], $messages);
    }
}
