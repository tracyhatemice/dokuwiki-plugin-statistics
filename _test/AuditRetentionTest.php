<?php

namespace dokuwiki\plugin\statistics\test;

use dokuwiki\Extension\Event;
use DokuWikiTest;
use helper_plugin_statistics;

/**
 * @group plugin_statistics
 * @group plugins
 */
class AuditRetentionTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    /** @var helper_plugin_statistics */
    protected $helper;

    public function setUp(): void
    {
        parent::setUp();
        $this->helper = plugin_load('helper', 'statistics');
        $this->helper->getDB()->exec('DELETE FROM audit');
        $this->helper->getDB()->exec('DELETE FROM logins');
        @unlink(getCacheName('statistics_retention', '.statistics-retention'));
    }

    protected function seed(): void
    {
        $log = $this->helper->getAuditLog();
        $base = ['facility' => 'f', 'user' => '', 'ip' => '', 'action' => '', 'subject' => '', 'details' => '', 'file' => '', 'line' => 0];
        $log->store($base + ['dt' => time() - 40 * 86400, 'message' => 'old']);
        $log->store($base + ['dt' => time(), 'message' => 'now']);

        $this->helper->getDB()->exec(
            "INSERT INTO logins (dt, ip, user, type) VALUES (datetime('now', '-40 days'), '', 'u', 'l')"
        );
    }

    protected function runRetention(): void
    {
        ob_start();
        $data = null;
        $event = new Event('INDEXER_TASKS_RUN', $data);
        plugin_load('action', 'statistics')->retention($event, null);
        ob_end_clean();
    }

    protected function messages(): array
    {
        return array_column($this->helper->getDB()->queryAll('SELECT message FROM audit ORDER BY dt'), 'message');
    }

    public function testAuditPrunedWhenOnlyAuditRetentionSet()
    {
        global $conf;
        $conf['plugin']['statistics']['retention'] = 0;
        $conf['plugin']['statistics']['audit_retention'] = 30;
        $this->seed();

        $this->runRetention();

        $this->assertSame(['now'], $this->messages());
        $this->assertSame(1, (int)$this->helper->getDB()->queryValue('SELECT COUNT(*) FROM logins'), 'stats untouched');
    }

    public function testStatsPrunedButAuditKeptWhenAuditRetentionZero()
    {
        global $conf;
        $conf['plugin']['statistics']['retention'] = 30;
        $conf['plugin']['statistics']['audit_retention'] = 0;
        $this->seed();

        $this->runRetention();

        $this->assertSame(['old', 'now'], $this->messages());
        $this->assertSame(0, (int)$this->helper->getDB()->queryValue('SELECT COUNT(*) FROM logins'));
    }

    public function testNothingHappensWhenBothZero()
    {
        global $conf;
        $conf['plugin']['statistics']['retention'] = 0;
        $conf['plugin']['statistics']['audit_retention'] = 0;
        $this->seed();

        $this->runRetention();

        $this->assertSame(['old', 'now'], $this->messages());
        $this->assertFileDoesNotExist(getCacheName('statistics_retention', '.statistics-retention'));
    }
}
