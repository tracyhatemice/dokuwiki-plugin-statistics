<?php

namespace dokuwiki\plugin\statistics\test;

use DokuWikiTest;
use helper_plugin_statistics;

/**
 * @group plugin_statistics
 * @group plugins
 */
class AuditQueryTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    /** @var helper_plugin_statistics */
    protected $helper;

    public function setUp(): void
    {
        parent::setUp();
        $this->helper = plugin_load('helper', 'statistics');
        $this->helper->getDB()->exec('DELETE FROM audit');

        $now = time();
        $base = ['ip' => '', 'details' => '', 'file' => '', 'line' => 0];
        $rows = [
            ['dt' => $now - 300, 'facility' => 'facility1', 'user' => 'alice', 'action' => 'delete', 'subject' => 'item1', 'message' => 'alice delete'],
            ['dt' => $now - 200, 'facility' => 'facility1', 'user' => 'bob', 'action' => 'create', 'subject' => 'item2', 'message' => 'bob create'],
            ['dt' => $now - 100, 'facility' => 'logged', 'user' => '', 'action' => 'show', 'subject' => 'wiki:100%done', 'message' => 'anonymous show wiki:100%done'],
            ['dt' => $now - 50, 'facility' => 'logged', 'user' => 'alice', 'action' => 'show', 'subject' => 'wiki:syntax', 'message' => 'alice show wiki:syntax'],
            ['dt' => $now - 3 * 86400, 'facility' => 'facility1', 'user' => 'alice', 'action' => 'delete', 'subject' => 'old', 'message' => 'three days ago'],
        ];
        foreach ($rows as $row) {
            $this->helper->getAuditLog()->store($row + $base);
        }

        $today = date('Y-m-d');
        $this->helper->getQuery()->setTimeFrame($today, $today);
        $this->helper->getQuery()->setPagination(0, 20);
    }

    public function testAuditlogNewestFirstWithinTimeframe()
    {
        $rows = $this->helper->getQuery()->auditlog();
        $this->assertSame(
            ['alice show wiki:syntax', 'anonymous show wiki:100%done', 'bob create', 'alice delete'],
            array_column($rows, 'message')
        );
        $this->assertSame(
            ['time', 'facility', 'user', 'ip', 'action', 'subject', 'message', 'details'],
            array_keys($rows[0])
        );
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $rows[0]['time']);
    }

    public function testExactFilters()
    {
        $q = $this->helper->getQuery();
        $this->assertCount(2, $q->auditlog(['facility' => 'logged']));
        $this->assertCount(2, $q->auditlog(['user' => 'alice']));
        $this->assertCount(1, $q->auditlog(['action' => 'create']));
        $this->assertCount(1, $q->auditlog(['facility' => 'logged', 'user' => 'alice']));
        $this->assertCount(0, $q->auditlog(['facility' => 'logged', 'action' => 'delete']));
    }

    public function testTextFilterMatchesSubjectOrMessage()
    {
        $q = $this->helper->getQuery();
        $this->assertCount(1, $q->auditlog(['q' => 'syntax']));
        $this->assertCount(1, $q->auditlog(['q' => 'bob cre']));
        $this->assertCount(0, $q->auditlog(['q' => 'nothing']));
    }

    public function testTextFilterEscapesLikeWildcards()
    {
        $q = $this->helper->getQuery();
        $this->assertCount(1, $q->auditlog(['q' => '100%done']));
        $this->assertCount(0, $q->auditlog(['q' => '100_done']));
    }

    public function testPagination()
    {
        $q = $this->helper->getQuery();
        $q->setPagination(0, 2);
        $this->assertCount(3, $q->auditlog(), 'limit + 1 signals a next page');
        $q->setPagination(2, 2);
        $this->assertSame(['bob create', 'alice delete'], array_column($q->auditlog(), 'message'));
    }

    public function testAuditactions()
    {
        $rows = $this->helper->getQuery()->auditactions();
        $this->assertSame(['cnt', 'action'], array_keys($rows[0]));
        $this->assertSame('logged:show', $rows[0]['action']);
        $this->assertSame(2, (int)$rows[0]['cnt']);
        $this->assertCount(3, $rows);
    }

    public function testAuditusers()
    {
        $rows = $this->helper->getQuery()->auditusers();
        $byUser = array_column($rows, 'cnt', 'user');
        $this->assertSame(2, (int)$byUser['alice']);
        $this->assertSame(1, (int)$byUser['bob']);
        $this->assertSame(1, (int)$byUser['(anonymous)']);
    }

    public function testAuditfacilities()
    {
        $this->assertSame(['facility1', 'logged'], $this->helper->getQuery()->auditfacilities());
    }
}
