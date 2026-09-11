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
        $this->assertSame(
            ['facility', 'auditaction', 'cnt', 'users', 'ips', 'first', 'last'],
            array_keys($rows[0])
        );
        $this->assertSame('logged', $rows[0]['facility']);
        $this->assertSame('show', $rows[0]['auditaction']);
        $this->assertSame(2, (int)$rows[0]['cnt']);
        $this->assertSame(1, (int)$rows[0]['users'], 'anonymous is not a user');
        $this->assertSame(0, (int)$rows[0]['ips']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $rows[0]['first']);
        $this->assertLessThanOrEqual($rows[0]['last'], $rows[0]['first']);
        $this->assertCount(3, $rows);
    }

    public function testAuditusers()
    {
        $rows = $this->helper->getQuery()->auditusers();
        $this->assertSame(
            ['audituser', 'cnt', 'actions', 'ips', 'facilities', 'first', 'last', 'topactions'],
            array_keys($rows[0])
        );
        $byUser = array_column($rows, null, 'audituser');
        $this->assertSame(2, (int)$byUser['alice']['cnt']);
        $this->assertSame(2, (int)$byUser['alice']['actions']);
        $this->assertSame(2, (int)$byUser['alice']['facilities']);
        $this->assertSame('delete 1, show 1', $byUser['alice']['topactions']);
        $this->assertSame(1, (int)$byUser['bob']['cnt']);
        $this->assertSame('create 1', $byUser['bob']['topactions']);
        $this->assertSame(1, (int)$byUser['(anonymous)']['cnt']);
        $this->assertSame('show 1', $byUser['(anonymous)']['topactions']);
    }

    public function testAuditips()
    {
        $this->helper->getDB()->exec("UPDATE audit SET ip = '192.0.2.1' WHERE user = 'alice'");
        $this->helper->getDB()->exec("UPDATE audit SET ip = '192.0.2.1' WHERE user = 'bob'");

        $rows = $this->helper->getQuery()->auditips();
        $this->assertCount(1, $rows, 'empty ips are left out');
        $this->assertSame(
            ['auditip', 'cnt', 'users', 'actions', 'facilities', 'first', 'last'],
            array_keys($rows[0])
        );
        $this->assertSame('192.0.2.1', $rows[0]['auditip']);
        $this->assertSame(3, (int)$rows[0]['cnt']);
        $this->assertSame(2, (int)$rows[0]['users']);
        $this->assertSame(3, (int)$rows[0]['actions']);
    }

    public function testAuditlogIpFilter()
    {
        $this->helper->getDB()->exec("UPDATE audit SET ip = '192.0.2.1' WHERE user = 'bob'");
        $q = $this->helper->getQuery();
        $this->assertCount(1, $q->auditlog(['ip' => '192.0.2.1']));
        $this->assertCount(0, $q->auditlog(['ip' => '192.0.2.2']));
    }

    public function testAudittrendByActionAndUser()
    {
        $q = $this->helper->getQuery();
        $today = date('Y-m-d');

        $byAction = $q->audittrend('action', false);
        $this->assertSame(['facility1:create' => 1, 'facility1:delete' => 1, 'logged:show' => 2], $byAction[$today]);

        $byUser = $q->audittrend('user', false);
        $this->assertSame(['(anonymous)' => 1, 'alice' => 2, 'bob' => 1], $byUser[$today]);

        $byIp = $q->audittrend('ip', false);
        $this->assertSame([], $byIp, 'empty ips are left out');
    }

    public function testAuditmatrix()
    {
        $data = $this->helper->getQuery()->auditmatrix();

        $this->assertSame(['alice', '', 'bob'], $data['users'], 'busiest first, then by name');
        $this->assertSame(['logged:show', 'facility1:create', 'facility1:delete'], $data['actions']);
        $this->assertSame(1, $data['cells']['alice']['logged:show']);
        $this->assertSame(1, $data['cells']['alice']['facility1:delete']);
        $this->assertSame(1, $data['cells']['']['logged:show']);
        $this->assertSame(1, $data['cells']['bob']['facility1:create']);
        $this->assertArrayNotHasKey('facility1:create', $data['cells']['alice']);

        $limited = $this->helper->getQuery()->auditmatrix(1);
        $this->assertSame(['alice'], $limited['users']);
        $this->assertSame(['logged:show'], $limited['actions']);
    }

    public function testAuditmatrixWithoutRows()
    {
        $this->helper->getDB()->exec('DELETE FROM audit');
        $this->assertSame(['users' => [], 'actions' => [], 'cells' => []], $this->helper->getQuery()->auditmatrix());
    }

    public function testAuditfacilities()
    {
        $this->assertSame(['facility1', 'logged'], $this->helper->getQuery()->auditfacilities());
    }

    public function testAuditaggregate()
    {
        $data = $this->helper->getQuery()->auditaggregate();

        $this->assertSame(4, $data['events']);
        $this->assertSame(2, $data['users'], 'alice and bob, anonymous not counted');
        $this->assertSame(0, $data['ips'], 'empty ips are not counted');
        $this->assertSame(1, $data['anonymous']);
        $this->assertSame(2, $data['facilities']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $data['last']);
    }

    public function testAuditaggregateWithoutRows()
    {
        $this->helper->getDB()->exec('DELETE FROM audit');
        $data = $this->helper->getQuery()->auditaggregate();

        $this->assertSame(
            ['events' => 0, 'users' => 0, 'ips' => 0, 'anonymous' => 0, 'facilities' => 0, 'last' => ''],
            $data
        );
    }

    public function testAuditdashboardByDay()
    {
        $data = $this->helper->getQuery()->auditdashboard(false);

        $this->assertCount(1, $data);
        $this->assertSame(date('Y-m-d'), array_key_first($data));
        $this->assertSame(['facility1' => 2, 'logged' => 2], $data[date('Y-m-d')]);
    }

    public function testAuditdashboardByHourSumsToAllEvents()
    {
        $data = $this->helper->getQuery()->auditdashboard(true);

        $total = 0;
        foreach ($data as $hour => $row) {
            $this->assertMatchesRegularExpression('/^\d\d$/', $hour);
            $total += array_sum($row);
        }
        $this->assertSame(4, $total);
    }

    public function testAuditdashboardSumsFacilitiesBeyondMaxAsOther()
    {
        $data = $this->helper->getQuery()->auditdashboard(false, 1);

        // facility1 and logged tie on count, the alphabetically first one is kept
        $this->assertSame(['facility1' => 2, 'other' => 2], $data[date('Y-m-d')]);
    }

    public function testAuditrecent()
    {
        $rows = $this->helper->getQuery()->auditrecent(2);

        $this->assertCount(2, $rows);
        $this->assertSame(['time', 'facility', 'user', 'action', 'subject'], array_keys($rows[0]));
        $this->assertSame(['wiki:syntax', 'wiki:100%done'], array_column($rows, 'subject'));
    }
}
