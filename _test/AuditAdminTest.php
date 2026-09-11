<?php

namespace dokuwiki\plugin\statistics\test;

use DokuWikiTest;

/**
 * @group plugin_statistics
 * @group plugins
 */
class AuditAdminTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    public function setUp(): void
    {
        parent::setUp();

        global $conf, $auth, $USERINFO;
        $conf['superuser'] = 'adminuser';
        $conf['plugin']['statistics']['audit_facilities'] = 'facility1';
        $auth = new \dokuwiki\test\mock\AuthPlugin();
        $USERINFO = null;

        $helper = plugin_load('helper', 'statistics');
        $helper->getDB()->exec('DELETE FROM audit');
        $helper->getAuditLog()->store([
            'dt' => time(),
            'facility' => 'facility1',
            'user' => 'alice',
            'ip' => '192.0.2.1',
            'action' => 'delete',
            'subject' => 'item<1>',
            'message' => 'alice delete success',
            'details' => '{"user":"alice","action":"delete","itemId":"item<1>"}',
            'file' => '',
            'line' => 0,
        ]);
        $helper->getAuditLog()->store([
            'dt' => time(),
            'facility' => 'logged',
            'user' => '',
            'ip' => '192.0.2.2',
            'action' => 'show',
            'subject' => 'wiki:syntax',
            'message' => 'anonymous show wiki:syntax',
            'details' => '',
            'file' => '',
            'line' => 0,
        ]);
    }

    protected function loginAs(string $user, array $groups): void
    {
        global $INPUT, $USERINFO;
        $INPUT->server->set('REMOTE_USER', $user);
        $USERINFO = ['grps' => $groups];
    }

    protected function tocLinks(): array
    {
        $admin = plugin_load('admin', 'statistics', true);
        return array_map(static fn($item) => $item['link'], $admin->getTOC());
    }

    protected function render(array $get): string
    {
        global $INPUT;
        // Input wraps $_REQUEST by reference, which survives between tests
        $server = $INPUT->server;
        $_REQUEST = [];
        $INPUT = new \dokuwiki\Input\Input();
        $INPUT->server = $server;
        foreach ($get as $k => $v) {
            $INPUT->set($k, $v);
        }
        $admin = plugin_load('admin', 'statistics', true);
        $admin->handle();
        // html() calls tpl_flush(), which flushes the innermost buffer into the outer one
        ob_start();
        ob_start();
        $admin->html();
        $inner = ob_get_clean();
        $outer = ob_get_clean();
        return $outer . $inner;
    }

    public function testManagerDoesNotSeeAuditSection()
    {
        global $conf;
        $conf['manager'] = 'manageruser';
        $this->loginAs('manageruser', ['user']);

        $links = implode("\n", $this->tocLinks());
        $this->assertStringNotContainsString('opt=auditlog', $links);
        $this->assertStringContainsString('opt=pages', $links);
    }

    public function testAdminSeesAuditSection()
    {
        $this->loginAs('adminuser', ['admin']);

        $links = implode("\n", $this->tocLinks());
        $this->assertStringContainsString('opt=auditdashboard', $links);
        $this->assertStringContainsString('opt=auditlog', $links);
        $this->assertStringContainsString('opt=auditactions', $links);
        $this->assertStringContainsString('opt=auditusers', $links);
    }

    public function testAdminWithoutFacilitiesDoesNotSeeAuditSection()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_facilities'] = '';
        $this->loginAs('adminuser', ['admin']);

        $this->assertStringNotContainsString('opt=auditlog', implode("\n", $this->tocLinks()));
    }

    public function testManagerRequestingAuditlogFallsBackToDashboard()
    {
        global $conf;
        $conf['manager'] = 'manageruser';
        $this->loginAs('manageruser', ['user']);

        $html = $this->render(['opt' => 'auditlog']);
        $this->assertStringContainsString('plg_stats_dashboard', $html);
        $this->assertStringNotContainsString('alice delete success', $html);
    }

    public function testAuditlogRendersRowsFilterFormAndEscapes()
    {
        $this->loginAs('adminuser', ['admin']);

        $html = $this->render(['opt' => 'auditlog']);

        $this->assertStringContainsString('plg_stats_auditfilter', $html);
        $this->assertStringContainsString('name="af"', $html);
        $this->assertStringContainsString('<option value="facility1"', $html);
        $this->assertStringContainsString('alice delete success', $html);
        $this->assertStringContainsString('item&lt;1&gt;', $html);
        $this->assertStringNotContainsString('item<1>', $html);
        $this->assertStringContainsString('&quot;itemId&quot;', $html, 'details are shown escaped');
        // logged rows link their page id
        $this->assertMatchesRegularExpression('/<a href="[^"]*wiki:syntax[^"]*" class="wikilink1">wiki:syntax<\/a>/', $html);
    }

    public function testAuditlogFilterIsAppliedAndCarriedInPager()
    {
        $this->loginAs('adminuser', ['admin']);

        $html = $this->render(['opt' => 'auditlog', 'au' => 'alice']);

        $this->assertStringContainsString('alice delete success', $html);
        $this->assertStringNotContainsString('anonymous show wiki:syntax', $html);
        $this->assertStringContainsString('value="alice"', $html, 'filter form keeps the value');
        // quick date links keep the filter
        $this->assertStringContainsString('au=alice', $html);
    }

    public function testAuditlogEmptyState()
    {
        $this->loginAs('adminuser', ['admin']);

        $html = $this->render(['opt' => 'auditlog', 'au' => 'nobody']);
        $this->assertStringContainsString('plg_stats_audit_empty', $html);
    }

    public function testSummaryPagesRender()
    {
        $this->loginAs('adminuser', ['admin']);

        $html = $this->render(['opt' => 'auditactions']);
        $this->assertStringContainsString('facility1:delete', $html);

        $html = $this->render(['opt' => 'auditusers']);
        $this->assertStringContainsString('(anonymous)', $html);
    }

    public function testAuditDashboardRenders()
    {
        $this->loginAs('adminuser', ['admin']);

        $html = $this->render(['opt' => 'auditdashboard']);

        $this->assertStringContainsString('plg_stats_auditdashboard', $html);
        $this->assertStringContainsString('<strong>2</strong> Audit Events', $html);
        $this->assertStringContainsString('<strong>1</strong> Distinct Users', $html);
        $this->assertStringContainsString('<strong>1</strong> Anonymous Events', $html);
        $this->assertStringContainsString('name="auditdashboard"', $html, 'trend chart is rendered');
        $this->assertStringContainsString('facility1:delete', $html, 'top actions table');
        $this->assertStringContainsString('(anonymous)', $html, 'top users table');
        $this->assertStringContainsString('item&lt;1&gt;', $html, 'latest events table');
        $this->assertStringContainsString('opt=auditlog', $html, 'more link to the log');
    }
}
