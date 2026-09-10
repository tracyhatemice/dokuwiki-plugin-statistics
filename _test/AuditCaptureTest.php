<?php

namespace dokuwiki\plugin\statistics\test;

use dokuwiki\Extension\Event;
use dokuwiki\Logger;
use DokuWikiTest;
use helper_plugin_statistics;

/**
 * LOGGER_DATA_FORMAT -> audit table, end to end through the event system
 *
 * @group plugin_statistics
 * @group plugins
 */
class AuditCaptureTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    /** @var helper_plugin_statistics */
    protected $helper;

    public function setUp(): void
    {
        parent::setUp();

        global $conf, $INPUT;
        $conf['plugin']['statistics']['audit_facilities'] = 'unit_audit, unit_second';
        $conf['plugin']['statistics']['audit_keepfiles'] = 1;
        $INPUT->server->set('REMOTE_USER', 'requser');

        $this->helper = plugin_load('helper', 'statistics');
        $this->helper->getDB()->exec('DELETE FROM audit');

        foreach (['unit_audit', 'unit_second', 'unit_other', 'error'] as $facility) {
            @unlink(Logger::getInstance($facility)->getLogfile());
        }
    }

    protected function rows(): array
    {
        return $this->helper->getDB()->queryAll('SELECT * FROM audit ORDER BY id');
    }

    public function testCapturesFacilityInScope()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_subject_keys'] = 'id, itemId';
        Logger::getInstance('unit_audit')->log(
            'alice item_created',
            '{"user":"alice","ip":"192.0.2.1","ua":"x","action":"item_created","itemId":"abc"}'
        );

        $rows = $this->rows();
        $this->assertCount(1, $rows);
        $this->assertSame('unit_audit', $rows[0]['facility']);
        $this->assertSame('alice', $rows[0]['user']);
        $this->assertSame('192.0.2.1', $rows[0]['ip']);
        $this->assertSame('item_created', $rows[0]['action']);
        $this->assertSame('abc', $rows[0]['subject']);
        $this->assertSame('alice item_created', $rows[0]['message']);
    }

    public function testDefaultSubjectKeysDoNotUseItemId()
    {
        Logger::getInstance('unit_audit')->log(
            'alice item_created',
            '{"user":"alice","action":"item_created","itemId":"abc"}'
        );

        $this->assertSame('', $this->rows()[0]['subject']);
    }

    public function testFacilityListIsTrimmed()
    {
        Logger::getInstance('unit_second')->log('bob thing', null);
        $this->assertCount(1, $this->rows());
    }

    public function testIgnoresFacilityOutOfScope()
    {
        Logger::getInstance('unit_other')->log('alice item_created', null);
        $this->assertCount(0, $this->rows());
        $this->assertFileExists(Logger::getInstance('unit_other')->getLogfile());
    }

    public function testRequestContextFillsMissingUserAndIp()
    {
        Logger::getInstance('unit_audit')->log('plain message', null);

        $rows = $this->rows();
        $this->assertSame('requser', $rows[0]['user']);
        $this->assertSame('172.17.18.19', $rows[0]['ip']);
    }

    public function testFileIsKeptByDefault()
    {
        Logger::getInstance('unit_audit')->log('alice item_created', null);
        $this->assertFileExists(Logger::getInstance('unit_audit')->getLogfile());
    }

    public function testFileIsSuppressedWhenKeepfilesOff()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_keepfiles'] = 0;

        Logger::getInstance('unit_audit')->log('alice item_created', null);

        $this->assertCount(1, $this->rows());
        $this->assertFileDoesNotExist(Logger::getInstance('unit_audit')->getLogfile());
    }

    public function testCustomEventCanRewriteTheRow()
    {
        global $EVENT_HANDLER;
        $EVENT_HANDLER->register_hook('PLUGIN_STATISTICS_AUDIT_RECORD', 'BEFORE', null, function (Event $event) {
            $event->data['subject'] = 'rewritten';
        });

        Logger::getInstance('unit_audit')->log('alice item_created', null);

        $this->assertSame('rewritten', $this->rows()[0]['subject']);
    }

    public function testCustomEventCanDropTheRow()
    {
        global $EVENT_HANDLER;
        $EVENT_HANDLER->register_hook('PLUGIN_STATISTICS_AUDIT_RECORD', 'BEFORE', null, function (Event $event) {
            $event->preventDefault();
        });

        Logger::getInstance('unit_audit')->log('alice item_created', null);

        $this->assertCount(0, $this->rows());
        $this->assertFileExists(Logger::getInstance('unit_audit')->getLogfile(), 'dropped rows still reach the file');
    }

    public function testDropInKeepfilesOffModeStillWritesFile()
    {
        global $conf, $EVENT_HANDLER;
        $conf['plugin']['statistics']['audit_keepfiles'] = 0;
        $EVENT_HANDLER->register_hook('PLUGIN_STATISTICS_AUDIT_RECORD', 'BEFORE', null, function (Event $event) {
            $event->preventDefault();
        });

        Logger::getInstance('unit_audit')->log('alice item_created', null);

        $this->assertCount(0, $this->rows());
        $this->assertFileExists(Logger::getInstance('unit_audit')->getLogfile());
    }

    public function testStoreFailureDoesNotRecurseOrThrow()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_facilities'] = 'unit_audit,error';
        $conf['plugin']['statistics']['audit_keepfiles'] = 0;
        $db = $this->helper->getDB();
        $db->exec('ALTER TABLE audit RENAME TO audit_bak');

        try {
            Logger::getInstance('unit_audit')->log('alice item_created', null);
        } finally {
            $db->exec('ALTER TABLE audit_bak RENAME TO audit');
        }

        // the failure was logged to the error facility, once, and the original
        // event still reached its file because the store failed
        $errorLog = file_get_contents(Logger::getInstance('error')->getLogfile());
        $this->assertSame(1, substr_count($errorLog, 'no such table: audit'));
        $this->assertFileExists(Logger::getInstance('unit_audit')->getLogfile());
        $this->assertCount(0, $this->rows());
    }
    protected function logAction(string $facility, string $action): void
    {
        Logger::getInstance($facility)->log(
            "alice $action",
            json_encode(['user' => 'alice', 'ip' => '192.0.2.1', 'ua' => 'x', 'action' => $action])
        );
    }

    protected function storedActions(): array
    {
        return array_map(
            static fn($row) => $row['facility'] . ':' . $row['action'],
            $this->rows()
        );
    }

    public function testIncludeListRestrictsToMatchingActions()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_include'] = 'unit_audit:item_*';

        $this->logAction('unit_audit', 'item_created');
        $this->logAction('unit_audit', 'download_done');
        $this->logAction('unit_second', 'item_created');

        $this->assertSame(['unit_audit:item_created'], $this->storedActions());
        $this->assertFileExists(Logger::getInstance('unit_second')->getLogfile(), 'filtered rows still reach the file');
    }

    public function testExcludeListDropsMatchingActions()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_exclude'] = ' unit_audit:download_* ,, unit_second';

        $this->logAction('unit_audit', 'item_created');
        $this->logAction('unit_audit', 'download_done');
        $this->logAction('unit_second', 'item_created');

        $this->assertSame(['unit_audit:item_created'], $this->storedActions());
    }

    public function testFacilityOnlyPatternMatchesWholeFacility()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_include'] = 'unit_second';

        $this->logAction('unit_audit', 'item_created');
        $this->logAction('unit_second', 'anything');
        $this->logAction('unit_second', 'else');

        $this->assertSame(['unit_second:anything', 'unit_second:else'], $this->storedActions());
    }

    public function testExcludeWinsOverInclude()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_include'] = 'unit_audit';
        $conf['plugin']['statistics']['audit_exclude'] = '*:item_created';

        $this->logAction('unit_audit', 'item_created');
        $this->logAction('unit_audit', 'item_deleted');

        $this->assertSame(['unit_audit:item_deleted'], $this->storedActions());
    }

    public function testFilteredRowStillWritesFileWhenKeepfilesOff()
    {
        global $conf;
        $conf['plugin']['statistics']['audit_keepfiles'] = 0;
        $conf['plugin']['statistics']['audit_exclude'] = 'unit_audit';

        $this->logAction('unit_audit', 'item_created');

        $this->assertCount(0, $this->rows());
        $this->assertFileExists(Logger::getInstance('unit_audit')->getLogfile());
    }
}
