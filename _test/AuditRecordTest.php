<?php

namespace dokuwiki\plugin\statistics\test;

use dokuwiki\plugin\statistics\AuditRecord;
use DokuWikiTest;

/**
 * Pure parser: LOGGER_DATA_FORMAT payload -> audit row
 *
 * @group plugin_statistics
 * @group plugins
 */
class AuditRecordTest extends DokuWikiTest
{
    protected function event(string $facility, string $message, $details, array $extra = []): array
    {
        return array_merge([
            'facility' => $facility,
            'datetime' => 1_700_000_000,
            'message' => $message,
            'details' => $details,
            'file' => '',
            'line' => 0,
            'loglines' => [],
            'logfile' => '/tmp/x.log',
        ], $extra);
    }

    protected function request(): array
    {
        return ['user' => 'requser', 'ip' => '203.0.113.9'];
    }

    public function testStructuredDetailsShape()
    {
        $json = '{"user":"alice","ip":"192.0.2.1","ua":"ExampleClient","action":"download_done","bytes":1234}';
        $row = AuditRecord::fromLogEvent($this->event('facility1', 'alice download_done', $json), $this->request());

        $this->assertSame(1_700_000_000, $row['dt']);
        $this->assertSame('facility1', $row['facility']);
        $this->assertSame('alice', $row['user']);
        $this->assertSame('192.0.2.1', $row['ip']);
        $this->assertSame('download_done', $row['action']);
        $this->assertSame('', $row['subject']);
        $this->assertSame('alice download_done', $row['message']);
        $this->assertSame($json, $row['details']);
        $this->assertSame('', $row['file']);
        $this->assertSame(0, $row['line']);
    }

    public function testDefaultSubjectKeysIgnorePluginSpecificKeys()
    {
        $json = '{"user":"bob","ip":"192.0.2.2","ua":"Firefox","action":"delete","itemId":"abc123","result":"success"}';
        $row = AuditRecord::fromLogEvent($this->event('facility3', 'bob delete success', $json));

        $this->assertSame('bob', $row['user']);
        $this->assertSame('delete', $row['action']);
        $this->assertSame('', $row['subject']);
        $this->assertSame(['id', 'page'], AuditRecord::DEFAULT_SUBJECT_KEYS);
    }

    public function testConfiguredSubjectKeysAreTriedInOrder()
    {
        $json = '{"user":"bob","action":"delete","itemId":"abc123","page":"docs:tpl"}';

        $row = AuditRecord::fromLogEvent($this->event('facility3', 'bob delete', $json), [], ['itemId', 'page']);
        $this->assertSame('abc123', $row['subject']);

        $row = AuditRecord::fromLogEvent($this->event('facility3', 'bob delete', $json), [], ['page', 'itemId']);
        $this->assertSame('docs:tpl', $row['subject']);

        $row = AuditRecord::fromLogEvent($this->event('facility3', 'bob delete', $json), [], ['code', 'itemId']);
        $this->assertSame('abc123', $row['subject'], 'missing keys are skipped');
    }

    public function testEmptySubjectKeysDisableSubject()
    {
        $json = '{"id":"wiki:syntax","act":"show"}';
        $row = AuditRecord::fromLogEvent($this->event('logged', 'anonymous show wiki:syntax', $json), [], []);
        $this->assertSame('', $row['subject']);
    }

    public function testLoggedShapeUsesActAndId()
    {
        $json = '{"id":"wiki:syntax","act":"show","ip":"1.2.3.4","user":"","query":"","ua":"Firefox"}';
        $row = AuditRecord::fromLogEvent($this->event('logged', 'anonymous show wiki:syntax', $json));

        $this->assertSame('', $row['user']);
        $this->assertSame('1.2.3.4', $row['ip']);
        $this->assertSame('show', $row['action']);
        $this->assertSame('wiki:syntax', $row['subject']);
    }

    public function testPlaceholderUserFallsBackToRequestUser()
    {
        $json = '{"user":"-","ip":"192.0.2.3","ua":"ExampleClient","action":"error","reason":"malformed"}';
        $row = AuditRecord::fromLogEvent($this->event('facility2', '- error', $json), $this->request());

        $this->assertSame('requser', $row['user']);
        $this->assertSame('192.0.2.3', $row['ip'], 'ip from details wins over request ip');
        $this->assertSame('error', $row['action']);
    }

    public function testNonJsonDetailsAreStoredVerbatim()
    {
        $trace = "#0 /srv/wiki/inc/foo.php(12): bar()\n#1 {main}";
        $row = AuditRecord::fromLogEvent(
            $this->event('error', 'Exception: boom', $trace, ['file' => '/srv/wiki/inc/foo.php', 'line' => 12]),
            $this->request()
        );

        $this->assertSame('requser', $row['user']);
        $this->assertSame('203.0.113.9', $row['ip']);
        $this->assertSame('', $row['action']);
        $this->assertSame('', $row['subject']);
        $this->assertSame($trace, $row['details']);
        $this->assertSame('/srv/wiki/inc/foo.php', $row['file']);
        $this->assertSame(12, $row['line']);
    }

    public function testArrayDetailsAreEncodedCompact()
    {
        $row = AuditRecord::fromLogEvent($this->event('debug', 'slow query', ['sql' => 'SELECT 1', 'n' => 2]));

        $this->assertSame('{"sql":"SELECT 1","n":2}', $row['details']);
    }

    public function testEmptyDetails()
    {
        $row = AuditRecord::fromLogEvent($this->event('custom', 'hello', null));
        $this->assertSame('', $row['details']);

        $row = AuditRecord::fromLogEvent($this->event('custom', 'hello', ''));
        $this->assertSame('', $row['details']);
    }

    public function testActionFromMessageWhenFirstTokenIsTheUser()
    {
        $row = AuditRecord::fromLogEvent($this->event('custom', 'requser download file.txt', null), $this->request());
        $this->assertSame('download', $row['action']);
    }

    public function testActionFromMessageWhenFirstTokenIsThePlaceholder()
    {
        $row = AuditRecord::fromLogEvent($this->event('custom', '- error', '{"user":"-"}'), ['user' => '', 'ip' => '']);
        $this->assertSame('', $row['user']);
        $this->assertSame('error', $row['action']);
    }

    public function testNoActionWhenMessageDoesNotStartWithUser()
    {
        $row = AuditRecord::fromLogEvent($this->event('custom', 'Statistics Plugin: failed', null), $this->request());
        $this->assertSame('', $row['action']);
    }

    public function testMessageNewlinesCollapsedAndCapped()
    {
        $long = str_repeat('x', 2000);
        $row = AuditRecord::fromLogEvent($this->event('custom', "a\nb\r\nc " . $long, null));

        $this->assertStringStartsWith('a b c x', $row['message']);
        $this->assertSame(AuditRecord::MAX_MESSAGE, strlen($row['message']));
        $this->assertStringEndsWith('...', $row['message']);
    }

    public function testDetailsCapped()
    {
        $row = AuditRecord::fromLogEvent($this->event('custom', 'm', str_repeat('y', 10000)));
        $this->assertSame(AuditRecord::MAX_DETAILS, strlen($row['details']));
    }

    public function testMissingDatetimeFallsBackToNow()
    {
        $data = $this->event('custom', 'm', null);
        unset($data['datetime']);
        $row = AuditRecord::fromLogEvent($data);
        $this->assertEqualsWithDelta(time(), $row['dt'], 5);
    }
}
