<?php

namespace dokuwiki\plugin\statistics\test;

use dokuwiki\plugin\statistics\Logger;
use DokuWikiTest;
use helper_plugin_statistics;

/**
 * Tests for the statistics plugin Logger class
 *
 * @group plugin_statistics
 * @group plugins
 */
class LoggerTest extends DokuWikiTest
{
    protected $pluginsEnabled = ['statistics', 'sqlite'];

    /** @var helper_plugin_statistics */
    protected $helper;

    const SESSION_ID = 'test-session-12345';
    const USER_ID = 'test-uid-12345';
    const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

    public function setUp(): void
    {
        parent::setUp();

        // Load the helper plugin
        $this->helper = plugin_load('helper', 'statistics');

        // set default user agent
        $_SERVER['HTTP_USER_AGENT'] = self::USER_AGENT;

        // Set up session data that Logger expects
        $_SESSION[DOKU_COOKIE]['statistics']['uid'] = self::USER_ID;
        $_SESSION[DOKU_COOKIE]['statistics']['id'] = self::SESSION_ID;
    }

    public function tearDown(): void
    {
        unset($_SERVER['HTTP_USER_AGENT']);
        unset($_SESSION[DOKU_COOKIE]['statistics']);
        parent::tearDown();
    }

    /**
     * Test constructor initializes properties correctly
     */
    public function testConstructor()
    {
        $this->assertInstanceOf(Logger::class, $this->helper->getLogger());

        // Test that bot user agents throw exception
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1 (+http://www.google.com/bot.html)';

        $this->expectException(\dokuwiki\plugin\statistics\IgnoreException::class);
        $this->expectExceptionMessage('Bot detected, not logging');
        new Logger($this->helper);
    }

    /**
     * Test begin and end transaction methods
     */
    public function testBeginEnd()
    {
        $this->helper->getLogger()->begin();

        // Verify transaction is active by checking PDO
        $pdo = $this->helper->getDB()->getPdo();
        $this->assertTrue($pdo->inTransaction());

        $this->helper->getLogger()->end();

        // Verify transaction is committed
        $this->assertFalse($pdo->inTransaction());
    }

    /**
     * Test user logging
     */
    public function testLogUser()
    {
        // Test with no user (should not log)
        $_SERVER['REMOTE_USER'] = '';
        $this->helper->getLogger()->begin();
        $this->helper->getLogger()->end();

        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM users');
        $this->assertEquals(0, $count);

        // Test with user
        $_SERVER['REMOTE_USER'] = 'testuser';
        $this->helper->getLogger()->begin();
        $this->helper->getLogger()->end();

        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM users');
        $this->assertEquals(1, $count);

        $user = $this->helper->getDB()->queryValue('SELECT user FROM users WHERE user = ?', ['testuser']);
        $this->assertEquals('testuser', $user);
    }

    /**
     * Data provider for logGroups test
     */
    public function logGroupsProvider()
    {
        return [
            'empty groups' => [[], 0],
            'single group' => [['admin'], 1],
            'multiple groups' => [['admin', 'user'], 2],
            'filtered groups' => [['admin', 'nonexistent'], 2], // all groups are logged
        ];
    }

    /**
     * Test logGroups method
     * @dataProvider logGroupsProvider
     */
    public function testLogGroups($groups, $expectedCount)
    {
        global $USERINFO;

        // Set up a test user and groups
        $_SERVER['REMOTE_USER'] = 'testuser';
        $USERINFO = ['grps' => $groups];


        $this->helper->getLogger()->begin();
        $this->helper->getLogger()->end();

        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM groups WHERE user = ?', ['testuser']);
        $this->assertEquals($expectedCount, $count);

        if ($expectedCount > 0) {
            $loggedGroups = $this->helper->getDB()->queryAll('SELECT `group` FROM groups WHERE user = ?', ['testuser']);
            $this->assertCount($expectedCount, $loggedGroups);
        }
    }

    /**
     * Data provider for testLogReferer test
     */
    public function logRefererProvider()
    {
        return [
            'google search' => [
                'https://www.google.com/search?q=dokuwiki+test',
                'google',
                true // should be logged
            ],
            'bing search' => [
                'https://www.bing.com/search?q=test+query',
                'bing',
                true // should be logged
            ],
            'external referer' => [
                'https://example.com/page',
                null,
                true // should be logged
            ],
            'direct access (empty referer)' => [
                '',
                null,
                true // should be logged
            ],
            'ws' => [
                '   ',
                null,
                true // should be logged (trimmed to empty)
            ],
        ];
    }

    /**
     * Test logReferer method
     * @dataProvider logRefererProvider
     */
    public function testLogReferer($referer, $expectedEngine, $shouldBeLogged)
    {
        $logger = $this->helper->getLogger();
        $logger->begin();
        $refId = $logger->logReferer($referer);
        $logger->end();

        if ($shouldBeLogged) {
            $this->assertNotNull($refId);
            $refererRecord = $this->helper->getDB()->queryRecord('SELECT * FROM referers WHERE id = ?', [$refId]);
            $this->assertNotNull($refererRecord);
            $this->assertEquals($expectedEngine, $refererRecord['engine']);
            $this->assertEquals(trim($referer), $refererRecord['url']);
        } else {
            $this->assertNull($refId);
        }
    }

    /**
     * Test that internal referers (our own pages) are not logged
     */
    public function testLogRefererInternal()
    {
        // Test internal referer (should return null and not be logged)
        $internalReferer = DOKU_URL;
        $refId = $this->helper->getLogger()->logReferer($internalReferer);
        $this->assertNull($refId, 'Internal referers should not be logged');

        // Verify no referer was actually stored
        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM referers WHERE url = ?', [$internalReferer]);
        $this->assertEquals(0, $count, 'Internal referer should not be stored in database');

        // Test another internal referer pattern
        $internalReferer2 = rtrim(DOKU_URL, '/') . '/doku.php?id=start';
        $refId2 = $this->helper->getLogger()->logReferer($internalReferer2);
        $this->assertNull($refId2, 'Internal wiki pages should not be logged as referers');
    }

    /**
     * Test logSearch method
     */
    public function testLogSearch()
    {
        $query = 'test search query';
        $words = ['test', 'search', 'query'];

        $this->helper->getLogger()->logSearch($query, $words);

        // Check search table
        $search = $this->helper->getDB()->queryRecord('SELECT * FROM search ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($query, $search['query']);

        // Check searchwords table
        $wordCount = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM searchwords WHERE sid = ?', [$search['id']]);
        $this->assertEquals(3, $wordCount);

        $loggedWords = $this->helper->getDB()->queryAll('SELECT word FROM searchwords WHERE sid = ? ORDER BY word', [$search['id']]);
        $this->assertEquals(['query', 'search', 'test'], array_column($loggedWords, 'word'));
    }

    /**
     * Test logSession method
     */
    public function testLogSession()
    {
        $_SERVER['REMOTE_USER'] = 'testuser';

        // Test session creation
        $logger = $this->helper->getLogger();

        $logger->begin();
        $logger->end();

        $sessionCount = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM sessions');
        $this->assertEquals(1, $sessionCount);

        $session = $this->helper->getDB()->queryRecord('SELECT * FROM sessions LIMIT 1');
        $this->assertIsArray($session);
        $this->assertEquals('testuser', $session['user']);
        $this->assertEquals(self::SESSION_ID, $session['session']);
        $this->assertEquals(self::USER_ID, $session['uid']);
        $this->assertEquals(self::USER_AGENT, $session['ua']);
        $this->assertEquals('Chrome', $session['ua_info']);
        $this->assertEquals('browser', $session['ua_type']);
        $this->assertEquals('91', $session['ua_ver']);
        $this->assertEquals('Windows', $session['os']);

    }

    /**
     * Test logIp method
     */
    public function testLogIp()
    {
        $ip = '8.8.8.8';
        $_SERVER['REMOTE_ADDR'] = $ip;

        // Create a mock HTTP client
        $mockHttpClient = $this->createMock(\dokuwiki\HTTP\DokuHTTPClient::class);

        // Mock the response of the local geoip lookup service
        $mockResponse = json_encode([
            'Country' => ['Code' => 'US', 'Names' => ['en' => 'United States']],
            'City' => ['Names' => ['en' => 'Ashburn']],
        ]);

        $mockHttpClient->expects($this->once())
            ->method('get')
            ->with('http://geoip/lookup/city?ip=' . $ip)
            ->willReturn($mockResponse);

        // Set timeout property
        $mockHttpClient->timeout = 10;

        // Create logger with mock HTTP client
        $this->helper->httpClient = $mockHttpClient;
        $logger = new Logger($this->helper);

        // Test with IP that doesn't exist in database
        $logger->logIp();

        // Verify the IP was logged
        $ipRecord = $this->helper->getDB()->queryRecord('SELECT * FROM iplocation WHERE ip = ?', [$ip]);
        $this->assertNotNull($ipRecord);
        $this->assertEquals($ip, $ipRecord['ip']);
        $this->assertEquals('United States', $ipRecord['country']);
        $this->assertEquals('US', $ipRecord['code']);
        $this->assertEquals('Ashburn', $ipRecord['city']);
        $this->assertSame('', $ipRecord['host']); // reverse DNS is disabled

        // Test with IP that already exists and is recent (should not make HTTP call)
        $mockHttpClient2 = $this->createMock(\dokuwiki\HTTP\DokuHTTPClient::class);
        $mockHttpClient2->expects($this->never())->method('get');

        $this->helper->httpClient = $mockHttpClient2;
        $logger2 = new Logger($this->helper);
        $logger2->logIp(); // Should not trigger HTTP call

        $this->helper->httpClient = null; // Reset HTTP client for other tests
    }

    /**
     * Test logOutgoing method
     */
    public function testLogOutgoing()
    {
        global $INPUT;

        // Test without outgoing link
        $INPUT->set('ol', '');
        $this->helper->getLogger()->logOutgoing();

        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM outlinks');
        $this->assertEquals(0, $count);

        // Test with outgoing link
        $link = 'https://example.com';
        $page = 'test:page';
        $INPUT->set('ol', $link);
        $INPUT->set('p', $page);

        $this->helper->getLogger()->logOutgoing();

        $count = $this->helper->getDB()->queryValue('SELECT COUNT(*) FROM outlinks');
        $this->assertEquals(1, $count);

        $outlink = $this->helper->getDB()->queryRecord('SELECT * FROM outlinks ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($link, $outlink['link']);
        $this->assertEquals($page, $outlink['page']);
    }

    /**
     * Test logPageView method
     */
    public function testLogPageView()
    {
        global $INPUT, $USERINFO, $conf;

        $conf['plugin']['statistics']['loggroups'] = ['admin', 'user'];

        $page = 'test:page';
        $referer = 'https://example.com';
        $user = 'testuser';

        $INPUT->set('p', $page);
        $INPUT->set('r', $referer);
        $INPUT->set('sx', 1920);
        $INPUT->set('sy', 1080);
        $INPUT->set('vx', 1200);
        $INPUT->set('vy', 800);
        $INPUT->server->set('REMOTE_USER', $user);

        $USERINFO = ['grps' => ['admin', 'user']];

        $logger = $this->helper->getLogger();
        $logger->begin();
        $logger->logPageView();
        $logger->end();

        // Check pageviews table
        $pageview = $this->helper->getDB()->queryRecord('SELECT * FROM pageviews ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($page, $pageview['page']);
        $this->assertEquals(1920, $pageview['screen_x']);
        $this->assertEquals(1080, $pageview['screen_y']);
        $this->assertEquals(1200, $pageview['view_x']);
        $this->assertEquals(800, $pageview['view_y']);
        $this->assertEquals(self::SESSION_ID, $pageview['session']);
    }

    /**
     * Data provider for logMedia test
     */
    public function logMediaProvider()
    {
        return [
            'image inline' => ['test.jpg', 'image/jpeg', true, 1024],
            'video not inline' => ['test.mp4', 'video/mp4', false, 2048],
            'document' => ['test.pdf', 'application/pdf', false, 512],
        ];
    }

    /**
     * Test logMedia method
     * @dataProvider logMediaProvider
     */
    public function testLogMedia($media, $mime, $inline, $size)
    {
        global $INPUT;

        $user = 'testuser';
        $INPUT->server->set('REMOTE_USER', $user);

        $this->helper->getLogger()->logMedia($media, $mime, $inline, $size);

        $mediaLog = $this->helper->getDB()->queryRecord('SELECT * FROM media ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($media, $mediaLog['media']);
        $this->assertEquals($size, $mediaLog['size']);
        $this->assertEquals($inline ? 1 : 0, $mediaLog['inline']);

        [$mime1, $mime2] = explode('/', strtolower($mime));
        $this->assertEquals($mime1, $mediaLog['mime1']);
        $this->assertEquals($mime2, $mediaLog['mime2']);
    }

    /**
     * Data provider for logEdit test
     */
    public function logEditProvider()
    {
        return [
            'create page' => ['new:page', 'create'],
            'edit page' => ['existing:page', 'edit'],
            'delete page' => ['old:page', 'delete'],
        ];
    }

    /**
     * Test logEdit method
     * @dataProvider logEditProvider
     */
    public function testLogEdit($page, $type)
    {
        global $INPUT, $USERINFO;


        $user = 'testuser';
        $INPUT->server->set('REMOTE_USER', $user);
        $USERINFO = ['grps' => ['admin']];

        $this->helper->getLogger()->logEdit($page, $type);

        // Check edits table
        $edit = $this->helper->getDB()->queryRecord('SELECT * FROM edits ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($page, $edit['page']);
        $this->assertEquals($type, $edit['type']);
    }

    /**
     * Data provider for logLogin test
     */
    public function logLoginProvider()
    {
        return [
            'login' => ['login', 'testuser'],
            'logout' => ['logout', 'testuser'],
            'create' => ['create', 'newuser'],
        ];
    }

    /**
     * Test logLogin method
     * @dataProvider logLoginProvider
     */
    public function testLogLogin($type, $user)
    {
        $this->helper->getLogger()->logLogin($type, $user);
        $login = $this->helper->getDB()->queryRecord('SELECT * FROM logins ORDER BY dt DESC LIMIT 1');
        $this->assertEquals($type, $login['type']);
        $this->assertEquals($user, $login['user']);
    }

    /**
     * Test logHistoryPages method
     */
    public function testLogHistoryPages()
    {
        $this->helper->getLogger()->logHistoryPages();

        // Check that both page_count and page_size entries were created
        $pageCount = $this->helper->getDB()->queryValue('SELECT value FROM history WHERE info = ?', ['page_count']);
        $pageSize = $this->helper->getDB()->queryValue('SELECT value FROM history WHERE info = ?', ['page_size']);

        $this->assertIsNumeric($pageCount);
        $this->assertIsNumeric($pageSize);
        $this->assertGreaterThanOrEqual(0, $pageCount);
        $this->assertGreaterThanOrEqual(0, $pageSize);
    }

    /**
     * Test logHistoryMedia method
     */
    public function testLogHistoryMedia()
    {
        $this->helper->getLogger()->logHistoryMedia();

        // Check that both media_count and media_size entries were created
        $mediaCount = $this->helper->getDB()->queryValue('SELECT value FROM history WHERE info = ?', ['media_count']);
        $mediaSize = $this->helper->getDB()->queryValue('SELECT value FROM history WHERE info = ?', ['media_size']);

        $this->assertIsNumeric($mediaCount);
        $this->assertIsNumeric($mediaSize);
        $this->assertGreaterThanOrEqual(0, $mediaCount);
        $this->assertGreaterThanOrEqual(0, $mediaSize);
    }

    /**
     * Test that feedreader user agents are handled correctly
     */
    public function testFeedReaderUserAgent()
    {
        // Use a user agent that DeviceDetector recognizes as a feedreader
        $_SERVER['HTTP_USER_AGENT'] = 'BashPodder/1.0 (http://bashpodder.sourceforge.net/)';

        $logger = new Logger($this->helper);

        // Use reflection to access protected property
        $reflection = new \ReflectionClass($logger);
        $uaTypeProperty = $reflection->getProperty('uaType');
        $uaTypeProperty->setAccessible(true);

        $this->assertEquals('feedreader', $uaTypeProperty->getValue($logger));
    }

    /**
     * Data provider for logCampaign test
     */
    public function logCampaignProvider()
    {
        return [
            'all utm parameters' => [
                ['utm_campaign' => 'summer_sale', 'utm_source' => 'google', 'utm_medium' => 'cpc'],
                ['summer_sale', 'google', 'cpc'],
                true
            ],
            'only campaign' => [
                ['utm_campaign' => 'newsletter'],
                ['newsletter', null, null],
                true
            ],
            'only source' => [
                ['utm_source' => 'facebook'],
                [null, 'facebook', null],
                true
            ],
            'only medium' => [
                ['utm_medium' => 'email'],
                [null, null, 'email'],
                true
            ],
            'campaign and source' => [
                ['utm_campaign' => 'holiday', 'utm_source' => 'twitter'],
                ['holiday', 'twitter', null],
                true
            ],
            'no utm parameters' => [
                [],
                [null, null, null],
                false
            ],
            'empty utm parameters' => [
                ['utm_campaign' => '', 'utm_source' => '', 'utm_medium' => ''],
                [null, null, null],
                false
            ],
            'whitespace utm parameters' => [
                ['utm_campaign' => '  ', 'utm_source' => '  ', 'utm_medium' => '  '],
                [null, null, null],
                false
            ],
            'mixed empty and valid' => [
                ['utm_campaign' => '', 'utm_source' => 'instagram', 'utm_medium' => ''],
                [null, 'instagram', null],
                true
            ],
        ];
    }

    /**
     * Test logCampaign method
     * @dataProvider logCampaignProvider
     */
    public function testLogCampaign($inputParams, $expectedValues, $shouldBeLogged)
    {
        global $INPUT;

        // Clean up any existing campaign data first
        $this->helper->getDB()->exec('DELETE FROM campaigns WHERE session = ?', [self::SESSION_ID]);

        // Set up INPUT parameters
        foreach ($inputParams as $key => $value) {
            $INPUT->set($key, $value);
        }

        $logger = $this->helper->getLogger();
        $logger->begin();
        $logger->end();

        if ($shouldBeLogged) {
            $campaign = $this->helper->getDB()->queryRecord(
                'SELECT * FROM campaigns WHERE session = ? ORDER BY rowid DESC LIMIT 1',
                [self::SESSION_ID]
            );
            
            $this->assertNotNull($campaign, 'Campaign should be logged');
            $this->assertEquals(self::SESSION_ID, $campaign['session']);
            $this->assertEquals($expectedValues[0], $campaign['campaign']);
            $this->assertEquals($expectedValues[1], $campaign['source']);
            $this->assertEquals($expectedValues[2], $campaign['medium']);
        } else {
            $count = $this->helper->getDB()->queryValue(
                'SELECT COUNT(*) FROM campaigns WHERE session = ?',
                [self::SESSION_ID]
            );
            $this->assertEquals(0, $count, 'No campaign should be logged');
        }

        // Clean up INPUT for next test
        foreach ($inputParams as $key => $value) {
            $INPUT->set($key, null);
        }
    }

    /**
     * Test that logCampaign uses INSERT OR IGNORE to prevent duplicates
     */
    public function testLogCampaignDuplicatePrevention()
    {
        global $INPUT;

        // Clean up any existing campaign data first
        $this->helper->getDB()->exec('DELETE FROM campaigns WHERE session = ?', [self::SESSION_ID]);

        $INPUT->set('utm_campaign', 'test_campaign');
        $INPUT->set('utm_source', 'test_source');
        $INPUT->set('utm_medium', 'test_medium');

        // Log the same campaign twice
        $logger1 = $this->helper->getLogger();
        $logger1->begin();
        $logger1->end();

        $logger2 = $this->helper->getLogger();
        $logger2->begin();
        $logger2->end();

        // Should only have one record due to INSERT OR IGNORE
        $count = $this->helper->getDB()->queryValue(
            'SELECT COUNT(*) FROM campaigns WHERE session = ?',
            [self::SESSION_ID]
        );
        $this->assertEquals(1, $count, 'Should only have one campaign record due to INSERT OR IGNORE');

        // Clean up
        $INPUT->set('utm_campaign', null);
        $INPUT->set('utm_source', null);
        $INPUT->set('utm_medium', null);
    }
}
