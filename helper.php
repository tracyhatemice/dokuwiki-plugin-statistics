<?php

use dokuwiki\ErrorHandler;
use dokuwiki\Extension\Plugin;
use dokuwiki\HTTP\DokuHTTPClient;
use dokuwiki\plugin\sqlite\SQLiteDB;
use dokuwiki\plugin\statistics\DummyLogger;
use dokuwiki\plugin\statistics\IgnoreException;
use dokuwiki\plugin\statistics\IpResolverException;
use dokuwiki\plugin\statistics\Logger;
use dokuwiki\plugin\statistics\Query;
use dokuwiki\plugin\statistics\StatisticsGraph;

/**
 * Statistics Plugin
 *
 * @license GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class helper_plugin_statistics extends Plugin
{
    protected ?Query $oQuery = null;
    protected ?StatisticsGraph $oGraph = null;
    protected ?SQLiteDB $db = null;
    public ?DokuHTTPClient $httpClient = null; // public for testing purposes

    /**
     * Get SQLiteDB instance
     *
     * @return SQLiteDB|null
     * @throws Exception when SQLite initialization failed
     */
    public function getDB(): ?SQLiteDB
    {
        if (!$this->db instanceof SQLiteDB) {
            if (!class_exists(SQLiteDB::class)) throw new Exception('SQLite Plugin missing');
            $this->db = new SQLiteDB('statistics', DOKU_PLUGIN . 'statistics/db/');
        }
        return $this->db;
    }


    /**
     * Return an instance of the query class
     *
     * @return Query
     */
    public function getQuery(): Query
    {
        if (is_null($this->oQuery)) {
            $this->oQuery = new Query($this);
        }
        return $this->oQuery;
    }

    /**
     * Return an instance of the logger class
     *
     * When the logger cannot be created for any reason a DummyLogger is returned
     *
     * @return Logger|DummyLogger
     */
    public function getLogger()
    {
        try {
            return new Logger($this);
        } catch (Exception $e) {
            if (!$e instanceof IgnoreException) {
                ErrorHandler::logException($e);
            }

            return new DummyLogger();
        }
    }

    /**
     * Return an instance of the Graph class
     *
     * @return StatisticsGraph
     */
    public function getGraph($from, $to, $width, $height)
    {
        if (is_null($this->oGraph)) {
            $this->oGraph = new StatisticsGraph($this, $from, $to, $width, $height);
        }
        return $this->oGraph;
    }

    /**
     * Just send a 1x1 pixel blank gif to the browser
     *
     * @called from dispatch.php
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     * @author Harry Fuecks <fuecks@gmail.com>
     */
    public function sendGIF($transparent = true)
    {
        if ($transparent) {
            $img = base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAEALAAAAAABAAEAAAIBTAA7');
        } else {
            $img = base64_decode('R0lGODdhAQABAIAAAP///////ywAAAAAAQABAAACAkQBADs=');
        }
        header('Content-Type: image/gif');
        header('Content-Length: ' . strlen($img));
        header('Connection: Close');
        echo $img;
        flush();
        // Browser should drop connection after this
        // Thinks it got the whole image
    }

    /**
     * Return the location information for an IP address
     *
     * @throws IpResolverException
     * @noinspection HttpUrlsUsage
     */
    public function resolveIP($ip)
    {
        $http = $this->httpClient ?: new DokuHTTPClient();
        $http->timeout = 7;
        $json = $http->get('http://geoip/lookup/city?ip=' . $ip); 

        if (!$json) {
            throw new IpResolverException('Failed talk to geoip.');
        }
        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new IpResolverException('Failed to decode JSON from geoip.', $e->getTrace(), 0, $e);
        }
        if (!isset($data['Country'])) {
            throw new IpResolverException('Invalid geoip result for ' . $ip, $data);
        }
        // we do not check for 'success' status here. when the API can't resolve the IP we still log it
        // without location data, so we won't re-query it in the next 30 days.

        return $data;
    }
}
