<?php

use dokuwiki\Extension\ActionPlugin;
use dokuwiki\Extension\Event;
use dokuwiki\Extension\EventHandler;
use dokuwiki\ErrorHandler;
use dokuwiki\plugin\statistics\AuditRecord;

/**
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */
class action_plugin_statistics extends ActionPlugin
{
    /** @var bool re-entrancy guard: a failing audit insert logs an error, which must not audit itself */
    protected static bool $auditing = false;

    /**
     * register the eventhandlers and initialize some options
     */
    public function register(EventHandler $controller)
    {
        global $JSINFO;
        global $ACT;
        $JSINFO['act'] = $ACT;

        $controller->register_hook('DOKUWIKI_INIT_DONE', 'AFTER', $this, 'initSession', []);
        // FIXME new save event might be better:
        $controller->register_hook('IO_WIKIPAGE_WRITE', 'BEFORE', $this, 'logedits', []);
        $controller->register_hook('SEARCH_QUERY_FULLPAGE', 'AFTER', $this, 'logsearch', []);
        $controller->register_hook('FETCH_MEDIA_STATUS', 'BEFORE', $this, 'logmedia', []);
        $controller->register_hook('INDEXER_TASKS_RUN', 'AFTER', $this, 'loghistory', []);
        $controller->register_hook('INDEXER_TASKS_RUN', 'AFTER', $this, 'retention', []);

        // audit: capture native Logger events into the audit table
        $controller->register_hook('LOGGER_DATA_FORMAT', 'BEFORE', $this, 'logaudit', []);

        // log registration and login/logout actionsonly when user tracking is enabled
        if (!$this->getConf('nousers')) {
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'loglogins', []);
            $controller->register_hook('AUTH_USER_CHANGE', 'AFTER', $this, 'logregistration', []);
        }
    }

    /**
     * This ensures we have a session for the statistics plugin
     *
     * We reset this when the user agent changes or the session is too old
     * (15 minutes).
     */
    public function initSession()
    {
        global $INPUT;

        // load session data
        $session = $_SESSION[DOKU_COOKIE]['statistics'] ?? [];

        // reset if session is too old
        if (time() - ($session['time'] ?? 0) > 60 * 15) {
            $session = [];
        }
        // reset if user agent changed
        if ($INPUT->server->str('HTTP_USER_AGENT') != ($session['user_agent'] ?? '')) {
            $session = [];
        }

        // update session data
        $session['time'] = time();
        $session['user_agent'] = $INPUT->server->str('HTTP_USER_AGENT');
        $session['uid'] = get_doku_pref('plgstats', bin2hex(random_bytes(16)));
        if (!isset($session['id'])) {
            // generate a new session id if not set
            $session['id'] = bin2hex(random_bytes(16));
        }

        // store session and cookie data
        $_SESSION[DOKU_COOKIE]['statistics'] = $session;

        // Workaround for dokuwiki/dokuwiki#4544
        $old = get_doku_pref('plgstats', false);
        if ($old !== $session['uid']) {
            set_doku_pref('plgstats', $session['uid']);
        }
    }

    /**
     * @fixme call this in the webbug call
     */
    public function putpixel()
    {
        global $ID, $INPUT;
        $url = DOKU_BASE . 'lib/plugins/statistics/dispatch.php?p=' . rawurlencode($ID) .
            '&amp;r=' . rawurlencode($INPUT->server->str('HTTP_REFERER')) . '&rnd=' . time();

        echo '<noscript><img alt="" src="' . $url . '" width="1" height="1" /></noscript>';
    }

    /**
     * Log page edits actions
     */
    public function logedits(Event $event, $param)
    {
        if ($event->data[3]) return; // no revision

        if (file_exists($event->data[0][0])) {
            if ($event->data[0][1] == '') {
                $type = 'D';
            } else {
                $type = 'E';
            }
        } else {
            $type = 'C';
        }
        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $hlp->getLogger()->logEdit($event->data[1] . ':' . $event->data[2], $type);
    }

    /**
     * Log internal search
     */
    public function logsearch(Event $event, $param)
    {
        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $hlp->getLogger()->logSearch($event->data['query'], $event->data['highlight']);
    }

    /**
     * Log login/logouts
     */
    public function loglogins(Event $event, $param)
    {
        global $INPUT;

        $type = '';
        $act = $this->actClean($event->data);
        $user = $INPUT->server->str('REMOTE_USER');
        if ($act == 'logout') {
            // logout
            $type = 'o';
        } elseif ($INPUT->server->str('REMOTE_USER') && $act == 'login') {
            if ($INPUT->str('r')) {
                // permanent login
                $type = 'p';
            } else {
                // normal login
                $type = 'l';
            }
        } elseif ($INPUT->str('u') && !$INPUT->str('http_credentials') && !$INPUT->server->str('REMOTE_USER')) {
            // failed attempt
            $user = $INPUT->str('u');
            $type = 'f';
        }
        if (!$type) return;

        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $hlp->getLogger()->logLogin($type, $user);
    }

    /**
     * Log user creations
     */
    public function logregistration(Event $event, $param)
    {
        if ($event->data['type'] == 'create') {
            /** @var helper_plugin_statistics $hlp */
            $hlp = plugin_load('helper', 'statistics');
            $hlp->getLogger()->logLogin('C', $event->data['params'][0]);
        }
    }

    /**
     * Capture a native Logger event into the audit table
     *
     * Runs BEFORE the default formatting, so message and details are still raw.
     * When audit_keepfiles is off and the row was stored, the default file write
     * is prevented. Failures never propagate to the caller and never recurse.
     */
    public function logaudit(Event $event, $param)
    {
        if (self::$auditing) return;
        if (!in_array($event->data['facility'], $this->auditFacilities(), true)) return;

        self::$auditing = true;
        try {
            global $INPUT;
            $row = AuditRecord::fromLogEvent(
                $event->data,
                ['user' => $INPUT->server->str('REMOTE_USER'), 'ip' => clientIP(true)],
                $this->auditList('audit_subject_keys')
            );
            if ($this->isAuditFiltered($row['facility'], $row['action'])) return;

            $hook = new Event('PLUGIN_STATISTICS_AUDIT_RECORD', $row);
            $stored = false;
            if ($hook->advise_before()) {
                /** @var helper_plugin_statistics $hlp */
                $hlp = plugin_load('helper', 'statistics');
                $hlp->getAuditLog()->store($row);
                $stored = true;
            }
            $hook->advise_after();

            if ($stored && !$this->getConf('audit_keepfiles')) {
                $event->preventDefault();
            }
        } catch (\Throwable $e) {
            ErrorHandler::logException($e);
        } finally {
            self::$auditing = false;
        }
    }

    /**
     * The configured audit facilities, trimmed, empty entries dropped
     *
     * @return string[]
     */
    public function auditFacilities(): array
    {
        return $this->auditList('audit_facilities');
    }

    /**
     * Is this event dropped by the audit_include / audit_exclude patterns?
     *
     * Patterns are facility:action with shell wildcards; a pattern without an
     * action part matches the whole facility. Exclusions win over inclusions.
     */
    public function isAuditFiltered(string $facility, string $action): bool
    {
        $exclude = $this->auditList('audit_exclude');
        if ($exclude && $this->auditMatches($exclude, $facility, $action)) return true;

        $include = $this->auditList('audit_include');
        if ($include && !$this->auditMatches($include, $facility, $action)) return true;

        return false;
    }

    /**
     * Does any pattern match the facility alone or facility:action?
     *
     * @param string[] $patterns
     */
    protected function auditMatches(array $patterns, string $facility, string $action): bool
    {
        foreach ($patterns as $pattern) {
            if (fnmatch($pattern, $facility) || fnmatch($pattern, "$facility:$action")) return true;
        }
        return false;
    }

    /**
     * A comma separated list setting, trimmed, empty entries dropped
     *
     * @return string[]
     */
    protected function auditList(string $setting): array
    {
        $list = explode(',', (string)$this->getConf($setting));
        $list = array_map('trim', $list);
        return array_values(array_filter($list, static fn($f) => $f !== ''));
    }

    /**
     * Log media access
     */
    public function logmedia(Event $event, $param)
    {
        if ($event->data['status'] < 200) return;
        if ($event->data['status'] >= 400) return;
        if (preg_match('/^\w+:\/\//', $event->data['media'])) return;

        // no size for redirect/not modified
        if ($event->data['status'] >= 300) {
            $size = 0;
        } else {
            $size = @filesize($event->data['file']);
        }

        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $hlp->getLogger()->logMedia(
            $event->data['media'],
            $event->data['mime'],
            !$event->data['download'],
            $size
        );
    }

    /**
     * Log the daily page and media counts for the history
     */
    public function loghistory(Event $event, $param)
    {
        echo 'Plugin Statistics: started' . DOKU_LF;

        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $db = $hlp->getDB();

        // check if a history was gathered already today
        $result = $db->queryAll(
            "SELECT info FROM history WHERE date(dt) = date('now')"
        );

        $page_ran = false;
        $media_ran = false;
        foreach ($result as $row) {
            if ($row['info'] == 'page_count') $page_ran = true;
            if ($row['info'] == 'media_count') $media_ran = true;
        }

        if ($page_ran && $media_ran) {
            echo 'Plugin Statistics: nothing to do - finished' . DOKU_LF;
            return;
        }

        $event->stopPropagation();
        $event->preventDefault();

        if ($page_ran) {
            echo 'Plugin Statistics: logging media' . DOKU_LF;
            $hlp->getLogger()->logHistoryMedia();
        } else {
            echo 'Plugin Statistics: logging pages' . DOKU_LF;
            $hlp->getLogger()->logHistoryPages();
        }
        echo 'Plugin Statistics: finished' . DOKU_LF;
    }

    /**
     * Prune old data
     *
     * This is run once a day and removes all data older than the configured
     * retention times. Statistics tables and the audit table have separate
     * retention settings.
     */
    public function retention(Event $event, $param)
    {
        $retention = (int)$this->getConf('retention');
        $auditRetention = (int)$this->getConf('audit_retention');
        if ($retention <= 0 && $auditRetention <= 0) return;

        // pruning is only done once a day
        $touch = getCacheName('statistics_retention', '.statistics-retention');
        if (file_exists($touch) && time() - filemtime($touch) < 24 * 3600) {
            return;
        }

        $event->stopPropagation();
        $event->preventDefault();

        // these are the tables to be pruned
        $tables = [
            'edits',
            'history',
            'iplocation',
            'logins',
            'media',
            'outlinks',
            'pageviews',
            'referers',
            'search',
            'sessions',
        ];

        /** @var helper_plugin_statistics $hlp */
        $hlp = plugin_load('helper', 'statistics');
        $db = $hlp->getDB();

        $db->getPdo()->beginTransaction();
        if ($retention > 0) {
            foreach ($tables as $table) {
                echo "Plugin Statistics: pruning $table" . DOKU_LF;
                $db->exec(
                    "DELETE FROM $table WHERE dt < datetime('now', '-$retention days')"
                );
            }
        }
        if ($auditRetention > 0) {
            echo "Plugin Statistics: pruning audit" . DOKU_LF;
            $hlp->getAuditLog()->prune($auditRetention);
        }
        $db->getPdo()->commit();

        echo "Plugin Statistics: Optimizing" . DOKU_LF;
        $db->exec('VACUUM');

        // touch the retention file to prevent multiple runs
        io_saveFile($touch, dformat());
    }

    /**
     * Pre-Sanitize the action command
     *
     * Similar to act_clean in action.php but simplified and without
     * error messages
     */
    protected function actClean($act)
    {
        // check if the action was given as array key
        if (is_array($act)) {
            [$act] = array_keys($act);
        }

        //remove all bad chars
        $act = strtolower($act);
        $act = preg_replace('/[^a-z_]+/', '', $act);

        return $act;
    }
}
