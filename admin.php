<?php

// phpcs:disable PSR1.Methods.CamelCapsMethodName.NotCamelCaps
use dokuwiki\Extension\AdminPlugin;
use dokuwiki\plugin\statistics\SearchEngines;

/**
 * statistics plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andreas Gohr <gohr@splitbrain.org>
 */
class admin_plugin_statistics extends AdminPlugin
{
    /** @var string the currently selected page */
    protected $opt = '';

    /** @var string from date in YYYY-MM-DD */
    protected $from = '';
    /** @var string to date in YYYY-MM-DD */
    protected $to = '';
    /** @var int Offset to use when displaying paged data */
    protected $start = 0;

    /** @var int rows per page on the audit log */
    protected const AUDIT_PAGE = 50;

    /** @var array audit log filters: facility, user, action, q */
    protected $filters = ['facility' => '', 'user' => '', 'action' => '', 'q' => ''];

    /** @var helper_plugin_statistics */
    protected $hlp;

    /**
     * Available statistic pages
     */
    protected $pages = [
        'dashboard' => 'printDashboard',
        'content' => [
            'pages' => 'printTable',
            'edits' => 'printTable',
            'images' => 'printImages',
            'downloads'  => 'printDownloads',
            'history'  => 'printHistory',
        ],
        'users' => [
            'topdomain' => 'printTableAndPieGraph',
            'topuser' => 'printTableAndPieGraph',
            'topeditor' => 'printTableAndPieGraph',
            'topgroup' => 'printTableAndPieGraph',
            'topgroupedit' => 'printTableAndPieGraph',
            'seenusers' => 'printTable',
        ],
        'links' => [
            'referer' => 'printReferer',
            'newreferer' => 'printTable',
            'outlinks'  => 'printTable'
        ],
        'campaign' => [
            'campaigns' => 'printTableAndPieGraph',
            'source' => 'printTableAndPieGraph',
            'medium' => 'printTableAndPieGraph',
        ],
        'search' => [
            'searchengines'  => 'printTableAndPieGraph',
            'internalsearchphrases' => 'printTable',
            'internalsearchwords' => 'printTable',
        ],
        'technology' => [
            'browsers' => 'printTableAndPieGraph',
            'os' => 'printTableAndPieGraph',
            'countries' => 'printTableAndPieGraph',
            'resolution' => 'printTableAndScatterGraph',
            'viewport' => 'printTableAndScatterGraph',
        ],
        'audit' => [
            'auditlog' => 'printAuditLog',
            'auditactions' => 'printTableAndPieGraph',
            'auditusers' => 'printTableAndPieGraph',
        ],
    ];

    /** @var array keeps a list of all real content pages, generated from above array */
    protected $allowedpages = [];

    /**
     * Initialize the helper
     */
    public function __construct()
    {
        $this->hlp = plugin_load('helper', 'statistics');

        // remove pages that are not available because logging its data is disabled
        if ($this->getConf('nolocation')) {
            $this->pages['technology'] = array_diff($this->pages['technology'], ['countries']);
        }
        if ($this->getConf('nousers')) {
            unset($this->pages['users']);
        }
        // audit pages are for superusers only, and only when auditing is configured
        if (!auth_isadmin() || trim((string)$this->getConf('audit_facilities')) === '') {
            unset($this->pages['audit']);
        }

        // build a list of pages
        foreach ($this->pages as $key => $val) {
            if (is_array($val)) {
                $this->allowedpages = array_merge($this->allowedpages, $val);
            } else {
                $this->allowedpages[$key] = $val;
            }
        }
    }

    /**
     * Access for managers allowed
     */
    public function forAdminOnly()
    {
        return false;
    }

    /**
     * return sort order for position in admin menu
     */
    public function getMenuSort()
    {
        return 350;
    }

    /**
     * handle user request
     */
    public function handle()
    {
        global $INPUT;
        $this->opt = preg_replace('/[^a-z]+/', '', $INPUT->str('opt'));
        if (!isset($this->allowedpages[$this->opt])) $this->opt = 'dashboard';

        $this->start = $INPUT->int('s');
        $this->filters = [
            'facility' => $INPUT->str('af'),
            'user' => $INPUT->str('au'),
            'action' => $INPUT->str('aa'),
            'q' => $INPUT->str('aq'),
        ];
        $this->setTimeframe($INPUT->str('f', date('Y-m-d')), $INPUT->str('t', date('Y-m-d')));
    }

    /**
     * set limit clause
     */
    public function setTimeframe($from, $to)
    {
        // swap if wrong order
        if ($from > $to) [$from, $to] = [$to, $from];

        $this->hlp->getQuery()->setTimeFrame($from, $to);
        $this->from = $from;
        $this->to = $to;
    }

    /**
     * URL parameters that identify the current view: page, timeframe and any audit filters
     */
    protected function urlParams(): array
    {
        $params = [
            'do' => 'admin',
            'page' => 'statistics',
            'opt' => $this->opt,
            'f' => $this->from,
            't' => $this->to,
        ];
        if ($this->opt === 'auditlog') {
            $names = ['facility' => 'af', 'user' => 'au', 'action' => 'aa', 'q' => 'aq'];
            foreach ($names as $key => $param) {
                if ($this->filters[$key] !== '') $params[$param] = $this->filters[$key];
            }
        }
        return $params;
    }

    /**
     * Output the Statistics
     */
    public function html()
    {
        echo '<script src="' . DOKU_BASE . 'lib/plugins/statistics/js/chart.js"></script>';
        echo '<script src="' . DOKU_BASE . 'lib/plugins/statistics/js/chartjs-plugin-datalabels.js"></script>';

        echo '<div id="plugin__statistics">';
        echo '<h1>' . $this->getLang('menu') . '</h1>';
        $this->html_timeselect();
        tpl_flush();


        $method = $this->allowedpages[$this->opt];
        if (method_exists($this, $method)) {
            echo '<div class="plg_stats_' . $this->opt . '">';
            echo '<h2>' . $this->getLang($this->opt) . '</h2>';
            $this->$method($this->opt);
            echo '</div>';
        }
        echo '</div>';
    }

    /**
     * Return the TOC
     *
     * @return array
     */
    public function getTOC()
    {
        $toc = [];
        foreach ($this->pages as $key => $info) {
            if (is_array($info)) {
                $toc[] = html_mktocitem(
                    '',
                    $this->getLang($key),
                    1,
                    ''
                );

                foreach (array_keys($info) as $page) {
                    $toc[] = html_mktocitem(
                        '?do=admin&amp;page=statistics&amp;opt=' . $page .
                        '&amp;f=' . $this->from .
                        '&amp;t=' . $this->to,
                        $this->getLang($page),
                        2,
                        ''
                    );
                }
            } else {
                $toc[] = html_mktocitem(
                    '?do=admin&amp;page=statistics&amp;opt=' . $key .
                    '&amp;f=' . $this->from .
                    '&amp;t=' . $this->to,
                    $this->getLang($key),
                    1,
                    ''
                );
            }
        }
        return $toc;
    }

    /**
     * @fixme instead of this, I would like the print* methods to call the Graph methods
     */
    public function html_graph($name, $width, $height)
    {
        $this->hlp->getGraph($this->from, $this->to, $width, $height)->$name();
    }

    /**
     * Outputs pagination links
     *
     * @param int $limit
     * @param int $next
     */
    public function html_pager($limit, $next)
    {
        $params = $this->urlParams();

        echo '<div class="plg_stats_pager">';
        if ($this->start > 0) {
            $go = max($this->start - $limit, 0);
            $params['s'] = $go;
            echo '<a href="?' . buildURLparams($params) . '" class="prev button">' . $this->getLang('prev') . '</a>';
        }

        if ($next) {
            $go = $this->start + $limit;
            $params['s'] = $go;
            echo '<a href="?' . buildURLparams($params) . '" class="next button">' . $this->getLang('next') . '</a>';
        }
        echo '</div>';
    }

    /**
     * Print the time selection menu
     */
    public function html_timeselect()
    {
        $quick = [
            'today' => date('Y-m-d'),
            'last1' => date('Y-m-d', time() - (60 * 60 * 24)),
            'last7' => date('Y-m-d', time() - (60 * 60 * 24 * 7)),
            'last30' => date('Y-m-d', time() - (60 * 60 * 24 * 30)),
        ];


        echo '<div class="plg_stats_timeselect">';
        echo '<span>' . $this->getLang('time_select') . '</span> ';

        echo '<form action="' . DOKU_SCRIPT . '" method="get">';
        foreach ($this->urlParams() as $name => $value) {
            if ($name === 'f' || $name === 't') continue;
            echo '<input type="hidden" name="' . hsc($name) . '" value="' . hsc($value) . '" />';
        }
        echo '<input type="date" name="f" value="' . $this->from . '" class="edit" />';
        echo '<input type="date" name="t" value="' . $this->to . '" class="edit" />';
        echo '<input type="submit" value="go" class="button" />';
        echo '</form>';

        echo '<ul>';
        foreach ($quick as $name => $time) {
            // today is included only today
            $to = $name == 'today' ? $quick['today'] : $quick['last1'];

            $url = buildURLparams(array_merge($this->urlParams(), ['f' => $time, 't' => $to]));

            echo '<li>';
            echo '<a href="?' . $url . '">';
            echo $this->getLang('time_' . $name);
            echo '</a>';
            echo '</li>';
        }
        echo '</ul>';

        echo '</div>';
    }

    // region: Print functions for the different statistic pages

    /**
     * Print an introductionary screen
     */
    public function printDashboard()
    {
        echo '<p>' . $this->getLang('intro_dashboard') . '</p>';

        // general info
        echo '<div class="plg_stats_top">';
        $result = $this->hlp->getQuery()->aggregate();

        echo '<ul>';
        foreach (['pageviews', 'sessions', 'visitors', 'users', 'logins', 'current'] as $name) {
            echo '<li><div class="li">' . sprintf($this->getLang('dash_' . $name), $result[$name]) . '</div></li>';
        }
        echo '</ul>';

        echo '<ul>';
        foreach (['bouncerate', 'timespent', 'avgpages', 'newvisitors', 'registrations', 'last'] as $name) {
            echo '<li><div class="li">' . sprintf($this->getLang('dash_' . $name), $result[$name]) . '</div></li>';
        }
        echo '</ul>';

        $this->html_graph('dashboardviews', 700, 280);
        $this->html_graph('dashboardwiki', 700, 280);
        echo '</div>';

        $quickgraphs = [
            ['lbl' => 'dash_mostpopular', 'query' => 'pages', 'opt' => 'page'],
            ['lbl' => 'dash_newincoming', 'query' => 'newreferer', 'opt' => 'newreferer'],
            ['lbl' => 'dash_topsearch', 'query' => 'internalsearchphrases', 'opt' => 'internalsearchphrases'],
        ];

        foreach ($quickgraphs as $graph) {
            $params = [
                'do' => 'admin',
                'page' => 'statistics',
                'f' => $this->from,
                't' => $this->to,
                'opt' => $graph['opt'],
            ];

            echo '<div>';
            echo '<h2>' . $this->getLang($graph['lbl']) . '</h2>';
            $result = call_user_func([$this->hlp->getQuery(), $graph['query']]);
            $this->html_resulttable($result);
            echo '<p><a href="?' . buildURLparams($params) . '" class="more">' . $this->getLang('more') . '…</a></p>';
            echo '</div>';
        }
    }

    public function printHistory($name)
    {
        echo '<p>' . $this->getLang('intro_history') . '</p>';
        $this->html_graph('history_page_count', 600, 200);
        $this->html_graph('history_page_size', 600, 200);
        $this->html_graph('history_media_count', 600, 200);
        $this->html_graph('history_media_size', 600, 200);
    }


    public function printTableAndPieGraph($name)
    {
        echo '<p>' . $this->getLang("intro_$name") . '</p>';


        $graph = $this->hlp->getGraph($this->from, $this->to, 300, 300);
        $graph->sumUpPieChart($name);

        $result = $this->hlp->getQuery()->$name();
        $this->html_resulttable($result, '', 150);
    }

    public function printTableAndScatterGraph()
    {
        echo '<p>' . $this->getLang('intro_resolution') . '</p>';
        $this->html_graph('resolution', 650, 490);
        $result = $this->hlp->getQuery()->resolution();
        $this->html_resulttable($result, '', 150);
    }

    public function printTable($name)
    {
        echo '<p>' . $this->getLang("intro_$name") . '</p>';
        $result = $this->hlp->getQuery()->$name();
        $this->html_resulttable($result, '', 150);
    }


    public function printImages()
    {
        echo '<p>' . $this->getLang('intro_images') . '</p>';

        $result = $this->hlp->getQuery()->imagessum();
        echo '<p>';
        echo sprintf($this->getLang('trafficsum'), $result[0]['cnt'], filesize_h($result[0]['filesize']));
        echo '</p>';

        $result = $this->hlp->getQuery()->images();
        $this->html_resulttable($result, '', 150);
    }

    public function printDownloads()
    {
        echo '<p>' . $this->getLang('intro_downloads') . '</p>';

        $result = $this->hlp->getQuery()->downloadssum();
        echo '<p>';
        echo sprintf($this->getLang('trafficsum'), $result[0]['cnt'], filesize_h($result[0]['filesize']));
        echo '</p>';

        $result = $this->hlp->getQuery()->downloads();
        $this->html_resulttable($result, '', 150);
    }

    public function printReferer()
    {
        $result = $this->hlp->getQuery()->aggregate();

        if ($result['referers']) {
            printf(
                '<p>' . $this->getLang('intro_referer') . '</p>',
                $result['referers'],
                $result['direct'],
                (100 * $result['direct'] / $result['referers']),
                $result['search'],
                (100 * $result['search'] / $result['referers']),
                $result['external'],
                (100 * $result['external'] / $result['referers'])
            );
        }

        $result = $this->hlp->getQuery()->referer();
        $this->html_resulttable($result, '', 150);
    }

    /**
     * The filterable audit event browser
     */
    public function printAuditLog()
    {
        echo '<p>' . $this->getLang('intro_auditlog') . '</p>';
        $this->html_auditfilter();

        $query = $this->hlp->getQuery();
        $query->setPagination($this->start, self::AUDIT_PAGE);
        $result = $query->auditlog($this->filters);

        $this->html_audittable(array_slice($result, 0, self::AUDIT_PAGE));
        $this->html_pager(self::AUDIT_PAGE, count($result) > self::AUDIT_PAGE);
    }

    /**
     * Filter form for the audit log
     */
    protected function html_auditfilter()
    {
        $facilities = $this->hlp->getQuery()->auditfacilities();

        echo '<div class="plg_stats_auditfilter">';
        echo '<form action="' . DOKU_SCRIPT . '" method="get">';
        echo '<input type="hidden" name="do" value="admin" />';
        echo '<input type="hidden" name="page" value="statistics" />';
        echo '<input type="hidden" name="opt" value="auditlog" />';
        echo '<input type="hidden" name="f" value="' . hsc($this->from) . '" />';
        echo '<input type="hidden" name="t" value="' . hsc($this->to) . '" />';

        echo '<label>' . $this->getLang('audit_filter_facility') . ' ';
        echo '<select name="af">';
        echo '<option value="">' . $this->getLang('audit_filter_any') . '</option>';
        foreach ($facilities as $facility) {
            $selected = $facility === $this->filters['facility'] ? ' selected="selected"' : '';
            echo '<option value="' . hsc($facility) . '"' . $selected . '>' . hsc($facility) . '</option>';
        }
        echo '</select></label>';

        foreach (['user' => 'au', 'action' => 'aa', 'q' => 'aq'] as $key => $param) {
            echo '<label>' . $this->getLang('audit_filter_' . $key) . ' ';
            echo '<input type="text" name="' . $param . '" value="' . hsc($this->filters[$key]) . '" class="edit" />';
            echo '</label>';
        }

        echo '<input type="submit" value="' . $this->getLang('audit_filter_go') . '" class="button" />';
        echo '</form>';
        echo '</div>';
    }

    /**
     * Render audit rows
     *
     * @param array $rows as returned by Query::auditlog()
     */
    protected function html_audittable(array $rows)
    {
        if (!$rows) {
            echo '<p class="plg_stats_audit_empty">' . $this->getLang('audit_noentries') . '</p>';
            return;
        }

        $columns = ['time', 'facility', 'user', 'ip', 'action', 'subject', 'message', 'details'];

        echo '<table class="inline plg_stats_audit">';
        echo '<tr>';
        foreach ($columns as $column) {
            echo '<th>' . $this->getLang('audit_col_' . $column) . '</th>';
        }
        echo '</tr>';

        foreach ($rows as $row) {
            echo '<tr>';
            foreach ($columns as $column) {
                echo '<td class="plg_stats_X' . $column . '">';
                if ($column === 'subject') {
                    echo $this->html_auditsubject($row);
                } elseif ($column === 'details') {
                    echo $this->html_auditdetails($row['details']);
                } else {
                    echo hsc($row[$column]);
                }
                echo '</td>';
            }
            echo '</tr>';
        }
        echo '</table>';
    }

    /**
     * The subject cell: linked for wiki pages and media logged by the logged plugin
     */
    protected function html_auditsubject(array $row): string
    {
        $subject = $row['subject'];
        if ($subject === '') return '';
        if ($row['facility'] !== 'logged') return hsc($subject);

        if ($row['action'] === 'media') {
            return '<a href="' . ml($subject) . '" class="wikilink1">' . hsc($subject) . '</a>';
        }
        return '<a href="' . wl($subject) . '" class="wikilink1">' . hsc($subject) . '</a>';
    }

    /**
     * The details cell: collapsed, pretty printed when it is JSON
     */
    protected function html_auditdetails(string $details): string
    {
        if ($details === '') return '';

        $decoded = json_decode($details, true);
        if (is_array($decoded)) {
            $details = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return '<details><summary>&hellip;</summary><pre>' . hsc($details) . '</pre></details>';
    }

    // endregion


    /**
     * Display a result in a HTML table
     */
    public function html_resulttable($result, $header = '', $pager = 0)
    {
        echo '<table class="inline">';
        if (is_array($header)) {
            echo '<tr>';
            foreach ($header as $h) {
                echo '<th>' . hsc($h) . '</th>';
            }
            echo '</tr>';
        }

        $count = 0;
        if (is_array($result)) foreach ($result as $row) {
            echo '<tr>';
            foreach ($row as $k => $v) {
                if ($k == 'res_x') continue;
                if ($k == 'res_y') continue;

                echo '<td class="plg_stats_X' . $k . '">';
                if ($k == 'page') {
                    echo '<a href="' . wl($v) . '" class="wikilink1">';
                    echo hsc($v);
                    echo '</a>';
                } elseif ($k == 'media') {
                    echo '<a href="' . ml($v) . '" class="wikilink1">';
                    echo hsc($v);
                    echo '</a>';
                } elseif ($k == 'filesize') {
                    echo filesize_h($v);
                } elseif ($k == 'url') {
                    $url = hsc($v);
                    $url = preg_replace('/^https?:\/\/(www\.)?/', '', $url);
                    if (strlen($url) > 45) {
                        $url = substr($url, 0, 30) . ' &hellip; ' . substr($url, -15);
                    }
                    echo '<a href="' . $v . '" class="urlextern">';
                    echo $url;
                    echo '</a>';
                } elseif ($k == 'ilookup') {
                    echo '<a href="' . wl('', ['id' => $v, 'do' => 'search']) . '">Search</a>';
                } elseif ($k == 'engine') {
                    $name = SearchEngines::getName($v);
                    $url = SearchEngines::getURL($v);
                    if ($url) {
                        echo '<a href="' . $url . '">' . hsc($name) . '</a>';
                    } else {
                        echo hsc($name);
                    }
                } elseif ($k == 'html') {
                    echo $v;
                } else {
                    echo hsc($v);
                }
                echo '</td>';
            }
            echo '</tr>';

            if ($pager && ($count == $pager)) break;
            $count++;
        }
        echo '</table>';

        if ($pager) $this->html_pager($pager, count($result) > $pager);
    }
}
