<?php

$lang['loggroups'] = 'Comma separated list of user groups that should be logged. Empty for all.';
$lang['anonips'] = 'Anonymize IP addresses in the log data by hashing them.';
$lang['nolocation'] = 'Do not resolve location information (country, region, city) for IP addresses.';
$lang['nousers'] = 'Do not log any identifying information about logged in users (user names, groups, etc).';
$lang['retention'] = 'Number of days to keep statistics data. All older data will be deleted! <code>0</code> means all data is kept indefinitely.';
$lang['timezone'] = 'Force timezone. Use a PHP timezone identifier (formatted "Europe/Berlin") if your system is showing wrong times.';
$lang['audit_facilities'] = 'Comma separated list of DokuWiki logger facilities to capture into the audit table, e.g. <code>facility1,facility2</code>. Empty disables auditing. Facilities listed in the core <code>dontlog</code> setting are never captured. <code>logged</code> and <code>debug</code> are high volume.';
$lang['audit_keepfiles'] = 'Keep writing captured facilities to their log files under <code>data/log/</code> as well. Switch off to make the audit table the only store.';
$lang['audit_retention'] = 'Number of days to keep audit events. All older events will be deleted! <code>0</code> means events are kept indefinitely.';
$lang['audit_include'] = 'Comma separated list of <code>facility:action</code> patterns (shell wildcards, action part optional). When set, only matching events are stored, e.g. <code>logged:edit, logged:save, facility1</code>. Empty stores everything.';
$lang['audit_exclude'] = 'Comma separated list of <code>facility:action</code> patterns whose events are not stored, e.g. <code>logged:show, logged:media, *:debug_*</code>. Exclusions win over inclusions. Excluded events still reach the file logs.';
$lang['audit_subject_keys'] = 'Comma separated keys of the JSON details tried, in order, for the subject column; the first non-empty one wins. Add keys your plugins emit, e.g. <code>id,page,itemId</code>. Empty disables the subject column.';
