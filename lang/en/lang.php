<?php
/**
 * english language file
 */






// for admin plugins, the menu prompt to be displayed in the admin menu
$lang['menu'] = 'Access and Usage Statistics';

$lang['more'] = 'more';
$lang['prev'] = 'previous page';
$lang['next'] = 'next page';

// time selection
$lang['time_select'] = 'Select the timeframe:';
$lang['time_today']  = 'Today';
$lang['time_last1']  = 'Yesterday';
$lang['time_last7']  = 'Last 7 Days';
$lang['time_last30'] = 'Last 30 Days';
$lang['time_go']     = 'Go';
$lang['days']                  = 'Days';
$lang['weeks']                 = 'Weeks';
$lang['months']                = 'Months';

// the different pages
$lang['dashboard']             = 'Dashboard';
$lang['pages']                 = 'Pages';
$lang['edits']                 = 'Edits';
$lang['images']                = 'Images';
$lang['downloads']             = 'Downloads';
$lang['referer']               = 'Incoming Links';
$lang['newreferer']            = 'New Incoming Links';
$lang['outlinks']              = 'Outgoing Links';
$lang['campaigns']             = 'Campaigns';
$lang['medium']                = 'Campaign Medium';
$lang['source']                = 'Campaign Source';
$lang['internalsearchphrases'] = 'Internal Search Phrases';
$lang['internalsearchwords']   = 'Internal Search Words';
$lang['searchengines']         = 'External Search Engines';
$lang['browsers']              = 'Browsers';
$lang['os']                    = 'Operating Systems';
$lang['countries']             = 'Countries';
$lang['resolution']            = 'Screen Size';
$lang['viewport']              = 'Browser Viewport';
$lang['seenusers']             = 'Seen Users';
$lang['history']               = 'Growth History';
$lang['topdomain']             = 'Top User Domains';
$lang['topuser']               = 'Top Users';
$lang['topeditor']             = 'Top Editors';
$lang['topgroup']              = 'Top Groups';
$lang['topgroupedit']          = 'Top Editing Groups';
$lang['content']               = '(Content)';
$lang['users']                 = '(Users and Groups)';
$lang['links']                 = '(Links)';
$lang['campaign']              = '(Campaigns)';
$lang['search']                = '(Search)';
$lang['technology']            = '(Technology)';
$lang['audit']                 = '(Audit)';
$lang['auditlog']              = 'Audit Log';
$lang['auditactions']          = 'Audit Events by Action';
$lang['auditusers']            = 'Audit Events by User';
$lang['trafficsum']            = '<strong>%s</strong> requests caused <strong>%s</strong> traffic.';


// the intro texts
$lang['intro_dashboard']             = 'This page gives you a quick overview on what has happened in your wiki during the chosen timeframe.<br />For detailed insights and graphs pick a topic from the Table of Contents.';
$lang['intro_page']                  = 'These are the wiki pages most viewed in the selected timeframe – your top content.';
$lang['intro_edits']                 = 'These are the wiki pages most edited in the selected timeframe – this is where the current activity takes place.';
$lang['intro_images']                = 'These are the top most displayed local images in your wiki. The third column shows the total amount of bytes transferred for each item.';
$lang['intro_downloads']             = 'These are the top most downloaded local media items in your wiki. The third column shows the total amount of bytes transferred for each item.';
$lang['intro_referer']               = 'Of all <strong>%d</strong> external visits, <strong>%d</strong> (<strong>%.1f%%</strong>) were direct (or bookmarked) accesses, <strong>%d</strong> (<strong>%.1f%%</strong>) came from search engines and <strong>%d</strong> (<strong>%.1f%%</strong>) were referred through links from other pages.<br />These other pages are listed below.';

$lang['intro_newreferer']            = 'The following incoming links where first logged in the selected timeframe and have never been seen before.';
$lang['intro_outlinks']              = 'These are the most clicked on links to external sites in your wiki.';
$lang['intro_searchengines']         = 'The following search engines were used by users to find your wiki.';
$lang['intro_internalsearchphrases'] = 'These are the exact phrases people used to search inside your wiki.';
$lang['intro_internalsearchwords']   = 'These are the most common words people used to search inside your wiki.';
$lang['intro_browsers']              = 'Here are the most popular browsers used by your users.';
$lang['intro_os']                    = 'Here are the most popular platforms used by your users.';
$lang['intro_countries']             = 'This is where your users come from. Note that resolving IP addresses to countries is error prone and no exact science.';
$lang['intro_resolution']            = 'This page gives you some info about the screen size (resolution) of your users. This is how much screen estate they have, not how much of that is available to the browser\'s display area. For the latter see the Browser Viewport page. All values are rounded to 100 pixels, the graph shows the top 100 values only.';
$lang['intro_viewport']              = 'These are the area sizes that your users\' browsers have available for rendering your wiki. All values are rounded to 100 pixels, the graph shows the top 100 values only.';
$lang['intro_seenusers']             = 'This is a list of when users have been last seen in the Wiki ordered by last seen date. This is independent of the selected time frame.';
$lang['intro_history']               = 'These graphs give you an idea on how your wiki grew over the given timeframe in relation to number of entries and size. Please note that this graph requires a timeframe of multiple days at least.';
$lang['intro_topdomain']             = 'This page shows which of your logged in users browsed the most pages in your wiki in the selected timeframe grouped by their email domain.';
$lang['intro_topuser']               = 'This page shows which of your logged in users browsed the most pages in your wiki in the selected timeframe.';
$lang['intro_topeditor']             = 'This page shows which of your logged in users did the most edits in the seleced timeframe.';
$lang['intro_topgroup']              = 'These are the groups of the logged in users that browsed the most pages in your wiki in the selected timeframe. Note: when a user is member of multiple groups, all her groups are counted.';
$lang['intro_topgroupedit']          = 'These are the groups of the logged in users that did the mst edits in the selected timeframe. Note: when a user is member of multiple groups, all her groups are counted.';
$lang['intro_campaigns']             = 'This shows the number of visits you received through a tracked campaign.';
$lang['intro_medium']                = 'This shows the number of visits you received via a specific medium of a tracked campaign, e.g. email, social media, etc.';
$lang['intro_source']                = 'This shows the number of visits you received via a specific source of a tracked campaign, e.g. newsletter, Facebook, etc.';
$lang['intro_auditlog']              = 'Events captured from the configured logger facilities in the selected timeframe, newest first. Use the filters to narrow the list; the free text filter matches the subject and the message.';
$lang['intro_auditactions']          = 'How often each audit action was recorded in the selected timeframe, grouped by facility and action.';
$lang['intro_auditusers']            = 'Which users caused the most audit events in the selected timeframe.';

// audit log page
$lang['audit_filter_facility'] = 'Facility';
$lang['audit_filter_any']      = 'any';
$lang['audit_filter_user']     = 'User';
$lang['audit_filter_action']   = 'Action';
$lang['audit_filter_q']        = 'Text';
$lang['audit_filter_go']       = 'Filter';
$lang['audit_col_time']        = 'Time';
$lang['audit_col_facility']    = 'Facility';
$lang['audit_col_user']        = 'User';
$lang['audit_col_ip']          = 'IP';
$lang['audit_col_action']      = 'Action';
$lang['audit_col_subject']     = 'Subject';
$lang['audit_col_message']     = 'Message';
$lang['audit_col_details']     = 'Details';
$lang['audit_noentries']       = 'No audit events match.';

// the dashboard items
$lang['dash_pageviews']     = '<strong>%d</strong> Page Views';
$lang['dash_sessions']      = '<strong>%d</strong> Visits (Sessions)';
$lang['dash_visitors']      = '<strong>%d</strong> Unique Visitors';
$lang['dash_users']         = '<strong>%d</strong> Logged in Users';
$lang['dash_logins']        = '<strong>%d</strong> User Logins';
$lang['dash_registrations'] = '<strong>%s</strong> New Registrations';
$lang['dash_current']       = '<strong>%d</strong> Current Visitors';
$lang['dash_bouncerate']    = '<strong>%.1f%%</strong> Bounces';
$lang['dash_timespent']     = '<strong>%.2f</strong> Minutes Spent in an Average Session';
$lang['dash_avgpages']      = '<strong>%.2f</strong> Pages Viewed in an Average Session';
$lang['dash_newvisitors']   = '<strong>%.1f%%</strong> New Visitors';
$lang['dash_last']          = '<strong>%s</strong> Last Visit';

$lang['dash_mostpopular'] = 'Most Popular Pages';
$lang['dash_newincoming'] = 'Top Incoming New Links';
$lang['dash_topsearch']   = 'Top Search Phrases';

// graph labels
$lang['graph_edits']       = 'Page Edits';
$lang['graph_creates']     = 'Page Creations';
$lang['graph_deletions']   = 'Page Deletions';
$lang['graph_views']       = 'Page Views';
$lang['graph_sessions']    = 'Visits';
$lang['graph_visitors']    = 'Visitors';
$lang['graph_page_count']  = 'Pages';
$lang['graph_page_size']   = 'Pagessize (MB)';
$lang['graph_media_count'] = 'Media Items';
$lang['graph_media_size']  = 'Media Item Size (MB)';
