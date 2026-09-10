<?php

/**
 * Options for the statistics plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['loggroups']   = array('array');
$meta['anonips']     = array('onoff');
$meta['nolocation'] = array('onoff');
$meta['nousers']     = array('onoff');
$meta['retention']   = array('numeric', '_min' => 0, '_pattern' => '/\d+/', '_caution' => 'warning');
$meta['timezone']    = array('string');
$meta['audit_facilities'] = array('string');
$meta['audit_keepfiles'] = array('onoff');
$meta['audit_retention'] = array('numeric', '_min' => 0, '_pattern' => '/\d+/', '_caution' => 'warning');
$meta['audit_include'] = array('string');
$meta['audit_exclude'] = array('string');
$meta['audit_subject_keys'] = array('string');
