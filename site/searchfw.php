<?php
/* @(#) $Id: searchfw.php,v 1.6 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2013 Trend Micro
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       
//TODO: Needs to be updated like search.php

/* OS PHP init */
if (!function_exists('os_handle_start'))
{
    echo '<b class="red-text">You are not allowed direct access.</b>';
    return(1);
}


/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo 'Unable to access ossec directory.';
    exit(1);
}


/* Initializing some variables */
$u_final_time = time(0);
$u_init_time = $u_final_time - $ossec_search_time;
$u_srcport = "";
$u_dstport = "";
$u_action = "";
$u_srcip = "";
$u_dstip = "";
$u_location = "";

$USER_srcip = NULL;
$USER_dstip = NULL;
$USER_srcport = NULL;
$USER_dstport = NULL;
$USER_action = NULL;
$USER_location = NULL;
$USER_protocol = NULL;

/* generic pattern */
$intpattern = "/^[0-9]{1,8}$/";
$strpattern = "/^[0-9a-zA-Z.: _|^!\-()?]{1,128}$/";

/* Reading user input -- being very careful parsing it */
$datepattern = "/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/";
$timepattern = "/^([0-9]{2}):([0-9]{2})$/";
$initdate = filter_input(INPUT_POST, 'initdate', FILTER_SANITIZE_STRING);
$inittime = filter_input(INPUT_POST, 'inittime', FILTER_SANITIZE_STRING);

if ($initdate != false && $initdate != NULL && $inittime != false && $inittime != NULL) {
    if(preg_match($datepattern, $initdate, $regs) && preg_match($timepattern, $inittime, $regt)) {
        $USER_init = mktime($regt[1], $regt[2], 0,$regs[2],$regs[3],$regs[1]);
        $u_init_time = $USER_init;
    }
}

$finaldate = filter_input(INPUT_POST, 'finaldate', FILTER_SANITIZE_STRING);
$finaltime = filter_input(INPUT_POST, 'finaltime', FILTER_SANITIZE_STRING);

if ($finaldate != false && $finaldate != NULL && $finaltime != false && $finaltime != NULL) {
    if(preg_match($datepattern, $finaldate, $regs) && preg_match($timepattern, $finaltime, $regt)) {
        $USER_final = mktime($regt[1], $regt[2], 0,$regs[2],$regs[3],$regs[1]);
        $u_final_time = $USER_final;
    }
}

/* Getting ports */
$srcport = filter_input(INPUT_POST, 'srcport', FILTER_SANITIZE_NUMBER_INT);
if ($srcport != false && $srcport != NULL) {
    if ($srcport >= 0 && $srcport < 65536) {
        $USER_srcport = $srcport;
        $u_srcport = $USER_srcport;
    }
}

$dstport = filter_input(INPUT_POST, 'dstport', FILTER_SANITIZE_NUMBER_INT);
if ($dstport != false && $dstport != NULL) {
    if ($dstport >= 0 && $dstport < 65536) {
        $USER_dstport = $dstport;
        $u_dstport = $USER_dstport;
    }
}

/* Getting location */
$location = filter_input(INPUT_POST, 'locationpattern', FILTER_SANITIZE_STRING);
if ($location != false && $location != NULL) {
    $lcpattern = "/^[0-9a-zA-Z.: _|^!>\/\\-]{1,156}$/";
    if(preg_match($lcpattern, $location)) {
        $LOCATION_pattern = $location;
        $u_location = $LOCATION_pattern;
    }
            
}

/* Src ip pattern */
$ippattern = "/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/";
$srcippattern = filter_input(INPUT_POST, 'srcippattern', FILTER_SANITIZE_STRING);
if ($srcippattern != false && $srcippattern != NULL) {
   if(preg_match($ippattern, $srcippattern))
   {
       $USER_srcip = $srcippattern;
       $u_srcip = $USER_srcip;
   }
}

/* dst ip */
$dstippattern = filter_input(INPUT_POST, 'dstippattern', FILTER_SANITIZE_STRING);
if ($dstippattern != false && $dstippattern != NULL) {
   if(preg_match($ippattern, $dstippattern))
   {
       $USER_dstip = $dstippattern;
       $u_dstip = $USER_dstip;
   }
}

/* User pattern */
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_STRING);
if ($action != false && $action != NULL) {
   if(preg_match($strpattern, $action))
   {
       $USER_action = $action;
       $u_action = $USER_action;
   }    
}

/* Maximum number of alerts */
$maxalerts = filter_input(INPUT_POST, 'max_alerts_per_page', FILTER_SANITIZE_NUMBER_INT);
if ($maxalerts != false && $maxalerts != NULL) {
    if ($maxalerts > 200 && $maxalerts < 10000) {
        $ossec_max_alerts_per_page = $maxalerts;
    }
}

/* Search forms */
echo '<form name="dosearch" method="post" action="index.php?f=sf">';
/* time field */
echo '<div class="row"><div class="col s12 m3">'
     .'<label for="i_date_a">From Date</label><input class="blue-text text-darken-2" type="date" name="initdate" id="i_date_a" value="'.date('Y-m-d', $u_init_time).'"/>'
     .'<label for="i_time_a">From Time</label><input class="blue-text text-darken-2" type="time" name="inittime" id="i_time_a" value="'.date('H:i', $u_init_time).'"/></div>'
     .'<div class="col s12 m3"><label for="f_date_a">To Date</label><input class="blue-text text-darken-2" type="date" name="finaldate" id="f_date_a" value="'.date('Y-m-d', $u_final_time).'"/>'
     .'<label for="f_time_a">To Time</label><input class="blue-text text-darken-2" type="time" name="finaltime" id="f_time_a" value="'.date('H:i', $u_final_time).'"/></div>'
     .'</div>';

/* Srcip pattern */
echo '<div class="row"><div class="col s12 m3"><label for="srcippattern">Src IP</label>'
    .'<input class="blue-text text-darken-2" id="srcippattern" type="text" name="srcippattern" value="'.$u_srcip.'"></div>';

/* Dst pattern */
echo '<div class="col s12 m3"><label for="dstippattern">Dst IP</label>'
    .'<input class="blue-text text-darken-2" id="dstippattern" type="text" name="dstippattern" value="'.$u_dstip.'"></div>';

/* Src Port */
echo '<div class="col s12 m3"><label for="srcportpattern">Src Port</label>'
    .'<input class="blue-text text-darken-2" id="srcportpattern" type="text" name="srcportpattern" value="'.$u_srcport.'"></div></div>';

/* Dst Port */
echo '<div class="row"><div class="col s12 m3"><label for="dstportpattern">Dst Port</label>'
    .'<input class="blue-text text-darken-2" id="dstportpattern" type="text" name="dstportpattern" value="'.$u_dstport.'"></div>';

/* Location */
echo '<div class="col s12 m3"><label for="locationpattern">Location</label>'
    .'<input class="blue-text text-darken-2" id="locationpattern" type="text" name="locationpattern" value="'.$u_location.'"></div>';

/* Action */
echo '<div class="col s12 m3"><label for="actionpattern">Action</label>'
    .'<input class="blue-text text-darken-2" id="actionpattern" type="text" name="actionpattern" value="'.$u_action.'"></div></div>';

/* Max Alerts */
echo '<div class="row"><div class="col s12 m3"><label for="max_alerts_per_page">Max Alerts</label>'
    .'<input class="blue-text text-darken-2" id="max_alerts_per_page" type="text" name="max_alerts_per_page" value="'.$ossec_max_alerts_per_page.'"></div></div>';

/* Button */
echo '<div class="row"><div class="col s12 m3"><input type="submit" name="search" value="Search" class="btn"></div></div>';
echo '</form>';
    
/* show result */
echo '<div class="row"><div class="col s12"><h5 class="topt">Results:</h5>';

if(!isset($USER_init) || !isset($USER_final))
{
    echo '<b>No search performed.</b></div></div>';
    return(1);
}

/* Search id not used */
$search_id = NULL;

/* Getting last firewall events */
$alert_list = os_searchfw($ossec_handle, $search_id,
                          $USER_init, $USER_final, 
                          $ossec_max_alerts_per_page,
                          $USER_protocol,
                          $USER_srcip, $USER_dstip,
                          $USER_srcport, $USER_dstport,
                          $USER_action, $USER_location);
if($alert_list == NULL)
{
    echo '<b class="red-text text-darken-2">Nothing returned</b></div></div>';
}
else
{
    echo '</div></div>';
    echo "<b>Total entries found: </b>".sizeof($alert_list)."<br /><br />";

    /* Printing all available dstips  */
    echo '<table width="100%">';
    search_pavailable($alert_list[0]{'dstips'}, 
                      $alert_list[0]{'dstips_total'}, 
                      "dstip", "Destination IP", "Dst IP breakdown");
    
    /* Printing all available srcips */
    search_pavailable($alert_list[0]{'srcips'}, 
                      $alert_list[0]{'srcips_total'}, 
                      "srcip", "Source IP", "Src IP breakdown");


    echo '</table><br />';
}


/* Printing all rules */
$evt_count = sizeof($alert_list) -1;
if($evt_count >= ($ossec_max_alerts_per_page -3))
{
    echo '
        <script type="text/javascript">
        alert (\'Your search returned more than the maximum value allowed: "'.
        $ossec_max_alerts_per_page.'". Please narrow your search to '. 
        'see all events.\')
        </script>';
}


/* Initializing div closeout control */
$dstip_div = 0;
$srcip_div = 0;

if($alert_list != NULL) {
    echo '<h5 class="topt">Alert list</h5>';
}
    
while($evt_count > 0)
{
    $alert = $alert_list[$evt_count];
    $al_date = date('Y M d H:i:s', $alert{'time'});
    
    /* Printing dstip block */
    if(isset($alert{'dstip_count'}))
    {
        if($dstip_div == 1)
        {
            /* We also close the srcip div */
            echo '</div></div>';
            $srcip_div = 0;
        }
        else
        {
            $dstip_div = 1;
        }
        echo '<div id="ctdstip'.$alert{'dstip'}.'-'.$alert{'dstip_count'}.'" 
            style="display: block">';
    }
    

    /* Printing srcip block */
    if(isset($alert{'srcip_count'}))
    {
        if($srcip_div == 1)
        {
            echo '</div>';
        }
        else
        {
            $srcip_div = 1;
        }

        echo '<div id=\'ctsrcip'.$alert{'srcip'}.'-'.$alert{'srcip_count'}.'\'
            style="display: block">';
    }

    echo "<div class=\"alert\"><b>".$al_date
        .'</b> Firewall <strong>'.$alert{'action'}."</strong>\n<br />";
    echo "<b>Location: </b>".$alert{'location'};    
    echo
        '</div><div class="msg">'."\n";

    echo $alert{'msg'}."<br />\n";     
    echo "<br /></div>\n";
    $evt_count--;
}

/* Closing out left divs */
if($srcip_div == 1)
{
    echo "</div>";
}
if($dstip_div == 1)
{
    echo "</div>";
}

/* EOF */
?>
