<?php
/* @(#) $Id: search.php,v 1.18 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2013 Trend Micro
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* OS PHP init */
if (!function_exists('os_handle_start'))
{
    echo '<b class="text-red">You are not allowed direct access.</b>';
    return(1);
}


/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo 'Unable to access ossec directory';
    exit(1);
}


/* Initializing some variables */
$u_final_time = time(0);
$u_init_time = $u_final_time - $ossec_search_time;
$u_level = $ossec_search_level;
$u_pattern = "";
$u_rule = "";
$u_srcip = "";
$u_user = "";
$u_location = "";


$USER_pattern = NULL;
$LOCATION_pattern = NULL;
$USER_group = NULL;
$USER_log = NULL;
$USER_rule = NULL;
$USER_srcip = NULL;
$USER_user = NULL;
$USER_page = 1;
$USER_searchid = 0;
$USER_monitoring = 0;
$used_stored = 0;

/* Getting search id */
$fsearchid = filter_input(INPUT_POST, 'searchid', FILTER_SANITIZE_STRING);
if ($fsearchid != false && $fsearchid != NULL) {
    $USER_searchid = $fsearchid;    
}

/* is real time monitoring */
$monitoring = filter_input(INPUT_POST, 'monitoring', FILTER_SANITIZE_NUMBER_INT);
if ($monitoring != false && $monitoring != NULL) {
    if ($monitoring == 1) {
         /* Cleaning up time */
        $USER_final = $u_final_time;
        $USER_init = $u_init_time;
        $USER_monitoring = 1;

        /* Cleaning up fields */
        $_POST['search'] = "Search";
        unset($_POST['initdate']);
        unset($_POST['finaldate']);
        
        /* Deleting search */
        if($USER_searchid != 0)
        {
            os_cleanstored($USER_searchid);
        }

        /* Refreshing every 90 seconds by default */
        $m_ossec_refresh_time = $ossec_refresh_time * 1000;

        echo '
            <script language="javascript">
                setTimeout("document.dosearch.submit()",'.
                $m_ossec_refresh_time.');
            </script>
            ';
        }
}

/* Getting start/end date */
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

/* Getting level */
$level = filter_input(INPUT_POST, 'level', FILTER_SANITIZE_NUMBER_INT);
if ($level != false && $level != NULL) {
    if ($level > 0 && $level < 16) {
        $USER_level = $level;
        $u_level = $USER_level;
    }
}

/* Getting page */
$page = filter_input(INPUT_POST, 'page', FILTER_SANITIZE_NUMBER_INT);
if ($page != false && $page != NULL) {
    if ($page > 0 && $page <= 999) {
        $USER_page = $page;
    }
}

/* Getting pattern  */
$strpattern = "/^[0-9a-zA-Z.: _|^!\-()?]{1,128}$/";
$strpat = filter_input(INPUT_POST, 'strpattern', FILTER_SANITIZE_STRING);
if ($strpat != false && $strpat != NULL) {
    if (preg_match($strpattern, $strpat)) {
        $USER_pattern = $strpat;
        $u_pattern = $USER_pattern;    
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

/* Group pattern */
$grouppattern = filter_input(INPUT_POST, 'grouppattern', FILTER_SANITIZE_STRING);
if ($grouppattern != false && $grouppattern != NULL) {
    if ($grouppattern == "ALL") {
        $USER_group = NULL;
    } else if(preg_match($strpattern, $grouppattern)) {
        $USER_group = $grouppattern;
    }
}

/* Log pattern */
$logpattern = filter_input(INPUT_POST, 'logpattern', FILTER_SANITIZE_STRING);
if ($logpattern != false && $logpattern != NULL) {
    if ($logpattern == "ALL") {
        $USER_log = NULL;
    } else if(preg_match($strpattern, $logpattern)) {
        $USER_log = $logpattern;
    }
}

/* Rule pattern */
$rulepattern = filter_input(INPUT_POST, 'rulepattern', FILTER_SANITIZE_STRING);
if ($rulepattern != false && $rulepattern != NULL) {
   if(preg_match($strpattern, $rulepattern) == true)
   {
       $USER_rule = $rulepattern;
       $u_rule = $USER_rule;
   }
}

/* Src ip pattern */
$ippattern = "/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/";
$srcip = filter_input(INPUT_POST, 'srcippattern', FILTER_SANITIZE_STRING);
if ($srcip != false && $srcip != NULL) {
    if (preg_match($ippattern, $srcip)) {
       $USER_srcip = $srcip;
       $u_srcip = $USER_srcip;
    }
}

/* User pattern */
$userpattern = filter_input(INPUT_POST, 'userpattern', FILTER_SANITIZE_STRING);
if ($userpattern != false && $userpattern != NULL) {
   if(preg_match($strpattern, $userpattern) == true)
   {
       $USER_user = $userpattern;
       $u_user = $USER_user;
   }
}

/* Maximum number of alerts */
$maxalerts = filter_input(INPUT_POST, 'max_alerts_per_page', FILTER_SANITIZE_NUMBER_INT);
if ($maxalerts != false && $maxalerts != NULL) {
    if ($maxalerts > 200 && $maxalerts < 10000) {
        $ossec_max_alerts_per_page = $maxalerts;
    }
}

/* Getting search id  -- should be enough to avoid duplicates */
$search = filter_input(INPUT_POST, 'search', FILTER_SANITIZE_STRING);
if ($search != false && $search != NULL) {
    if ($search == "Search") {
        /* Creating new search id */
        $USER_searchid = md5(uniqid(rand(), true));
        $USER_page = 1;
    }
    else if ($search == "First") {
        $USER_page = 1;
    }
    else if ($search == "Prev") {
        if($USER_page > 1)
	    {
	        $USER_page--;
	    }
    }
    else if ($search == "Next") {
        $USER_page++;
    }
    else if ($search == "Last") {
        $USER_page = 999;
    }
    else if ($search == "") {
        
    }
    else {
        echo '<b class="red-text">Invalid search.</b>';
        return;
    }
}

/* Printing current date */
//echo '<div class="smaller2">'.date('F dS Y h:i:s A').'<br />';
echo '<div class="right">Last Update: '.date('F dS, Y h:i:s A').'</div>';
if($USER_monitoring == 1)
{
    //echo ' -- Refreshing every '.$ossec_refresh_time.' secs</div><br />';
    echo '<div class="left"> -- Refreshing every '.$ossec_refresh_time.' secs</div>';
    $monf = '';
    $monr = 'checked="checked"';
}
else
{
    $monf = 'checked="checked"';
    $monr = '';
}


/* Getting all agents. */
$agent_list = os_getagents($ossec_handle);

echo '<form name="dosearch" method="post" action="index.php?f=s">';
echo '<div class="row"><div class="col s12 m12">';
echo '<div class="row"><div class="col s12 m2"><p>
        <input name="monitoring" type="radio" value="0" id="monf" '.$monf.'/>
        <label for="monf">Date</label>
      </p></div>'
      .'<div class="col s12 m3"><label for="i_date_a">From Date</label><input class="blue-text text-darken-2" type="date" name="initdate" id="i_date_a" value="'.date('Y-m-d', $u_init_time).'"/>'
      .'<label for="i_time_a">From Time</label><input class="blue-text text-darken-2" type="time" name="inittime" id="i_time_a" value="'.date('H:i', $u_init_time).'"/></div>'
      .'<div class="col s12 m3"><label for="f_date_a">To Date</label><input class="blue-text text-darken-2" type="date" name="finaldate" id="f_date_a" value="'.date('Y-m-d', $u_final_time).'"/>'
      .'<label for="f_time_a">To Time</label><input class="blue-text text-darken-2" type="time" name="finaltime" id="f_time_a" value="'.date('H:i', $u_final_time).'"/></div>'
      .'</div>';

echo '<div class="row"><div class="col s12 m2"><p>
        <input name="monitoring" type="radio" value="1" id="monr" '.$monr.'/>
        <label for="monr">Real time monitoring</label>
      </p></div>';

echo '</div></div></div>';

/* Level */
echo '<div class="row"><div class="col s12 m3"><div class="input-field col s4 blue-text text-darken-2"><select name="level">';

if($u_level == 1)
{
    echo '   <option value="1" selected="selected">All</option>';
}
else
{
    echo '   <option value="1">All</option>';
}
for($l_counter = 15; $l_counter >= 2; $l_counter--)
{
    if($l_counter == $u_level)
    {
        echo '   <option value="'.$l_counter.'" selected="selected">'.
             $l_counter.'</option>';
    }
    else
    {
        echo '   <option value="'.$l_counter.'">'.$l_counter.'</option>';
    }
}
echo '</select><label>Minimum level</label></div></div>';

/* Category */
echo '<div class="col s12 m3"><div class="input-field col s12 m7 blue-text text-darken-2"><select name="grouppattern">';
echo '<option value="ALL">All categories</option>';

foreach($global_categories as $_cat_name => $_cat)
{
    foreach($_cat as $cat_name => $cat_val)
    {
        $sl = "";
        if($USER_group == $cat_val)
        {
            $sl = ' selected="selected"';
        }
        if(strpos($cat_name, "(all)") !== FALSE)
        {
            echo '<option'.$sl.' value="'.$cat_val.'">'.$cat_name.'</option>';
        }
        else
        {
            echo '<option value="'.$cat_val.'" '.$sl.'> &nbsp; '.$cat_name.'</option>';
        }
    }
}
echo '</select><label>Category</label></div></div>';

/* Log formats */
echo '<div class="col s12 m3"><div class="input-field col s12 m7 blue-text text-darken-2"><select name="logpattern">';
echo '<option value="ALL" class="bluez">All log formats</option>';

foreach($log_categories as $_cat_name => $_cat)
{
    foreach($_cat as $cat_name => $cat_val)
    {
        $sl = "";
        if($USER_log == $cat_val)
        {
            $sl = ' selected="selected"';
        }
        if(strpos($cat_name, "(all)") !== FALSE)
        {
            echo '<option'.$sl.' value="'.$cat_val.'">'.$cat_name.'</option>';
        }
        else
        {
            echo '<option value="'.$cat_val.'" '.$sl.'> &nbsp; '.$cat_name.'</option>';
        }
    }
}
echo '</select><label>Log formats</label></div></div></div>';

/* Str pattern */
echo '<div class="row"><div class="col s12 m3"><label for="strpattern">Pattern</label>'
    .'<input class="blue-text text-darken-2" id="strpattern" type="text" name="strpattern" value="'.$u_pattern.'"></div>';

/* Srcip pattern */
echo '<div class="col s12 m3"><label for="srcippattern">Src IP</label>'
    .'<input class="blue-text text-darken-2" id="srcippattern" type="text" name="srcippattern" value="'.$u_srcip.'"></div>';

/* Rule pattern */
echo '<div class="col s12 m3"><label for="userpattern">User</label>'
    .'<input class="blue-text text-darken-2" id="userpattern" type="text" name="userpattern" value="'.$u_user.'"></div></div>';


/* Location */
echo '<div class="row"><div class="col s12 m3"><label for="locationpattern">Location</label>'
    .'<input class="blue-text text-darken-2" id="locationpattern" type="text" name="locationpattern" value="'.$u_location.'"></div>';


/* Rule pattern */
echo '<div class="col s12 m3"><label for="rulepattern">Rule ID</label>'
    .'<input class="blue-text text-darken-2" id="rulepattern" type="text" name="rulepattern" value="'.$u_rule.'"></div>';


/* Max Alerts  */
echo '<div class="col s12 m3"><label for="max_alerts_per_page">Max Alerts</label>'
    .'<input class="blue-text text-darken-2" id="max_alerts_per_page" type="text" name="max_alerts_per_page" value="'.$ossec_max_alerts_per_page.'"></div></div>';


/* Agent */
//foreach ($agent_list as $agent)

/* Final form */
echo '<div class="row"><div class="col s12 m3"><input type="submit" name="search" value="Search" class="btn"></div></div>';
echo '<input type="hidden" name="searchid" value="'.$USER_searchid.'" /></form>';

/* show result */
echo '<div class="row"><div class="col s12"><h5 class="topt">Results:</h5>';

if(!isset($USER_init) || !isset($USER_final) || !isset($USER_level))
{
    echo '<b>No search performed.</b></div></div>';
    return(1);
}

$output_list = NULL;


/* Getting stored alerts */
if($search != "Search")
{
    $output_list = os_getstoredalerts($ossec_handle, $USER_searchid);
    $used_stored = 1;
}

/* Searching for new ones */
else
{
    $output_list = os_searchalerts($ossec_handle, $USER_searchid,
                                   $USER_init, $USER_final,
                                   $ossec_max_alerts_per_page,
                                   $USER_level,$USER_rule, $LOCATION_pattern,
                                   $USER_pattern, $USER_group,
                                   $USER_srcip, $USER_user,
                                   $USER_log);
}

if($output_list == NULL || $output_list[1] == NULL)
{
    if($used_stored == 1)
    {
        echo "<b class='red'>Nothing returned (search expired). </b></div></div>";
    }
    else
    {
        echo "<b class='red'>Nothing returned. </b><br /></div></div>";
    }
    return(1);
}


/* Checking for no return */
if(!isset($output_list[0]{'count'}))
{
    echo '<b class="red">Nothing returned. </b></div></div>';
    return(1);
}

/* Checking maximum page size */
if($USER_page >= $output_list[0]{'pg'})
{
    $USER_page = $output_list[0]{'pg'};
}

/* Page 1 will become the latest and the latest, page 1 */
$real_page = ($output_list[0]{'pg'} + 1) - $USER_page;


if($output_list[0]{'pg'} > 1)
{
    echo '<div><form name="dopage" method="post" action="index.php?f=s">';
    echo '<input type="submit" name="search" value="First" class="btn-flat green-text text-darken-2" />
          <input type="submit" name="search" value="Prev" class="btn-flat green-text text-darken-2" />';

    echo 'Page <b>'.$USER_page.'</b>/'.$output_list[0]{'pg'}.' (<b>'.$output_list[0]{$real_page}.'</b>/'.$output_list[0]{'count'}.' alerts)';
} else {
    echo '<div><b>Total alerts found: </b>'.$output_list[0]{'count'}.'</div>';
}

/* Currently page */
echo '
    <input type="hidden" name="initdate"
           value="'.date('Y-m-d', $u_init_time).'" />
    <input type="hidden" name="finaldate"
           value="'.date('Y-m-d', $u_final_time).'" />
    <input type="hidden" name="inittime"
           value="'.date('H:i', $u_init_time).'" />
    <input type="hidden" name="finaltime"
           value="'.date('H:i', $u_final_time).'" />
    <input type="hidden" name="rulepattern" value="'.$u_rule.'" />
    <input type="hidden" name="srcippattern" value="'.$u_srcip.'" />
    <input type="hidden" name="userpattern" value="'.$u_user.'" />
    <input type="hidden" name="locationpattern" value="'.$u_location.'" />
    <input type="hidden" name="level" value="'.$u_level.'" />
    <input type="hidden" name="page" value="'.$USER_page.'" />
    <input type="hidden" name="searchid" value="'.$USER_searchid.'" />
    <input type="hidden" name="monitoring" value="'.$USER_monitoring.'" />
    <input type="hidden" name="max_alerts_per_page"
                         value="'.$ossec_max_alerts_per_page.'" />';


if($output_list[0]{'pg'} > 1)
{
echo '<input type="submit" name="search" value="Next" class="btn-flat green-text text-darken-2" />
     <input type="submit" name="search" value="Last" class="btn-flat green-text text-darken-2" />
     </form></div>';
}

echo '</div></div>';

/* Checking if page exists */
if(!isset($output_list[0]{$real_page}) ||
   (strlen($output_list[$real_page]) < 5) ||
   (!file_exists($output_list[$real_page])))
{
    echo "<b class='red'>Nothing returned (or search expired). </b><br />\n";
    return(1);
}

/* Printing page */
// TODO: There are functions for slurping file contents.
$fp = fopen($output_list[$real_page], "r");
if($fp)
{
    while(!feof($fp))
    {
        echo fgets($fp);
    }
}


/* EOF */
?>
