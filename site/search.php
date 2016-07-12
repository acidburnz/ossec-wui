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
    echo "<b class='red'>You are not allowed direct access.</b><br />\n";
    return(1);
}


/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo "Unable to access ossec directory.\n";
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
if(isset($_POST['searchid']))
{
    if(preg_match('/^[a-z0-9]+$/', $_POST['searchid']))
    {
        $USER_searchid = $_POST['searchid'];
    }
}


$rt_sk = "";
$sv_sk = 'checked="checked"';
if(isset($_POST['monitoring']) && ($_POST['monitoring'] == 1))
{
    $rt_sk = 'checked="checked"';
    $sv_sk = "";

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


/* Reading user input -- being very careful parsing it */
$datepattern = "/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/";
$timepattern = "/^([0-9]{2}):([0-9]{2})$/";
if(isset($_POST['initdate']) && isset($_POST['inittime']))
{
    if(preg_match($datepattern, $_POST['initdate'], $regs) && preg_match($timepattern, $_POST['inittime'], $regt))
    {
        $USER_init = mktime($regt[1], $regt[2], 0,$regs[2],$regs[3],$regs[1]);
        $u_init_time = $USER_init;
    }
}
if(isset($_POST['finaldate']) && isset($_POST['finaltime']))
{
    if(preg_match($datepattern, $_POST['finaldate'], $regs) && preg_match($timepattern, $_POST['finaltime'], $regt))
    {
        $USER_final = mktime($regt[1], $regt[2], 0,$regs[2],$regs[3],$regs[1]);
        $u_final_time = $USER_final;
    }
}
if(isset($_POST['level']))
{
    if((is_numeric($_POST['level'])) &&
        ($_POST['level'] > 0) &&
        ($_POST['level'] < 16))
    {
        $USER_level = $_POST['level'];
        $u_level = $USER_level;
    }
}
if(isset($_POST['page']))
{
    if((is_numeric($_POST['page'])) &&
        ($_POST['page'] > 0) &&
        ($_POST['page'] <= 999))
    {
        $USER_page = $_POST['page'];
    }
}


$strpattern = "/^[0-9a-zA-Z.: _|^!\-()?]{1,128}$/";
$intpattern = "/^[0-9]{1,8}$/";

if(isset($_POST['strpattern']))
{
   if(preg_match($strpattern, $_POST['strpattern']) == true)
   {
       $USER_pattern = $_POST['strpattern'];
       $u_pattern = $USER_pattern;
   }
}


/* Getting location */
if(isset($_POST['locationpattern']))
{
    $lcpattern = "/^[0-9a-zA-Z.: _|^!>\/\\-]{1,156}$/";
    if(preg_match($lcpattern, $_POST['locationpattern']) == true)
    {
        $LOCATION_pattern = $_POST['locationpattern'];
        $u_location = $LOCATION_pattern;
    }
}


/* Group pattern */
if(isset($_POST['grouppattern']))
{
    if($_POST['grouppattern'] == "ALL")
    {
        $USER_group = NULL;
    }
    else if(preg_match($strpattern,$_POST['grouppattern']) == true)
    {
        $USER_group = $_POST['grouppattern'];
    }
}

/* Group pattern */
if(isset($_POST['logpattern']))
{
    if($_POST['logpattern'] == "ALL")
    {
        $USER_log = NULL;
    }
    else if(preg_match($strpattern,$_POST['logpattern']) == true)
    {
        $USER_log = $_POST['logpattern'];
    }
}


/* Rule pattern */
if(isset($_POST['rulepattern']))
{
   if(preg_match($strpattern, $_POST['rulepattern']) == true)
   {
       $USER_rule = $_POST['rulepattern'];
       $u_rule = $USER_rule;
   }
}


/* Src ip pattern */
if(isset($_POST['srcippattern']))
{
   if(preg_match($strpattern, $_POST['srcippattern']) == true)
   {
       $USER_srcip = $_POST['srcippattern'];
       $u_srcip = $USER_srcip;
   }
}


/* User pattern */
if(isset($_POST['userpattern']))
{
   if(preg_match($strpattern, $_POST['userpattern']) == true)
   {
       $USER_user = $_POST['userpattern'];
       $u_user = $USER_user;
   }
}


/* Maximum number of alerts */
if(isset($_POST['max_alerts_per_page']))
{
    if(preg_match($intpattern, $_POST['max_alerts_per_page']) == true)
    {
        if(($_POST['max_alerts_per_page'] > 200) &&
           ($_POST['max_alerts_per_page'] < 10000))
        {
            $ossec_max_alerts_per_page = $_POST['max_alerts_per_page'];
        }
    }
}



/* Getting search id  -- should be enough to avoid duplicates */
if( array_key_exists( 'search', $_POST ) ) {
    if($_POST['search'] == "Search")
    {
        /* Creating new search id */
        $USER_searchid = md5(uniqid(rand(), true));
        $USER_page = 1;
    }
    else if($_POST['search'] == "<< First")
    {
        $USER_page = 1;
    }
    else if($_POST['search'] == "< Prev")
    {
        if($USER_page > 1)
	    {
	        $USER_page--;
	    }
	}
	else if($_POST['search'] == "Next >")
	{
	    $USER_page++;
	}
	else if($_POST['search'] == "Last >>")
	{
	    $USER_page = 999;
	}
	else if($_POST['search'] == "")
	{
	}
	else
	{
	    echo "<b class='red'>Invalid search. </b><br />\n";
	    return;
	}
}

/* Printing current date */
//echo '<div class="smaller2">'.date('F dS Y h:i:s A').'<br />';
echo '<div class="row"><div class="right">Last Update: '.date('F dS, Y h:i:s A').'</div></div>';
if($USER_monitoring == 1)
{
    //echo ' -- Refreshing every '.$ossec_refresh_time.' secs</div><br />';
    echo '<div class="row"><div class="right" -- Refreshing every '.$ossec_refresh_time.' secs</div></div>';
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
echo '<div class="col s12 m3"><div class="input-field col s12 m5 blue-text text-darken-2"><select name="grouppattern">';
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
            echo '<option class="bluez" '.$sl.
                 ' value="'.$cat_val.'">'.$cat_name.'</option>';
        }
        else
        {
            echo '<option value="'.$cat_val.'" '.$sl.
                 '> &nbsp; '.$cat_name.'</option>';
        }
    }
}
echo '</select><label>Category</label></div></div></div>';

/* Str pattern */
echo '<div class="row"><div class="col s12 m3"><label for="strpattern">Pattern</label>'
    .'<input class="blue-text text-darken-2" id="strpattern" type="text" name="strpattern" value="'.$u_pattern.'"></div>';

/* Log formats */
echo '<div class="col s12 m3"><div class="input-field col s12 m5 blue-text text-darken-2"><select name="logpattern">';
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
            echo '<option class="bluez" '.$sl.
                 ' value="'.$cat_val.'">'.$cat_name.'</option>';
        }
        else
        {
            echo '<option value="'.$cat_val.'" '.$sl.
                 '> &nbsp; '.$cat_name.'</option>';
        }
    }
}
echo '</select><label>Log formats</label></div></div></div>';


/* Srcip pattern */
echo '<div class="row"><div class="col s12 m3"><label for="srcippattern">Src IP</label>'
    .'<input class="blue-text text-darken-2" id="srcippattern" type="text" name="srcippattern" value="'.$u_srcip.'"></div>';

/* Rule pattern */
echo '<div class="col s12 m3"><label for="userpattern">User</label>'
    .'<input class="blue-text text-darken-2" id="userpattern" type="text" name="userpattern" value="'.$u_user.'"></div></div>';


/* Location */
echo '<div class="row"><div class="col s12 m3"><label for="locationpattern">Location</label>'
    .'<input class="blue-text text-darken-2" id="locationpattern" type="text" name="locationpattern" value="'.$u_rule.'"></div>';


/* Rule pattern */
echo '<div class="col s12 m3"><label for="rulepattern">Rule ID</label>'
    .'<input class="blue-text text-darken-2" id="rulepattern" type="text" name="rulepattern" value="'.$u_rule.'"></div></div>';


/* Max Alerts  */
echo '<div class="row"><div class="col s12 m3"><label for="max_alerts_per_page">Max Alerts</label>'
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
if($_POST['search'] != "Search")
{
    $output_list = os_getstoredalerts($ossec_handle, $USER_searchid);
    $used_stored = 1;
}

/* Searching for new ones */
else
{
    /* Getting alerts */
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
        echo "<b class='red'>Nothing returned (search expired). </b>";
    }
    else
    {
        echo "<b class='red'>Nothing returned. </b><br />";
    }
    return(1);
}


/* Checking for no return */
if(!isset($output_list[0]{'count'}))
{
    echo "<b class='red'>Nothing returned. </b><br />\n";
    return(1);
}


/* Checking maximum page size */
if($USER_page >= $output_list[0]{'pg'})
{
    $USER_page = $output_list[0]{'pg'};
}

/* Page 1 will become the latest and the latest, page 1 */
$real_page = ($output_list[0]{'pg'} + 1) - $USER_page;


echo '<div><b>Total alerts found: </b>'.$output_list[0]{'count'}.'</div>';

if($output_list[0]{'pg'} > 1)
{
    echo "<b>Output divided in </b>".
         $output_list[0]{'pg'}." pages.<br />";

    echo '<br /><form name="dopage" method="post" action="index.php?f=s">';
}


if($output_list[0]{'pg'} > 1)
{
    echo '
        <input type="submit" name="search" value="<< First" class="button"
               class="formText" />

        <input type="submit" name="search" value="< Prev" class="button"
               class="formText" />
         ';

    echo 'Page <b>'.$USER_page.'</b> ('.$output_list[0]{$real_page}.' alerts)';
}

/* Currently page */
echo '
    <input type="hidden" name="initdate"
           value="'.date('Y-m-d H:i', $u_init_time).'" />
    <input type="hidden" name="finaldate"
           value="'.date('Y-m-d H:i', $u_final_time).'" />
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
echo '
    &nbsp;&nbsp;
    <input type="submit" name="search" value="Next >" class="button"
           class="formText" />
     <input type="submit" name="search" value="Last >>" class="button"
           class="formText" />
    </form>
';
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
