<?php
/* @(#) $Id: stats.php,v 1.9 2008/03/03 19:37:26 dcid Exp $ */

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
    echo '<b class="red-text">You are not allowed direct access.</b>';
    return(1);
}

/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo '<b class="red-text">Unable to access ossec directory.</b>';
    return(1);
}


/* Current date values */
$curr_time = time(0);
$curr_day = date('d',$curr_time);
$curr_month = date('m', $curr_time);
$curr_year = date('Y', $curr_time);

/* Getting user values */
$day = filter_input(INPUT_POST, 'day', FILTER_SANITIZE_NUMBER_INT);
if (($day != false && $day != NULL) || $day == 0 ) {
    if ($day >= 0 && $day <= 31) {
        $USER_day = $day;
    }
}

$month = filter_input(INPUT_POST, 'month', FILTER_SANITIZE_NUMBER_INT);
if ($month != false) {
    if ($month > 0 && $month <= 12) {
        $USER_month = $month;
    }
}

$year = filter_input(INPUT_POST, 'year', FILTER_SANITIZE_NUMBER_INT);
if ($year != false) {
    if ($year >= 1 && $year <= 3000) {
        $USER_year = $year;
    }
}

/* Building stat times */
if(isset($USER_year) && isset($USER_month) && isset($USER_day))
{
    /* Stat for whole month */
    if($USER_day == 0)
    {
        $init_time = mktime(0, 0, 0, $USER_month, 1, $USER_year);
        $final_time = mktime(0, 0, 0, $USER_month +1, 0, $USER_year);
    }

    else
    {
        $init_time = mktime(0, 0, 0, $USER_month, $USER_day, $USER_year);
        $final_time = mktime(0, 0, 10, $USER_month, $USER_day, $USER_year);
        
        /* Getting valid formated day */
        $USER_day = date('d',$init_time);
    }
}
else
{
    $init_time = $curr_time -1;
    $final_time = $curr_time;

    /* Setting user values */
    $USER_month = $curr_month;
    $USER_day = $curr_day;
    $USER_year = $curr_year;
}




/* Day option */
echo '<div class="row">';
echo '<form name="dosearch" method="post" action="index.php?f=t">'
    . '<div class="input-field col s12 m3 blue-text text-darken-2">'
    . '<select name="day">';

$option = '<option value="%s" %s>%s</option>';

echo sprintf($option, 0, "", "All days");

for($l_counter = 1; $l_counter <= 31 ; $l_counter++)
{
    $tmp_msg = '';
    if($l_counter == $USER_day)
    {
        $tmp_msg = ' selected="selected"';
    }
    echo sprintf($option, $l_counter, $tmp_msg, $l_counter);
}
echo '</select><label>Day</label></div>';


/* Monthly */
echo '<div class="input-field col s12 m3 blue-text text-darken-2">'
    . '<select name="month">';
$months = array("January" => "Jan", 
                "February" => "Feb", 
                "March" => "Mar", 
                "April" => "Apr", 
                "May" => "May",
                "June" => "Jun",
                "July" => "Jul", 
                "August" => "Aug", 
                "September" => "Sep", 
                "October" => "Oct", 
                "November" => "Nov", 
                "December" => "Dec");
$mnt_ct = 1;
foreach($months as $tmp_month => $tmp_month_v)
{
    if($USER_month == $mnt_ct)
    {
        echo '    <option value="'.$mnt_ct.'" selected="selected">'.
             $tmp_month.'</option>';
    }
    else
    {
        echo '    <option value="'.$mnt_ct.'">'.$tmp_month.'</option>';
    }
    $mnt_ct++;
}
echo '</select><label>Month</label></div>';


/* Year */
echo '<div class="input-field col s12 m3 blue-text text-darken-2">'
    . '<select name="year">';

echo '<option value="'.$curr_year.'" selected="selected">'.$curr_year.'</option>
    <option value="'.($curr_year-1).'">'.($curr_year-1).'</option>
    <option value="'.($curr_year-2).'">'.($curr_year-2).'</option>
    ';
echo '</select><label>Year</label></div>'
     . '<div class="col s12 m3"><input type="submit" name="Stats" value="Change options" class="btn" />'
     .'</div></form></div>';


echo '<div class="row"><div class="col s12 m3">';
/* Getting daily stats */
$l_year_month = date('Y/M', $init_time);

$stats_list = os_getstats($ossec_handle, $init_time, $final_time);

$daily_stats = array();
if(isset($stats_list{$l_year_month}{$USER_day}))
{
    $daily_stats = $stats_list{$l_year_month}{$USER_day};
    $all_stats = $stats_list{$l_year_month};
}

if(!isset($daily_stats{'total'}))
{
    echo '<b class="red-text">No stats available.</b>';
    return(1);
}      

/* Day 0 == month stats */
if($USER_day == 0)
{
    echo '<h5 class="topt">Ossec Stats for: <b class="blue-text text-darken-2">'.$l_year_month.'</b></h5>';
}
else
{
    echo '<h5 class="topt">Ossec Stats for: <b class="blue-text text-darken-2">'.$l_year_month.
         '/'.$USER_day.'</b></h5>';
}

echo '<b>Total</b>: '.number_format($daily_stats{'total'}).'<br />';
echo '<b>Alerts</b>: '.number_format($daily_stats{'alerts'}).'<br />';
echo '<b>Syscheck</b>: '.number_format($daily_stats{'syscheck'}).'<br />';
echo '<b>Firewall</b>: '.number_format($daily_stats{'firewall'}).'<br />';
if($USER_day != 0)
{
    (int)$h_avg = (int)$daily_stats{'total'}/24;
    echo '<b>Average</b>: '.sprintf("%.01f", $h_avg).' events per hour.';
}

echo '</div>';
echo '<div class="col s12 m3">';

echo '<h5 class="topt">Aggregate values by severity</h5>';
echo '<table class="responsive-table bordered">
    <thead>
    <tr>
    <th>Level</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
    </thead>
';

if( array_key_exists( 'level', $daily_stats ) ) {
    asort($daily_stats{'level'});
}

if( array_key_exists( 'rule', $daily_stats ) ) {
    asort($daily_stats{'rule'});
}

$odd_count = 0;
$odd_msg = '';

if( array_key_exists( 'level', $daily_stats ) ) {
	foreach($daily_stats{'level'} as $l_level => $v_level)
	{
	    (int)$level_pct = (int)($v_level * 100)/$daily_stats{'alerts'};
	    if(($odd_count % 2) == 0)
	    {
	        $odd_msg = ' class="odd"';
	    }
	    else
	    {
	        $odd_msg = '';
	    }
	    $odd_count++;
	    echo '
	    <tr'.$odd_msg.'>
	    <td>Total for level '.$l_level.'</td>
	    <td>'.number_format($v_level).'</td>
	    <td>'.sprintf("%.01f", $level_pct).'%</td>
	    </tr>
	    ';
	}
}
if(($odd_count % 2) == 0)
{
    $odd_msg = ' class="odd"';
}
else
{
    $odd_msg = '';
}
echo '
<tr'.$odd_msg.'>
<td>Total for all levels</td>
<td>'.number_format($daily_stats{'alerts'}).'</td>
<td>100%</td>
</tr>
</table>';

echo '</div>';
echo '<div class="col s12 m3">';

echo '<h5 class="topt">Aggregate values by rule</h5>';
echo '<table class="responsive-table bordered">
    <thead>
    <tr>
    <th>Rules</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
    </thead>
';


$odd_count = 0;
$odd_msg = '';

if( array_key_exists( 'rule', $daily_stats ) ) {
	foreach($daily_stats{'rule'} as $l_rule => $v_rule)
	{
	    (int)$rule_pct = (int)($v_rule * 100)/$daily_stats{'alerts'};
	    if(($odd_count % 2) == 0)
	    {
	        $odd_msg = ' class="odd"';
	    }
	    else
	    {
	        $odd_msg = '';
	    }
	    $odd_count++;
	    echo '
	    <tr'.$odd_msg.'>
	    <td>'.$l_rule.'</td>
	    <td>'.number_format($v_rule).'</td>
	    <td>'.sprintf("%.01f", $rule_pct).'%</td>
	    </tr>
	    ';
	}
}
if(($odd_count % 2) == 0)
{
    $odd_msg = ' class="odd"';
}
else
{
    $odd_msg = '';
}
echo '
<tr'.$odd_msg.'>
<td>Total</td>
<td>'.number_format($daily_stats{'alerts'}).'</td>
<td>100%</td>
</tr>
';

echo '</table>';
echo '</div></div>';
echo '<div class="row"><div class="col s12">';


/* Monthly stats */
if($USER_day == 0)
{
    echo '<h5 class="topt">Total values per Day</h5>';
echo '
        <table class="responsive-table bordered">
        <thead>
        <tr>
        <th>Day</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>
        </thead>
        ';

    $odd_count = 0;
    $odd_msg;
    for($i = 1; $i<=31; $i++)
    {
        if($i < 10)
        {
            $myi = "0$i";
        }
        else
        {
            $myi = $i;
        }
            
        if(!isset($all_stats{$myi}{'total'}))
        {
            continue;
        }
        
        $d_total = $all_stats{$myi}{'total'};
        $d_alerts = $all_stats{$myi}{'alerts'};
        $d_syscheck = $all_stats{$myi}{'syscheck'};
        $d_firewall = $all_stats{$myi}{'firewall'};


        (int)$total_pct = (int)($d_total * 100)/max($daily_stats{'total'},1);
        (int)$alerts_pct = (int)($d_alerts * 100)/max($daily_stats{'alerts'},1);
        (int)$syscheck_pct=(int)($d_syscheck *100)/max($daily_stats{'syscheck'},1);
        (int)$firewall_pct=(int)($d_firewall *100)/max($daily_stats{'firewall'},1);

        if(($odd_count % 2) == 0)
        {
            $odd_msg = ' class="odd"';
        }
        else
        {
            $odd_msg = '';
        }
        $odd_count++;
        echo '
            <tr'.$odd_msg.'>
            <td>Day '.$i.'</td>
            <td>'.number_format($d_alerts).'</td>
            <td>'.sprintf("%.01f", $alerts_pct).'%</td>

            <td>'.number_format($d_syscheck).'</td>
            <td>'.sprintf("%.01f", $syscheck_pct).'%</td>

            <td>'.number_format($d_firewall).'</td>
            <td>'.sprintf("%.01f", $firewall_pct).'%</td>

            <td>'.number_format($d_total).'</td>
            <td>'.sprintf("%.01f", $total_pct).'%</td>
            </tr>
            ';
    }
}

/* Daily stats */
else
{
    echo '<h5 class="topt">Total values per hour</h5>';
    echo '
        <table class="responsive-table bordered">
        <thead>
        <tr>
        <th>Hour</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>
        </thead>
        ';

    $odd_count = 0;
    $odd_msg;
    for($i = 0; $i<=23; $i++)
    {
        if(!isset($daily_stats{'total_by_hour'}[$i]))
        {
            continue;
        }

        $hour_total = $daily_stats{'total_by_hour'}[$i];
        $hour_alerts = $daily_stats{'alerts_by_hour'}[$i];
        $hour_syscheck = $daily_stats{'syscheck_by_hour'}[$i];
        $hour_firewall = $daily_stats{'firewall_by_hour'}[$i];

        (int)$total_pct = (int)($hour_total * 100)/max($daily_stats{'total'},1);
        (int)$alerts_pct = (int)($hour_alerts * 100)/max($daily_stats{'alerts'},1);
        (int)$syscheck_pct=(int)($hour_syscheck *100)/max($daily_stats{'syscheck'},1);
        (int)$firewall_pct=(int)($hour_firewall *100)/max($daily_stats{'firewall'},1);

        if(($odd_count % 2) == 0)
        {
            $odd_msg = ' class="odd"';
        }
        else
        {
            $odd_msg = '';
        }
        $odd_count++;
        echo '
            <tr'.$odd_msg.'>
            <td>Hour '.$i.'</td>
            <td>'.number_format($hour_alerts).'</td>
            <td>'.sprintf("%.01f", $alerts_pct).'%</td>

            <td>'.number_format($hour_syscheck).'</td>
            <td>'.sprintf("%.01f", $syscheck_pct).'%</td>

            <td>'.number_format($hour_firewall).'</td>
            <td>'.sprintf("%.01f", $firewall_pct).'%</td>

            <td>'.number_format($hour_total).'</td>
            <td>'.sprintf("%.01f", $total_pct).'%</td>
            </tr>
            ';
    }
}

echo '</table></div></div>';

?>
