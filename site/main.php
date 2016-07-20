<?php
/* @(#) $Id: main.php,v 1.12 2008/03/03 19:37:26 dcid Exp $ */

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
    return(1);
}


/* Getting all agents */
if(($agent_list = os_getagents($ossec_handle)) == NULL)
{
    echo "No agent available.\n";
    return(1);
}


/* Printing current date */
/* echo '<div class="smaller2">'.date('F dS Y h:i:s A').'</div><br />'; */
echo '<div class="row"><div class="right">Last Update: '.date('F dS, Y h:i:s A').'</div></div>';

/* Getting syscheck information */
$syscheck_list = os_getsyscheck($ossec_handle);



echo '<div class="row">';
echo '<div class="col s12 m3">';
/* Available agents */
echo '<h5 class="topt">Available agents:</h5>';


/* Agent count for java script */
$agent_count = 0;

$agenti = '<div id="agent%s" onclick="ossec.togglesection(\'#agent%s\',\'#agentd%s\');" class="expand"><div class="valign-wrapper"><i class="material-icons valign green-text text-darken-3">add_circle</i><span class="valign %s">&nbsp;%s( %s ) %s</span></div></div>';
$agentd = '<div id="agentd%s" style="display:none;" class="detail"><b>Name:</b> %s<br/><b>IP:</b> %s<br/><b>Last Update:</b> %s<br/><b>OS:</b> %s</div>';


/* Looping all agents */
foreach ($agent_list as $agent) 
{
    $aclass = "";
    $amsg = "";

    /* If agent is connected */
    if($agent{'connected'})
    {
        $aclass = 'blue-text text-darken-2';
    }
    else
    {
        $aclass = 'red-text text-darken-2';
        $amsg = " - Inactive";
    }
    
    echo sprintf($agenti, $agent_count, $agent_count, $agent_count, $aclass, $agent['name'], $agent['ip'], $amsg);
    echo sprintf($agentd, $agent_count, $agent['name'], $agent['ip'], date('Y M d H:i:s', $agent['change_time']), $agent['os']);

    $agent_count++;
}

echo '</div><div class="col s12 m4">';
echo '<h5 class="topt">Latest modified files:</h5>';

$sysfiles = '<div id="file%s" onclick="ossec.togglesection(\'#file%s\',\'#filed%s\');" class="expand"><div class="valign-wrapper"><i class="material-icons valign green-text text-darken-3">add_circle</i><span class="valign blue-text text-darken-2">%s</span></div></div>';
$sysfilesd = '<div id="filed%s" style="display:none;" class="detail"><b>File:</b> %s<br/><b>Agent:</b> %s<br/><b>Modification time:</b> %s</div>';


/* Last modified files */
$syscheck_list = os_getsyscheck($ossec_handle);
if(($syscheck_list == NULL) || ($syscheck_list{'global_list'} == NULL))
{
    echo '<ul class="ulsmall bluez">
        No integrity checking information available.<br />
        Nothing reported as changed.
        </ul>
      ';
}
else
{
   if(isset($syscheck_list{'global_list'}) && 
      isset($syscheck_list{'global_list'}{'files'}))
   {
       $sk_count = 0;
       
       foreach($syscheck_list{'global_list'}{'files'} as $syscheck)
       {
           $sk_count++;
           if($sk_count > ($agent_count +4))
           {
               break;
           }
           
           # Initing file name
           $ffile_name = "";
           $ffile_name2 = "";
           
           if(strlen($syscheck[2]) > 40)
           {
               $ffile_name = substr($syscheck[2], 0, 45)."..";
               $ffile_name2 = substr($syscheck[2], 46, 85);
           }
           else
           {
               $ffile_name = $syscheck[2];
           }
                      
           echo sprintf($sysfiles, $sk_count, $sk_count, $sk_count, $ffile_name);
           echo sprintf($sysfilesd, $sk_count, $ffile_name, $syscheck[1], date('Y M d H:i:s', $syscheck[0]));
           
       }
   }
}


echo '</div><div class="col s12 m5">';


/* Getting last alerts */
$alert_list = os_getalerts($ossec_handle, 0, 0, 30);
if($alert_list == NULL)
{
    echo "<b class='red'>Unable to retrieve alerts. </b><br />\n";
}
else
{
    echo '<h5 class="topt">Latest events</h5>';
    $alert_count = $alert_list->size() -1;
    $alert_array = $alert_list->alerts();
    
    while($alert_count >= 0)
    {
        echo $alert_array[$alert_count]->toHtml();
        $alert_count--;
    }
}

echo '</div></div>';

?>
