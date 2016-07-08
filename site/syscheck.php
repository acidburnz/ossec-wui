<?php
/* @(#) $Id: syscheck.php,v 1.6 2008/03/03 19:37:26 dcid Exp $ */

/* Copyright (C) 2006-2013 Trend Micro
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       

/* Initializing variables */
$u_agent = "ossec-server";
$u_file = "";
$USER_agent = NULL;
$USER_file = NULL;


/* Getting user patterns */
$strpattern = "/^[0-9a-zA-Z.:_^ -]{1,128}$/";
if(isset($_POST['agentpattern']))
{
    if(preg_match($strpattern, $_POST['agentpattern']) == true)
    {
        $USER_agent = $_POST['agentpattern'];
        $u_agent = $USER_agent;
    }
}
if(isset($_POST['filepattern']))
{
    if(preg_match($strpattern, $_POST['filepattern']) == true)
    {
        $USER_file = $_POST['filepattern'];
        $u_file = $USER_file;
    }
}      


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


/* Getting syscheck information */
$syscheck_list = os_getsyscheck($ossec_handle);

/* Creating form */
echo '<div class="row">';
echo '<form name="dosearch" method="post" action="index.php?f=i">'
    . '<div class="input-field col s3 blue-text text-darken-2">'
    . '<select name="agentpattern">';

$option = '<option value="%s" %s>%s</option>';

foreach($syscheck_list as $agent => $agent_name)
{
    $sl = "";
    if($agent == "global_list")
    {
        continue;
    }
    else if($u_agent == $agent)
    {
        $sl = ' selected="selected"';
    }
    echo sprintf($option, $agent, $sl, $agent);
}

echo '</select><label>Agent Name</label></div>';

echo '<div class="col s4"><input type="submit" name="ss" value="Dump database" class="btn"/>';
echo '</div></form></div>';

/* Dumping database */
if( array_key_exists( 'ss', $_POST ) ) {
    if(($_POST['ss'] == "Dump database") && ($USER_agent != NULL))
    {
        os_syscheck_dumpdb($ossec_handle, $USER_agent);
        return(1);
    }
}

/* Last modified files */
if(($syscheck_list == NULL) || ($syscheck_list{'global_list'} == NULL))
{
    echo '<h5>
        No integrity checking information available.<br />
        Nothing reported as changed.
        </h5>
      ';
}
else
{

   echo '<div class="row"><div class="col s12">';
   echo '<h5 class="topt">Latest modified files (for all agents): </h5>';
   
   $sysfiles = '<div id="file%s" onclick="ossec.togglesection(\'#file%s\',\'#filed%s\');" class="blue-text text-darken-2"><i class="material-icons">add</i>%s</div>';
   $sysfilesd = '<div id="filed%s" style="display:none;" class="detail"><b>File:</b> %s</br><b>Agent:</b> %s</br><b>Modification time:</b> %s</div>';
   
   if(isset($syscheck_list{'global_list'}) && 
      isset($syscheck_list{'global_list'}{'files'}))
   {
       $last_mod_date = "";
       $sk_count = 0;
       
       foreach($syscheck_list{'global_list'}{'files'} as $syscheck)
       {
           $sk_count++;
           
           # Initing file name
           $ffile_name = "";
           $ffile_name2 = "";
           
           if(strlen($syscheck[2]) > 90)
           {
               $ffile_name = substr($syscheck[2], 0, 95)."..";
               $ffile_name2 = substr($syscheck[2], 96, 160);
           }
           else
           {
               $ffile_name = $syscheck[2];
           }
           
           /* Setting the date */
           if($last_mod_date != date('Y M d', $syscheck[0]))
           {
               $last_mod_date = date('Y M d', $syscheck[0]);
               echo "<b>$last_mod_date</b>";
           }
           
           echo sprintf($sysfiles, $sk_count, $sk_count, $sk_count, $ffile_name);
           echo sprintf($sysfilesd, $sk_count, $ffile_name, $syscheck[1], date('Y M d H:i:s', $syscheck[0]));
       }
   }
}


echo "</div></div>";


?>
