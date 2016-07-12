<?php
/* @(#) $Id: help.php,v 1.10 2008/03/04 14:26:41 dcid Exp $ */

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
?>

<div class="row"><div class="col s12">
<h5 class="topt">About</h5>
OSWUI is a an open source web interface for the <a href="http://www.ossec.net">OSSEC-HIDS</a> project.</br>
For details on how to install, configure or use it, please take a look at <a href="http://www.ossec.net/wiki/index.php/OSSECWUI:Install">http://www.ossec.net/wiki/index.php/OSSECWUI:Install</a>.</br>
If you have any problems or questions, please use one of the free support options available at <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.</br>
For information regarding commercial support, please visit <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.</br>
</div></div>

<div class="row"><div class="col s12">
<h5 class="topt">Development team</h5>
<ul>
    <li><b>Daniel Cid</b> - dcid ( at ) dcid.me</li>
    <li><b>Chris Abernethy</b> - chris.abernethy (at) ossec.net</li>
    <li><b>Vic Hargrave</b> - ossec ( at )  vichargrave.com</li>
</ul>
</div></div>

<div class="row"><div class="col s12">
<h5 class="topt">License</h5>
Copyright &copy; 2006 - 2016 <a href="http://www.trendmicro.com">Trend Micro</a>.  All rights reserved.</br>
OSSEC WEB UI (ossec-wui) is a free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (version 2) as published by the FSF - Free Software Foundation.</br>
OSSEC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
</div></div>
