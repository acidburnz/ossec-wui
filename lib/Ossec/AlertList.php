<?php
/* @(#) $Id: AlertList.php,v 1.6 2008/03/03 15:12:18 dcid Exp $ */

/**
 * Ossec Framework
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @category   Ossec
 * @package    Ossec
 * @version    $Id: AlertList.php,v 1.6 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */

require_once 'Ossec/Histogram.php';

/**
 * 
 * 
 * @category   Ossec
 * @package    Ossec
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid, All rights reserved.
 */
class Ossec_AlertList {

    var $_alerts = array( );
    var $_earliest = null;
    var $_latest   = null;

    var $_id_histogram    = null;
    var $_srcip_histogram = null;
    var $_level_histogram = null;

    function Ossec_AlertList( ) {
        $this->_id_histogram    = new Ossec_Histogram();
        $this->_level_histogram = new Ossec_Histogram();
        $this->_srcip_histogram = new Ossec_Histogram();
    }

    /**
     * Return the array of alerts.
     *
     * @return array
     */
    function alerts( ) {
        return $this->_alerts;
    }

    function addAlert( $alert ) {

        $this->_id_histogram   ->count( "{$alert->id}"    );
        $this->_srcip_histogram->count( "{$alert->srcip}" );
        $this->_level_histogram->count( "{$alert->level}" );

        // If the event is older than the earliest event, update
        // the earliest event.

        if( is_null( $this->_earliest )
        || ( $alert->time < $this->_earliest->time ) ) {
            $this->_earliest = $alert;
        }

        // If the event is newer than the latest event, update
        // the latest event. In case of a tie, always update.

        if( is_null( $this->_latest )
        || ( $alert->time >= $this->_latest->time ) ) {
            $this->_latest = $alert;
        }

        $this->_alerts[] = $alert;

    }

    function earliest() {
        return $this->_alerts[0];
    }

    function latest() {
        return $this->_latest;
    }

    function size( ) {
        return count( $this->_alerts );
    }

    function toHTML( ) {

        ob_start(); ?>

        <div class="row"><div class="col s12 m4"><div id="alert_list_nav">
            <?php echo $this->_tallyNav( $this->_level_histogram, 'level', 'severity' , 'Severity breakdown' ) ?>
            <?php echo $this->_tallyNav( $this->_id_histogram   , 'id'   , 'rule'     , 'Rules breakdown'    ) ?>
            <?php echo $this->_tallyNav( $this->_srcip_histogram, 'srcip', 'Source IP', 'Src IP breakdown'   ) ?>
        </div></div>

        <div id="listcard" class="col s12 m8">
	    <?php foreach( array_reverse($this->_alerts) as $alert ): ?>
	        <?php echo $alert->toHtml( ) ?>
	    <?php endforeach; ?>
        </div>
        <?php
        
        return ob_get_clean( );

    }

/*    function _tallyNav($histogram, $key, $description, $title ) {

        // Obtain copy of histogram and sort in reverse order by value.

        $tally = $histogram->getRaw( );
        arsort( $tally ); ?>

        <div class="alert_list_nav">
            <div class="asmall toggle">
                <a href="#" title="<?php echo $title ?>" class="black bigg" style="font-weight:bold;"><?php echo $title ?></a>
                <div class="asmall details" style="display:none">
                    <?php foreach($tally as $id => $count): ?>
                        <div id="showing_<?php echo $key ?>_<?php echo $id ?>" class="asmall">
                            Showing <?php echo $count ?> alert(s) from <b><?php echo $key ?> <?php echo $id ?></b>
                            <a href="#" class="asmall hide <?php echo $key ?>_<?php echo $id ?>" title="Hide this <?php echo $key ?>">(hide)</a>
                            <a href="#" class="asmall only <?php echo $key ?>_<?php echo $id ?>" title="Show only this <?php echo $key ?>">(show only)</a>
                        </div>
                        <div id="hiding_<?php echo $key ?>_<?php echo $id ?>" class="asmall" style="display:none;">
                            Hiding <?php echo $count ?> alert(s) from <b><?php echo $key ?> <?php echo $id ?></b>
                            <a href="#" class="asmall show <?php echo $key ?>_<?php echo $id ?>" title="Hiding <?php echo $key ?>">(show)</a>
                        </div>
                    <?php endforeach; ?>
                    <a href="#" class="asmall clear <?php echo $key ?>" title="Clear <?php echo $description ?> restrictions">Clear <?php echo $key ?> restrictions</a>
                </div>
            </div>
        </div><?php

    } */

    function _tallyNav($histogram, $key, $description, $title ) {
       // Obtain copy of histogram and sort in reverse order by value.

       $tally = $histogram->getRaw( );
       arsort( $tally ); 
       $uid = uniqid();
       
       $cat = '<div id="cat%s" onclick="ossec.togglesection(\'#cat%s\',\'#catd%s\');" class="expand"><div class="valign-wrapper"><i class="material-icons valign green-text text-darken-3">add_circle</i><span class="valign blue-text text-darken-2">%s</span></div></div>';
       $catd = '<div id="catd%s" style="display:none;" class="detail">';
       $ele = '<div>%s alert(s) from <b>%s %s</b></div>';
             
       echo '<div class="alert_list_nav">';
       echo sprintf($cat, $uid, $uid, $uid, $title);
       echo sprintf($catd, $uid);

       foreach($tally as $id => $count) {
           echo sprintf($ele, $count, $key, $id, $key, $id);
       }       

       echo '</div></div>';

       
    }

};

?>
