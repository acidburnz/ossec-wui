<?php
/* @(#) $Id: Alert.php,v 1.4 2008/03/03 15:12:18 dcid Exp $ */

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
 * @version    $Id: Alert.php,v 1.4 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */

/**
 * 
 * 
 * @category   Ossec
 * @package    Ossec
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid, All rights reserved.
 */
class Ossec_Alert {

    var $time;
    var $id;
    var $level;
    var $user;
    var $srcip;
    var $description;
    var $location;
    var $msg;

    function toHtml( ) {

        $date    = date('Y/m/d H:i:s', $this->time);
        $id_link = '<a class="blue-text text-lighten-2" href="http://www.ossec.net/doc/search.html?q=rule-id-'.$this->id.'">'.$this->id.'</a>';
        $message = join( '</br>', $this->msg );

        $srcip = "";
        if( $this->srcip != '(none)' && $this->srcip != "") {
            $srcip = '<div><b>Src IP: </b>'.$this->srcip.'</div>';
        }

        $user = "";
        if( $this->user != '') {
            $user = "<div><b>User: </b>'.$this->user.'</div>";
        }

        if ( $this->level >= 7) {
            $icon = "warning";
            $icolor = 'orange-text';
        } else {
            $icon = "done";
            $icolor = "green-text";
        }

        $alert = '<div class="card level'.$this->level.' id'.$this->id.' srcip'.$this->srcip.'">'
                  .'<div class="card-content blue-grey darken-2 white-text">'
                  .'<span class="card-title activator"><div class="valign-wrapper activator"><i class="material-icons left valign '.$icolor.'">'.$icon.'</i><span class="valign activator">'.$date.' - '.$this->location.'</span></div></span>'
                  .'<div><b>Level: </b>'.$this->level.'</div>'
                  .'<div><b>Rule: </b>'.$id_link.'</div>'
                  .'<div><b>Description: </b>'.$this->description.'</div>'
                  .'</div>'
                  .'<div class="card-reveal blue-grey darken-2 white-text">'
                  .'<span class="card-title"><i class="material-icons left '.$icolor.'">'.$icon.'</i><span>'.$date.' - '.$this->location.'</span><i class="material-icons right">close</i></span>'  
                  .$srcip
                  .$user
                  .'<div>'.$message.'</div>'
                  .'</div></div>';

        return $alert;
    }
};

?>
