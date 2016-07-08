<?php


/* Update the include path so that all library files can be
 * easily found.
 */
ini_set('include_path', ini_get('include_path').':'.dirname(__FILE__).'/lib');


/* Getting user argument (page) */
$USER_f = false;
if(isset($_GET['f']))
{
	$USER_f = $_GET['f'];
}
/* If nothing is set, default to the main page. */
else
{
	$USER_f = "m";
}
?>

<html>
	<head>
		<title>OSSEC Web Interface - Open Source Security</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="author" content="Daniel B. Cid - ossec.net" />
		<meta name="copyright" content="2006-2008 by Daniel B. Cid ossec.net" />
		<meta name="keywords" content="ids, ossec, hids, free software" />
		<meta name="description" content="OSSEC Web Interface" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <?php
        /* If we are in the main page, refresh the results every 90 seconds.*/
        if($USER_f == "m")
        {
            echo '<meta http-equiv="refresh" content="90" />';
        }
        ?>
        <link rel="shortcut icon" href="img/favicon.ico" />
        <script type="text/javascript"  data-main="js/main.js" src="js/require.js"></script>
        <link rel="stylesheet" href="css/materialize.min.css" type="text/css" />
	</head>
    
<body class="grey lighten-1">

<?php 
    /* Defining the error messages */
    $int_error="Internal error. Try again later.\n <br />";
    $include_error="Unable to include file:";
    
    /* Including the header */
    if(!(include("site/header.html")))
    {
        echo "$include_error 'site/header.html'.\n<br />";
        echo "$int_error<br />";
        return(1);
    }
?>

  <div id="container">


<!-- BEGIN: content -->

            <?php

            $array_lib = array("ossec_conf.php", "lib/ossec_categories.php",
                          "lib/ossec_formats.php",  
                          "lib/os_lib_handle.php",
                          "lib/os_lib_agent.php",
                          "lib/os_lib_mapping.php",
                          "lib/os_lib_stats.php",
                          "lib/os_lib_syscheck.php",
                          "lib/os_lib_firewall.php",
                          "lib/os_lib_alerts.php");

            foreach ($array_lib as $mylib)
            {

                if(!(include($mylib)))
                {
                    echo "$include_error '$mylib'.\n<br />";
                    echo "$int_error";
                    return(1);
                }
            }

            if(!os_check_config($ossec_dir, $ossec_max_alerts_per_page,
                         $ossec_search_level, $ossec_search_time,
                         $ossec_refresh_time))
            {
                echo "$int_error";
                return(1);
            }

			switch ($USER_f) 
            {
			case "s":
                if(!include("site/search.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
            case "sf":
                if(!include("site/searchfw.php"))
                {
                    echo "$int_error";
                    return(1);
                }
                break;
			case "m":
                if(!include("site/main.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "u":
                if(!include("site/user_mapping.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "t":
                if(!include("site/stats.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;
			case "a":
                if(!include("site/help.php"))
                {
                    echo "$int_error";
                    return(1);
                }
			   break;	
            case "i":
                if(!include("site/syscheck.php"))
                {
                    echo "$int_error";
                    return(1);
                }
                break;
			default:
                echo '<b class="red">Invalid argument.</b>';
                return(1);						   
			}
            
           ?>


    <!-- END: content -->
    </div>

<?php
    /* Including the footer */
    if(!(include("site/footer.html")))
    {
        echo "$include_error 'site/footer.html'.\n<br />";
        echo "$int_error";
        return(1);
    }
?>

</body>
</html>
