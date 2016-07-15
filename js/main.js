// scripts loaders
requirejs.config({
	baseUrl: "js/",
	paths: {
            "jquery": "jquery.min",
            "materialize": "materialize.min",
    	},
	shim : {
            'materialize': { deps: ['jquery'] },
            'ossec': { deps: ['materialize']}
	}
});

require(["jquery", "materialize", "ossec"], function($, Materialise, ossec) {
    $(document).ready(function() {
        "use strict";
        console.log("Ready Fire !!");
        
        ossec.setscroll();
        $(".button-collapse").sideNav();
        
        if (window.location.search === "?f=i") {
            ossec.initsyscheck();
        } else if (window.location.search === "?f=s") {
            ossec.initsearch();
        } else if (window.location.search === "?f=t") {
            ossec.initstats();
        } else if (window.location.search === "?f=sf") {
            ossec.initsearchf();
        }
        
    });
});
