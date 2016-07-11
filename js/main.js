// scripts loaders
requirejs.config({
	baseUrl: "js/",
	paths: {
            "jquery": "jquery.min",
            "mustache": "mustache.min",
            "materialize": "materialize.min",
    	},
	shim : {
            'materialize': { deps: ['jquery'] },
            'ossec': { deps: ['materialize']}
	}
});

require(["jquery", "materialize", "mustache", "ossec"], function($, Materialise, Mustache, ossec) {
    $(document).ready(function() {
        "use strict";
        console.log("Ready Fire !!");
        
        ossec.setscroll();
        
        if (window.location.search === "?f=i") {
            ossec.initsyscheck();
        } else if (window.location.search === "?f=s") {
            ossec.initsearch();
        } else if (window.location.search === "?f=t") {
            ossec.initstats();
        }
        
    });
});
