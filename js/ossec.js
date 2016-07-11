define(["ossec"], function() {
    var ossec = {
        togglesection: function(tid, did) {
            if ($(did).is(":visible")) {
                $(did).hide();
                $(tid + " > div > i").text("add_circle");
            } else { 
                $(did).show();
                $(tid + " > div > i").text("remove_circle");
            }

        },

        initsearch: function() {
            $('#i_date_a').pickadate({format: "yyyy-mm-dd"});
            $('#f_date_a').pickadate({format: "yyyy-mm-dd"});
            $('select').material_select();

            if ($("#alert_list_nav").length !== 0) {
                 ossec.initadvsearch();
            }
        },

        initsyscheck: function() {
            $('select').material_select();
        },
        
        initstats: function() {
            $('select').material_select();
        },
        
        setscroll: function() {
            var options = [{
                selector: '.nav-wrapper',
                offset: 200,
                callback: ossec.topbut
            }];

            Materialize.scrollFire(options);  
        },
        
        topbut: function() {
            if ($("#topbut").is(":hidden")){
                $("#topbut").show();    
            }
        },
        
        scrolltop: function() {
            window.scrollTo(0,0);
            $("#topbut").hide();
            ossec.setscroll();
        },

        initadvsearch: function() {
           console.log("adv init");
           
        }
    };
    
    window.ossec = ossec;
    return ossec;
})
