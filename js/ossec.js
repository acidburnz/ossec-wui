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
            var options = {
                format: "yyyy-mm-dd",
                onSet: ossec.addtime
            };
            $('#i_date_a').pickadate(options);
            $('#f_date_a').pickadate(options);
            $('select').material_select();
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

        addtime: function(context) {
            curs = $(this.$node).val();
            $(this.$node).val(curs + " 00:00");
        }
    };
    
    window.ossec = ossec;
    return ossec;
})
