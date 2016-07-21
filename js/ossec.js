define(['ossec'], function() {
    var ossec = {
        togglesection: function(tid, did) {
            if ($(did).is(':visible')) {
                $(did).hide();
                $(tid + ' > div > i').text('add_circle');
            } else { 
                $(did).show();
                $(tid + ' > div > i').text('remove_circle');
            }
        },

        initsearch: function() {
            var options = {
                format: 'yyyy-mm-dd'
            };

            var optt = {
                format: 'HH:i'
            };

            $('#i_date_a').pickadate(options);
            $('#f_date_a').pickadate(options);
            $('#i_time_a').pickatime(optt);
            $('#f_time_a').pickatime(optt);
            $('select').material_select();
        },
        
        initsearchf: function() {
            var options = {
                format: 'yyyy-mm-dd'
            };

            var optt = {
                format: 'HH:i'
            };

            $('#i_date_a').pickadate(options);
            $('#f_date_a').pickadate(options);
            $('#i_time_a').pickatime(optt);
            $('#f_time_a').pickatime(optt);
        },

        initsyscheck: function() {
            $('select').material_select();
        },
        
        initstats: function() {
            $('select').material_select();
        },
        
        setscroll: function() {
            var options = [{
                selector: 'nav',
                offset: 400,
                callback: ossec.topbut
            }];
            
            Materialize.scrollFire(options);  
        },
        
        topbut: function() {
            if ($('#topbut').is(':hidden')){
                $('#topbut').show();    
            }
        },
        
        scrolltop: function() {
            window.scrollTo(0,0);
            $('#topbut').hide();
            setTimeout(ossec.setscroll, 500);
        },

        filtera: function(nid, type, nb) {
           if ($('#st'+nid).text() === 'Showing') {
               $('#st'+nid).text('Hidding');
               $('#sa'+nid).text('(show)');
               $('.'+type+nb).hide();
           } else {
               $('#st'+nid).text('Showing');
               $('#sa'+nid).text('(hide)');
               $('.'+type+nb).show();
           }
        },
        
        filtertable: function(filter) {
            $('#tfilter').val(filter);
            ossec.SimpleTableFilter('#tfilter');
            window.scrollTo(0,0);
        },
        
        SimpleTableFilter: function(input) {
            var val = new RegExp($(input).val(), 'i');
               $('tr').hide();
               $('tr').filter(function() {
                   return val.test($(this).text());
               }).show();
        },
        
        cleartablefilter: function() {
            $('tr').show();
        },
        
        setsearchpage: function(action) {
            $('#setpage').val(action);
            $('#dopage').submit();
        }
    };
    
    window.ossec = ossec;
    return ossec;
});
