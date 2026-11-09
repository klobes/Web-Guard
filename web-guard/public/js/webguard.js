(function(){
    'use strict';
    var T={};try{T=JSON.parse(document.getElementById('wg-i18n').textContent);}catch(e){T={};}
    function start(){
        document.querySelectorAll('[data-wg-confirm]').forEach(function(form){form.addEventListener('submit',function(e){if(!window.confirm(form.dataset.wgConfirm))e.preventDefault();});});
        document.querySelectorAll('pre[data-wg-copy]').forEach(function(pre){
            var button=document.createElement('button');button.type='button';button.className='btn btn-sm btn-outline-secondary wg-copy';button.textContent=T.copy||'Copy';
            button.addEventListener('click',function(){
                var value=pre.firstChild?pre.textContent:'';
                function done(){button.textContent=T.copied||'Copied';setTimeout(function(){button.textContent=T.copy||'Copy';},1500);}
                if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(value).then(done,function(){});return;}
                var area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();
                try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(area);
            });
            pre.parentNode.insertBefore(button,pre);
        });
        var panel=document.getElementById('wg-dashboard');if(!panel)return;
        function text(id,value){var el=document.getElementById(id);if(el)el.textContent=value==null?'—':String(value);}
        function chart(rows){
            var svg=document.getElementById('wg-chart'),ns='http://www.w3.org/2000/svg';
            while(svg.firstChild)svg.removeChild(svg.firstChild);
            function add(tag,attrs,label){var el=document.createElementNS(ns,tag);Object.keys(attrs).forEach(function(k){el.setAttribute(k,attrs[k]);});if(label!=null)el.textContent=label;svg.appendChild(el);return el;}
            var max=Math.max(1,...rows.map(function(r){return Math.max(r.requests,r.bans,r.monitor);})),width=660,height=160;
            for(var i=0;i<5;i++){var y=20+i*40;add('line',{x1:45,y1:y,x2:705,y2:y,stroke:'rgba(100,116,139,.2)'});add('text',{x:35,y:y+4,'text-anchor':'end',fill:'#728097','font-size':10},Math.round(max*(4-i)/4));}
            [['requests','#4167d5'],['bans','#1b9c5d'],['monitor','#e4a628']].forEach(function(series){var points=rows.map(function(r,index){return (45+index*width/Math.max(1,rows.length-1))+','+(180-height*r[series[0]]/max);}).join(' ');add('polyline',{points:points,fill:'none',stroke:series[1],'stroke-width':2.3,'stroke-linejoin':'round'});});
            rows.forEach(function(r,i){if(i%4===0||i===rows.length-1)add('text',{x:45+i*width/Math.max(1,rows.length-1),y:205,'text-anchor':'middle',fill:'#728097','font-size':10},r.hour);});
            if(rows.length)text('wg-chart-range',rows[0].hour+' → '+rows[rows.length-1].hour+(T.chart_note||' · Local log, port 5555'));
        }
        function render(data){
            panel.querySelectorAll('[data-wg]').forEach(function(el){el.textContent=String(data[el.dataset.wg]??'—');});
            text('wg-cpu',data.metrics.cpu_percent);text('wg-load',data.metrics.load1);text('wg-mode',data.mode);
            text('wg-f2b',data.metrics.fail2ban_online?(T.online||'Online'):(T.no_confirm||'Unconfirmed'));text('wg-queue',data.metrics.queued_events);text('wg-dropped',data.metrics.dropped_events);text('wg-agent-error',data.last_error);
            text('wg-api-success',data.metrics.api_last_success?new Date(data.metrics.api_last_success*1000).toISOString().replace('T',' ').slice(0,19):(T.no_confirm||'Unconfirmed'));
            var alert=document.getElementById('wg-live-alert');alert.className='wg-notice '+(data.online?'wg-green':'wg-red');alert.textContent=data.online?(T.agent_online||'Agent online · Last update: ')+data.last_seen:(T.agent_stale||'The agent has not sent data recently. Numbers may be stale.');chart(data.chart);
        }
        var initial=document.getElementById('wg-initial');if(initial)render(JSON.parse(initial.textContent));
        if(!panel.dataset.endpoint)return;
        var busy=false;
        setInterval(async function(){if(document.hidden||busy)return;busy=true;try{var response=await fetch(panel.dataset.endpoint,{credentials:'same-origin',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('HTTP '+response.status);render(await response.json());}catch(error){var alert=document.getElementById('wg-live-alert');alert.className='wg-notice wg-red';alert.textContent=T.refresh_failed||'The panel refresh was not confirmed. Reload the page.';}finally{busy=false;}},10000);
    }
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
