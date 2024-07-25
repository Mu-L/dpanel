"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[8022],{80821:function(K,f,e){e.d(f,{Z:function(){return M}});var v=e(5574),r=e.n(v),T=e(93246),o=e(54006),l=e(31418),U=e(86738),h=e(14726),R=e(83062),c=e(62435),g=e(86074);function M(t){var C=(0,c.useState)(!1),_=r()(C,2),u=_[0],A=_[1],j=l.Z.useApp(),i=(0,o.useIntl)(),d=function(){A(!0),t.action().then(function(a){if(A(!1),typeof t.onSuccess=="function"&&t.onSuccess(a),t.messageSuccess){var s="";typeof t.messageSuccess=="function"?s=t.messageSuccess(a):s=t.messageSuccess,s.indexOf(".")>-1&&(s=i.formatMessage({id:s})),t.asynced?(0,T.Rk)(j,s):(0,T.$h)(j,s)}}).catch(function(a){A(!1),typeof t.onError=="function"&&t.onError(a)})};return t.confirm?(0,g.jsx)(U.Z,{style:{width:500},title:"\u63D0\u793A",description:t.confirm,onConfirm:d,okText:"Yes",cancelText:"No",children:(0,g.jsx)(h.ZP,{disabled:t.disabled,icon:t.icon,loading:u,danger:t.danger,type:t.type,children:t.children})}):(0,g.jsx)(R.Z,{title:t.tips,children:(0,g.jsx)(h.ZP,{disabled:t.disabled,icon:t.icon,loading:u,onClick:d,danger:t.danger,type:t.type,children:t.children})})}},94359:function(K,f,e){e.d(f,{Z:function(){return C}});var v=e(62435),r=e(3089),T=e(98165),o=e(18429),l=e(8751),U=e(14313),h=e(30159),R=e(87740),c=e(66309),g=e(83062),M=e(54006),t=e(86074);function C(_){var u=(0,t.jsx)(t.Fragment,{});return _.status=="0"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(r.Z,{}),color:"default",children:"waiting"})),_.status=="10"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(T.Z,{spin:!0}),color:"processing",children:"processing"})),_.status=="20"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(o.Z,{}),color:"error",children:"error"})),_.status=="30"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(l.Z,{}),color:"success",children:"success"})),_.status=="running"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(U.Z,{}),color:"success",children:_.status})),_.status=="paused"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(h.Z,{}),children:_.status})),_.status=="restarting"&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(R.Z,{}),children:_.status})),(_.status=="exited"||_.status=="dead"||_.status=="removing")&&(u=(0,t.jsx)(c.Z,{icon:(0,t.jsx)(o.Z,{}),color:"warning",children:_.status})),_.link&&(u=(0,t.jsx)(M.Link,{to:_.link,children:u})),_.message&&(u=(0,t.jsx)(g.Z,{placement:_.message.placement,title:_.message.content,children:u})),(0,t.jsx)(t.Fragment,{children:u})}},96781:function(K,f,e){var v=e(62435),r=(0,v.createContext)({});f.Z=r},92922:function(K,f,e){e.r(f),e.d(f,{default:function(){return $}});var v=e(15009),r=e.n(v),T=e(99289),o=e.n(T),l=e(5574),U=e.n(l),h=e(80821),R=e(24910),c=e(14313),g=e(45605),M=e(43425),t=e(57132),C=e(90639),_=e(54006),u=e(78957),A=e(66309),j=e(96074),i=e(83062),d=e(75891),E=e(62435),a=e(96781),s=e(60335),m=e(94359),L=e(6409),n=e(86074);function $(){var Z=(0,E.useContext)(a.Z),F=Z.createYamlFormRef,B=Z.listTableRef,w=(0,E.useState)([]),S=U()(w,2),G=S[0],z=S[1];return(0,E.useEffect)(function(){(0,s.IE)({}).then(function(y){z(y.data.list)})},[]),(0,n.jsx)(C.Z,{request:function(){var y=o()(r()().mark(function I(O){var W,P,D;return r()().wrap(function(p){for(;;)switch(p.prev=p.next){case 0:return p.next=2,(0,R.pm)({title:O.title,name:O.name,pageSize:(W=O.pageSize)!==null&&W!==void 0?W:10,page:(P=O.current)!==null&&P!==void 0?P:1});case 2:return D=p.sent,p.abrupt("return",{data:D.data.list,success:!0,total:D.data.total});case 4:case"end":return p.stop()}},I)}));return function(I){return y.apply(this,arguments)}}(),rowKey:"id",columns:[{title:"\u6807\u8BC6",dataIndex:"name",width:200,render:function(I,O,W,P,D){return(0,n.jsx)(_.Link,{to:"/compose/deploy/"+O.id,children:O.name},W)}},{title:"\u540D\u79F0",dataIndex:"title",width:200},{title:"\u5BB9\u5668\u72B6\u6001",render:function(I,O,W,P,D){var x=[];return G.map(function(p){p.Names.map(function(b){b.startsWith("/"+O.name+"-")&&x.push(p)})}),x.length>0?x.map(function(p,b){return(0,n.jsx)(u.Z,{wrap:!0,children:(0,n.jsx)(A.Z,{color:p.State=="running"?"success":"warning",icon:p.State=="running"?(0,n.jsx)(c.Z,{}):(0,n.jsx)(g.Z,{}),children:p.Names[0]})},b)}):(0,n.jsx)(m.Z,{status:"0",message:{content:"\u5F85\u90E8\u7F72",placement:"top"}})}},{title:"\u64CD\u4F5C",width:100,valueType:"option",key:"option",render:function(I,O,W,P,D){return(0,n.jsxs)(u.Z,{split:(0,n.jsx)(j.Z,{type:"vertical"}),children:[(0,n.jsx)(_.Link,{to:"/compose/deploy/"+O.id,children:(0,n.jsx)(i.Z,{title:"\u7BA1\u7406",children:(0,n.jsx)(M.Z,{})})},"3"),(0,n.jsx)(_.Link,{to:"#",onClick:function(){var p;(p=F.current)===null||p===void 0||p.showCopy(O)},children:(0,n.jsx)(i.Z,{title:"\u590D\u5236",children:(0,n.jsx)(t.Z,{})})},"2")]})}}],pagination:(0,L.O)(),search:{collapsed:!1},rowSelection:{defaultSelectedRowKeys:[],alwaysShowAlert:!0},actionRef:B,tableAlertOptionRender:function(I){var O=I.selectedRowKeys;return(0,n.jsx)(u.Z,{size:16,children:(0,n.jsx)(h.Z,{danger:!0,type:"primary",action:function(){return(0,R.ik)({id:O})},onSuccess:function(){var P,D;return!((P=B.current)===null||P===void 0)&&P.reloadAndRest&&((D=B.current)===null||D===void 0||D.reloadAndRest()),!0},onError:function(){var P,D;return!((P=B.current)===null||P===void 0)&&P.reset&&((D=B.current)===null||D===void 0||D.reset()),!0},messageSuccess:"\u5220\u9664\u6210\u529F",confirm:(0,n.jsx)(u.Z,{style:{width:280},direction:"vertical",children:(0,n.jsx)(d.Z.Text,{children:"\u5220\u9664\u955C\u50CF\u540E\u65E0\u6CD5\u6062\u590D,\u786E\u8BA4\u5417\uFF1F"})}),children:"\u6279\u91CF\u5220\u9664"})})}})}},24910:function(K,f,e){e.d(f,{GG:function(){return i},Oh:function(){return _},U_:function(){return E},YZ:function(){return g},ik:function(){return t},im:function(){return U},mg:function(){return A},pm:function(){return R}});var v=e(15009),r=e.n(v),T=e(99289),o=e.n(T),l=e(54006);function U(s){return h.apply(this,arguments)}function h(){return h=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/create",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),h.apply(this,arguments)}function R(s){return c.apply(this,arguments)}function c(){return c=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/get-list",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),c.apply(this,arguments)}function g(s){return M.apply(this,arguments)}function M(){return M=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/get-detail",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),M.apply(this,arguments)}function t(s){return C.apply(this,arguments)}function C(){return C=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/delete",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),C.apply(this,arguments)}function _(s){return u.apply(this,arguments)}function u(){return u=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/container-deploy",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),u.apply(this,arguments)}function A(s){return j.apply(this,arguments)}function j(){return j=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/container-destroy",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),j.apply(this,arguments)}function i(s){return d.apply(this,arguments)}function d(){return d=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/container-ctrl",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),d.apply(this,arguments)}function E(s){return a.apply(this,arguments)}function a(){return a=o()(r()().mark(function s(m){return r()().wrap(function(n){for(;;)switch(n.prev=n.next){case 0:return n.abrupt("return",(0,l.request)("/api/app/compose/container-process-kill",{method:"POST",data:m}));case 1:case"end":return n.stop()}},s)})),a.apply(this,arguments)}},60335:function(K,f,e){e.d(f,{IE:function(){return R},IW:function(){return U},KK:function(){return _},LJ:function(){return A},eE:function(){return t},jV:function(){return g}});var v=e(15009),r=e.n(v),T=e(99289),o=e.n(T),l=e(54006);function U(i){return h.apply(this,arguments)}function h(){return h=o()(r()().mark(function i(d){return r()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,l.request)("/api/app/container/status",{method:"POST",data:d}));case 1:case"end":return a.stop()}},i)})),h.apply(this,arguments)}function R(i){return c.apply(this,arguments)}function c(){return c=o()(r()().mark(function i(d){return r()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,l.request)("/api/app/container/get-list",{data:d,method:"POST"}));case 1:case"end":return a.stop()}},i)})),c.apply(this,arguments)}function g(i){return M.apply(this,arguments)}function M(){return M=o()(r()().mark(function i(d){return r()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,l.request)("/api/app/container/get-detail",{data:d,method:"POST"}));case 1:case"end":return a.stop()}},i)})),M.apply(this,arguments)}function t(i){return C.apply(this,arguments)}function C(){return C=o()(r()().mark(function i(d){return r()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,l.request)("/api/app/container/update",{data:d,method:"POST"}));case 1:case"end":return a.stop()}},i)})),C.apply(this,arguments)}function _(){return u.apply(this,arguments)}function u(){return u=o()(r()().mark(function i(){return r()().wrap(function(E){for(;;)switch(E.prev=E.next){case 0:return E.abrupt("return",(0,l.request)("/api/app/container/prune",{method:"POST"}));case 1:case"end":return E.stop()}},i)})),u.apply(this,arguments)}function A(i){return j.apply(this,arguments)}function j(){return j=o()(r()().mark(function i(d){return r()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,l.request)("/api/app/container/export",{method:"POST",data:d,responseType:"blob"}));case 1:case"end":return a.stop()}},i)})),j.apply(this,arguments)}},6409:function(K,f,e){e.d(f,{O:function(){return v}});function v(){return{showSizeChanger:!0,defaultPageSize:20}}}}]);