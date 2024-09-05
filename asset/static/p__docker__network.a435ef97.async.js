"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[236],{80821:function(X,D,r){r.d(D,{Z:function(){return m}});var T=r(5574),d=r.n(T),S=r(93246),g=r(54006),b=r(31418),B=r(86738),E=r(14726),O=r(83062),$=r(67294),y=r(85893);function m(o){var M=(0,$.useState)(!1),w=d()(M,2),A=w[0],R=w[1],V=b.Z.useApp(),W=(0,g.useIntl)(),P=function(){R(!0),o.action().then(function(x){if(R(!1),typeof o.onSuccess=="function"&&o.onSuccess(x),o.messageSuccess){var l="";typeof o.messageSuccess=="function"?l=o.messageSuccess(x):l=o.messageSuccess,l.indexOf(".")>-1&&(l=W.formatMessage({id:l})),o.asynced?(0,S.Rk)(V,l):(0,S.$h)(V,l)}}).catch(function(x){R(!1),typeof o.onError=="function"&&o.onError(x)})};return o.confirm?(0,y.jsx)(B.Z,{style:{width:500},title:"\u63D0\u793A",description:o.confirm,onConfirm:P,okText:"Yes",cancelText:"No",children:(0,y.jsx)(E.ZP,{disabled:o.disabled,icon:o.icon,loading:A,danger:o.danger,type:o.type,children:o.children})}):(0,y.jsx)(O.Z,{title:o.tips,children:(0,y.jsx)(E.ZP,{disabled:o.disabled,icon:o.icon,loading:A,onClick:P,danger:o.danger,type:o.type,children:o.children})})}},51672:function(X,D,r){r.r(D),r.d(D,{default:function(){return ce}});var T=r(15009),d=r.n(T),S=r(99289),g=r.n(S),b=r(5574),B=r.n(b),E=r(80821),O=r(14946),$=r(93246),y=r(184),m=r(5966),o=r(62370),M=r(97462),w=r(52688),A=r(24739),R=r(17186),V=r(31418),W=r(14726),P=r(34041),K=r(71230),x=r(15746),l=r(67294),e=r(85893),p=(0,l.forwardRef)(function(j,J){var k=(0,l.useState)(!1),_=B()(k,2),z=_[0],Q=_[1],Y=V.Z.useApp(),n=(0,l.useRef)();return(0,l.useImperativeHandle)(J,function(){return{}}),(0,e.jsxs)(y.a,{name:"create",title:"\u521B\u5EFA\u7F51\u7EDC",open:z,onOpenChange:function(I){Q(I)},formRef:n,trigger:(0,e.jsx)(W.ZP,{type:"primary",children:"\u521B\u5EFA\u7F51\u7EDC"}),onFinish:function(){var N=g()(d()().mark(function I(u){var C,U,i,s,t,f,h,c,Z,F,H,q;return d()().wrap(function(L){for(;;)switch(L.prev=L.next){case 0:return u.driver=="macvlan"&&(u.driverOptionName||(u.driverOptionName=[],u.driverOptionValue=[]),u.driverOptionName.push("parent"),u.driverOptionValue.push(u.macvlanParentCard)),L.next=3,(0,O.XY)({name:u.name,driver:(C=u.driver)!==null&&C!==void 0?C:"bridge",ipSubnet:(U=u.ipSubnet)!==null&&U!==void 0?U:"",ipGateway:(i=u.ipGateway)!==null&&i!==void 0?i:"",ipRange:(s=u.ipRange)!==null&&s!==void 0?s:"",ipAux:u.ipAux,enableIpV6:(t=u.enableIpV6)!==null&&t!==void 0?t:!1,ipV6Subnet:(f=u.ipV6Subnet)!==null&&f!==void 0?f:"",ipV6Gateway:(h=u.ipV6Gateway)!==null&&h!==void 0?h:"",ipV6Range:(c=u.ipV6Range)!==null&&c!==void 0?c:"",ipV6Aux:u.ipV6Aux,driverOption:u.driverOption,internal:(Z=u.internal)!==null&&Z!==void 0?Z:!1,attachable:(F=u.attachable)!==null&&F!==void 0?F:!1});case 3:if(H=L.sent,!(H&&H.data&&H.data.id!="")){L.next=9;break}return(0,$.$h)(Y,"\u521B\u5EFA\u7F51\u7EDC\u6210\u529F"),j.onFinish&&j.onFinish(),(q=n.current)===null||q===void 0||q.resetFields(),L.abrupt("return",!0);case 9:case"end":return L.stop()}},I)}));return function(I){return N.apply(this,arguments)}}(),children:[(0,e.jsx)(m.Z,{label:"\u540D\u79F0",tooltip:"\u4E0D\u914D\u7F6E\u5B50\u7F51\u65F6\uFF0C\u4F1A\u81EA\u52A8\u751F\u6210",name:"name",required:!0,rules:[{required:!0}],placeholder:"\u6307\u5B9A\u552F\u4E00\u7684\u7F51\u7EDC\u540D\u79F0"}),(0,e.jsx)(o.Z,{label:"\u7C7B\u578B",name:"driver",children:(0,e.jsxs)(P.Z,{defaultValue:"bridge",children:[(0,e.jsx)(P.Z.Option,{value:"bridge",children:"bridge"}),(0,e.jsx)(P.Z.Option,{value:"ipvlan",children:"ipvlan"}),(0,e.jsx)(P.Z.Option,{value:"macvlan",children:"macvlan"}),(0,e.jsx)(P.Z.Option,{value:"overlay",children:"overlay"})]})}),(0,e.jsx)(M.Z,{name:["driver"],children:function(I){var u=I.driver;if(u=="macvlan")return(0,e.jsx)(m.Z,{label:"\u7236\u7F51\u5361",name:"macvlanParentCard"})}}),(0,e.jsxs)(K.Z,{children:[(0,e.jsx)(x.Z,{span:8,children:(0,e.jsx)(w.Z,{label:"\u81EA\u5B9AIPV4\u5B50\u7F51",name:"userIpV4Subnet"})}),(0,e.jsx)(x.Z,{span:8,children:(0,e.jsx)(w.Z,{name:"internal",label:"\u9694\u79BB\u5916\u90E8\u8BBF\u95EE",initialValue:!1})}),(0,e.jsx)(x.Z,{span:8,children:(0,e.jsx)(w.Z,{name:"attachable",label:"\u5141\u8BB8\u624B\u52A8\u9644\u52A0\u5BB9\u5668",initialValue:!1})})]}),(0,e.jsx)(M.Z,{name:["userIpV4Subnet"],children:function(I){var u=I.userIpV4Subnet;if(u)return(0,e.jsxs)(e.Fragment,{children:[(0,e.jsxs)(A.UW,{title:"IPV4\u914D\u7F6E",children:[(0,e.jsx)(m.Z,{label:"\u5B50\u7F51",name:"ipSubnet",width:"md",placeholder:"\u4F8B\u5982: 172.20.0.0/16"}),(0,e.jsx)(m.Z,{label:"\u7F51\u5173",name:"ipGateway",width:"md",placeholder:"\u4F8B\u5982: 172.20.10.11"}),(0,e.jsx)(m.Z,{label:"Ip\u8303\u56F4",name:"ipRange",width:"md",placeholder:"\u4F8B\u5982: 172.20.10.128/25"})]}),(0,e.jsx)(R.u,{name:"ipAux",label:"\u6392\u9664Ip",children:(0,e.jsxs)(A.UW,{children:[(0,e.jsx)(m.Z,{label:"\u8BBE\u5907\u540D\u79F0",name:"ipAuxDevice",width:"md"}),(0,e.jsx)(m.Z,{label:"Ip\u5730\u5740",name:"ipAuxAddress",width:"md"})]})})]})}}),(0,e.jsxs)(K.Z,{children:[(0,e.jsx)(x.Z,{span:8,children:(0,e.jsx)(w.Z,{label:"\u542F\u7528IPV6",name:"enableIpV6"})}),(0,e.jsx)(x.Z,{children:(0,e.jsx)(w.Z,{label:"\u81EA\u5B9AIPV6\u5B50\u7F51",name:"userIpV6Subnet",fieldProps:{onChange:function(I,u){if(I){var C;(C=n.current)===null||C===void 0||C.setFieldValue("enableIpV6",!0)}}}})})]}),(0,e.jsx)(M.Z,{name:["userIpV6Subnet"],children:function(I){var u=I.userIpV6Subnet;if(u)return(0,e.jsxs)(e.Fragment,{children:[(0,e.jsxs)(A.UW,{title:"IPV6\u914D\u7F6E",children:[(0,e.jsx)(m.Z,{label:"\u5B50\u7F51",name:"ipV6Subnet",width:"md",placeholder:"\u4F8B\u5982: 2001:db8::/48"}),(0,e.jsx)(m.Z,{label:"\u7F51\u5173",name:"ipV6Gateway",width:"md",placeholder:"\u4F8B\u5982: 2001:db8::1"}),(0,e.jsx)(m.Z,{label:"Ip\u8303\u56F4",name:"ipV6Range",width:"md",placeholder:"\u4F8B\u5982: 2001:db8::/64"})]}),(0,e.jsx)(R.u,{name:"ipV6Aux",label:"\u6392\u9664Ip",children:(0,e.jsxs)(A.UW,{children:[(0,e.jsx)(m.Z,{label:"\u8BBE\u5907\u540D\u79F0",name:"ipAuxDevice",width:"md"}),(0,e.jsx)(m.Z,{label:"Ip\u5730\u5740",name:"ipAuxAddress",width:"md"})]})})]})}}),(0,e.jsx)(R.u,{name:"driverOption",label:"\u81EA\u5B9A\u4E49\u9A71\u52A8\u914D\u7F6E",children:(0,e.jsxs)(A.UW,{children:[(0,e.jsx)(m.Z,{label:"\u540D\u79F0",name:"driverOptionName",width:"md"}),(0,e.jsx)(m.Z,{label:"\u503C",name:"driverOptionValue",width:"md"})]})})]})}),a=p,re=r(6409),te=r(43425),ae=r(48689),le=r(6110),ue=r(88717),ee=r(38345),ie=r(66309),G=r(78957),ne=r(96074),se=r(83062),v=r(26412),de=r(63490),oe=r(39711);function ce(){var j=(0,l.useRef)(),J=(0,l.useState)(""),k=B()(J,2),_=k[0],z=k[1],Q=(0,l.useState)(),Y=B()(Q,2),n=Y[0],N=Y[1],I=(0,l.useState)(),u=B()(I,2),C=u[0],U=u[1];return(0,e.jsxs)(le._z,{header:{extra:[(0,e.jsx)(a,{onFinish:function(){var s,t;!((s=j.current)===null||s===void 0)&&s.reloadAndRest&&((t=j.current)===null||t===void 0||t.reloadAndRest())}}),(0,e.jsx)(E.Z,{action:function(){return(0,O.CI)()},onSuccess:function(){var s,t;return!((s=j.current)===null||s===void 0)&&s.reloadAndRest&&((t=j.current)===null||t===void 0||t.reloadAndRest()),!0},onError:function(){var s,t;return!((s=j.current)===null||s===void 0)&&s.reset&&((t=j.current)===null||t===void 0||t.reset()),!0},messageSuccess:"\u6E05\u9664\u6210\u529F",confirm:"\u662F\u5426\u6E05\u7406\u672A\u4F7F\u7528\u7684\u7F51\u7EDC\uFF1F",children:"\u6E05\u7406\u672A\u4F7F\u7528\u7F51\u7EDC"})]},children:[(0,e.jsx)(ue.Z,{scroll:{x:"max-content"},rowKey:"Name",columns:[{title:"\u540D\u79F0",ellipsis:!0,dataIndex:"Name",render:function(s,t,f,h,c){return t.Name=="none"||t.Name=="bridge"||t.Name=="host"?(0,e.jsxs)(e.Fragment,{children:[t.Name," ",(0,e.jsx)(ie.Z,{color:"blue",children:"System"})]}):(0,e.jsx)(e.Fragment,{children:s})}},{title:"\u7C7B\u578B",ellipsis:!0,width:80,dataIndex:"Driver",search:!1},{title:"IPAM Driver",ellipsis:!0,width:120,search:!1,dataIndex:["IPAM","Driver"]},{title:"IPV4",ellipsis:!0,width:150,search:!1,render:function(s,t,f,h,c){return t.IPAM.Config&&t.IPAM.Config[0]?(0,e.jsxs)(G.Z,{direction:"vertical",children:[(0,e.jsx)("div",{children:t.IPAM.Config&&t.IPAM.Config[0].Subnet}),(0,e.jsx)("div",{children:t.IPAM.Config&&t.IPAM.Config[0].Gateway})]}):"-"}},{title:"IPV6",ellipsis:!0,width:150,search:!1,render:function(s,t,f,h,c){return t.IPAM.Config&&t.IPAM.Config[1]?(0,e.jsxs)(G.Z,{direction:"vertical",children:[(0,e.jsx)("div",{children:t.IPAM.Config&&t.IPAM.Config[1].Subnet}),(0,e.jsx)("div",{children:t.IPAM.Config&&t.IPAM.Config[1].Gateway})]}):"-"}},{title:"\u521B\u5EFA\u65F6\u95F4",ellipsis:!0,width:180,search:!1,dataIndex:"Created",render:function(s,t,f,h,c){return new Date(t.Created).toLocaleString()}},{title:"\u64CD\u4F5C",width:100,search:!1,render:function(s,t,f,h,c){return(0,e.jsx)(G.Z,{split:(0,e.jsx)(ne.Z,{type:"vertical"}),children:(0,e.jsx)(W.ZP,{type:"link",onClick:function(){z(t.Name)},children:(0,e.jsx)(se.Z,{title:"\u7BA1\u7406",children:(0,e.jsx)(te.Z,{})})})})}}],request:function(){var i=g()(d()().mark(function s(t,f,h){var c;return d()().wrap(function(F){for(;;)switch(F.prev=F.next){case 0:return F.next=2,(0,O.jR)({name:t.Name});case 2:return c=F.sent,F.abrupt("return",{data:c.data.list,success:!0,total:c.data.list.length});case 4:case"end":return F.stop()}},s)}));return function(s,t,f){return i.apply(this,arguments)}}(),rowSelection:{defaultSelectedRowKeys:[],alwaysShowAlert:!0},actionRef:j,tableAlertOptionRender:function(s){var t=s.selectedRowKeys;return(0,e.jsx)(G.Z,{size:16,children:(0,e.jsx)(E.Z,{danger:!0,type:"primary",action:function(){return(0,O._x)({name:t})},onSuccess:function(){var h,c;return!((h=j.current)===null||h===void 0)&&h.reloadAndRest&&((c=j.current)===null||c===void 0||c.reloadAndRest()),!0},onError:function(){var h,c;return!((h=j.current)===null||h===void 0)&&h.reset&&((c=j.current)===null||c===void 0||c.reset()),!0},messageSuccess:"\u5220\u9664\u6210\u529F",children:"\u6279\u91CF\u5220\u9664"})})},pagination:(0,re.O)()}),(0,e.jsxs)(y.a,{title:"\u7F51\u7EDC\u8BE6\u60C5",open:_!="",onOpenChange:function(s){s?_&&(0,O.IS)({name:_}).then(function(t){if(t.data.info.Containers){var f=[];Object.keys(t.data.info.Containers).map(function(h){t.data.info.Containers[h].Id=h,f.push(t.data.info.Containers[h])}),U(f)}else U([]);N(t.data.info)}):z("")},submitter:!1,children:[(0,e.jsx)(ee.Z,{ghost:!0,children:(0,e.jsxs)(v.Z,{labelStyle:{width:"180px"},column:1,bordered:!0,children:[(0,e.jsx)(v.Z.Item,{label:"\u540D\u79F0",children:n==null?void 0:n.Name}),(0,e.jsx)(v.Z.Item,{label:"Id",children:n==null?void 0:n.Id}),(0,e.jsx)(v.Z.Item,{label:"Driver",children:n==null?void 0:n.Driver}),(0,e.jsx)(v.Z.Item,{label:"Scope",children:n==null?void 0:n.Scope}),(0,e.jsx)(v.Z.Item,{label:"Attachable",children:n!=null&&n.Attachable?"\u662F":"\u5426"}),(0,e.jsx)(v.Z.Item,{label:"Internal",children:n!=null&&n.Internal?"\u662F":"\u5426"}),(n==null?void 0:n.IPAM.Config)&&(n==null?void 0:n.IPAM.Config[0])&&(0,e.jsx)(v.Z.Item,{label:"IPV4",children:(0,e.jsxs)(v.Z,{labelStyle:{width:"150px"},column:1,bordered:!0,children:[(0,e.jsx)(v.Z.Item,{label:"Subnet",children:n==null?void 0:n.IPAM.Config[0].Subnet}),(0,e.jsx)(v.Z.Item,{label:"Gateway",children:n==null?void 0:n.IPAM.Config[0].Gateway}),(0,e.jsx)(v.Z.Item,{label:"IP Range ",children:n==null?void 0:n.IPAM.Config[0].IPRange}),(0,e.jsx)(v.Z.Item,{label:"Excluded IPs",children:(n==null?void 0:n.IPAM.Config[0].AuxiliaryAddresses)&&Object.keys(n==null?void 0:n.IPAM.Config[0].AuxiliaryAddresses).map(function(i){return(n==null?void 0:n.IPAM.Config[0].AuxiliaryAddresses[i])+" ,"})})]})}),(n==null?void 0:n.IPAM.Config)&&(n==null?void 0:n.IPAM.Config[1])&&(0,e.jsx)(v.Z.Item,{label:"IPV6",children:(0,e.jsxs)(v.Z,{labelStyle:{width:"150px"},column:1,bordered:!0,children:[(0,e.jsx)(v.Z.Item,{label:"Subnet",children:n==null?void 0:n.IPAM.Config[1].Subnet}),(0,e.jsx)(v.Z.Item,{label:"Gateway",children:n==null?void 0:n.IPAM.Config[1].Gateway}),(0,e.jsx)(v.Z.Item,{label:"IP Range ",children:n==null?void 0:n.IPAM.Config[1].IPRange}),(0,e.jsx)(v.Z.Item,{label:"Excluded IPs",children:(n==null?void 0:n.IPAM.Config[1].AuxiliaryAddresses)&&Object.keys(n==null?void 0:n.IPAM.Config[1].AuxiliaryAddresses).map(function(i){return(n==null?void 0:n.IPAM.Config[1].AuxiliaryAddresses[i])+" ,"})})]})}),(n==null?void 0:n.Options)&&Object.keys(n==null?void 0:n.Options).length>0&&(0,e.jsx)(v.Z.Item,{label:"Options",children:(0,e.jsx)(v.Z,{labelStyle:{width:"150px"},column:1,bordered:!0,children:Object.keys(n==null?void 0:n.Options).map(function(i){return(0,e.jsx)(v.Z.Item,{label:i,children:n.Options[i]},i)})})}),(n==null?void 0:n.Labels)&&Object.keys(n==null?void 0:n.Labels).length>0&&(0,e.jsx)(v.Z.Item,{label:"Lables",children:(0,e.jsx)(v.Z,{labelStyle:{width:"150px"},column:1,bordered:!0,children:Object.keys(n==null?void 0:n.Labels).map(function(i){return(0,e.jsx)(v.Z.Item,{label:i,children:n.Labels[i]},i)})})})]})}),(0,e.jsx)(ee.Z,{title:"\u7F51\u7EDC\u5185\u5BB9\u5668",ghost:!0,children:(0,e.jsx)(de.Z,{rowKey:"Id",columns:[{title:"\u5BB9\u5668\u540D\u79F0",dataIndex:"Name",render:function(s,t,f){return(0,e.jsx)(oe.rU,{target:"_blank",to:"/app/detail/edit/".concat(t.Id),children:t.Name})}},{title:"IPV4",dataIndex:"IPv4Address"},{title:"IPV6",dataIndex:"IPv6Address"},{title:"MacAddress",dataIndex:"MacAddress"},{title:"\u64CD\u4F5C",render:function(s,t,f){return(0,e.jsx)(G.Z,{split:(0,e.jsx)(ne.Z,{type:"vertical"}),children:(0,e.jsx)(E.Z,{type:"text",action:function(){var c,Z;return(0,O.t9)({name:(c=n==null?void 0:n.Id)!==null&&c!==void 0?c:"",containerName:(Z=t.Id)!==null&&Z!==void 0?Z:""})},messageSuccess:"\u5BB9\u5668\u6210\u529F\u9000\u51FA\u8BE5\u7F51\u7EDC",onSuccess:function(){var c=C==null?void 0:C.filter(function(Z){return Z.Id!=t.Id});U(c)},children:(0,e.jsx)(ae.Z,{})},"delete")})}}],dataSource:C,pagination:!1})})]})]})}},14946:function(X,D,r){r.d(D,{CI:function(){return y},HY:function(){return W},IS:function(){return B},XY:function(){return w},_3:function(){return K},_x:function(){return o},jR:function(){return O},t9:function(){return R}});var T=r(15009),d=r.n(T),S=r(99289),g=r.n(S),b=r(54006);function B(l){return E.apply(this,arguments)}function E(){return E=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,b.request)("/api/app/network/get-detail",{method:"POST",data:e}));case 1:case"end":return a.stop()}},l)})),E.apply(this,arguments)}function O(l){return $.apply(this,arguments)}function $(){return $=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,b.request)("/api/app/network/get-list",{method:"POST",data:e}));case 1:case"end":return a.stop()}},l)})),$.apply(this,arguments)}function y(){return m.apply(this,arguments)}function m(){return m=g()(d()().mark(function l(){return d()().wrap(function(p){for(;;)switch(p.prev=p.next){case 0:return p.next=2,(0,b.request)("/api/app/network/prune",{method:"POST"});case 2:return p.abrupt("return",p.sent);case 3:case"end":return p.stop()}},l)})),m.apply(this,arguments)}function o(l){return M.apply(this,arguments)}function M(){return M=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,(0,b.request)("/api/app/network/delete",{method:"POST",data:e});case 2:return a.abrupt("return",a.sent);case 3:case"end":return a.stop()}},l)})),M.apply(this,arguments)}function w(l){return A.apply(this,arguments)}function A(){return A=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,(0,b.request)("/api/app/network/create",{method:"POST",data:e});case 2:return a.abrupt("return",a.sent);case 3:case"end":return a.stop()}},l)})),A.apply(this,arguments)}function R(l){return V.apply(this,arguments)}function V(){return V=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,(0,b.request)("/api/app/network/disconnect",{method:"POST",data:e});case 2:return a.abrupt("return",a.sent);case 3:case"end":return a.stop()}},l)})),V.apply(this,arguments)}function W(l){return P.apply(this,arguments)}function P(){return P=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,(0,b.request)("/api/app/network/connect",{method:"POST",data:e});case 2:return a.abrupt("return",a.sent);case 3:case"end":return a.stop()}},l)})),P.apply(this,arguments)}function K(l){return x.apply(this,arguments)}function x(){return x=g()(d()().mark(function l(e){return d()().wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",(0,b.request)("/api/app/network/get-container-list",{method:"POST",data:e}));case 1:case"end":return a.stop()}},l)})),x.apply(this,arguments)}},6409:function(X,D,r){r.d(D,{O:function(){return T}});function T(){var d,S=parseInt((d=localStorage.getItem("dpanel-pagesize"))!==null&&d!==void 0?d:"0");return{showSizeChanger:!0,defaultPageSize:S!=null?S:20}}}}]);