"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[1180],{88484:function(X,T,e){e.d(T,{Z:function(){return p}});var E=e(87462),d=e(67294),D={icon:{tag:"svg",attrs:{viewBox:"64 64 896 896",focusable:"false"},children:[{tag:"path",attrs:{d:"M400 317.7h73.9V656c0 4.4 3.6 8 8 8h60c4.4 0 8-3.6 8-8V317.7H624c6.7 0 10.4-7.7 6.3-12.9L518.3 163a8 8 0 00-12.6 0l-112 141.7c-4.1 5.3-.4 13 6.3 13zM878 626h-60c-4.4 0-8 3.6-8 8v154H214V634c0-4.4-3.6-8-8-8h-60c-4.4 0-8 3.6-8 8v198c0 17.7 14.3 32 32 32h684c17.7 0 32-14.3 32-32V634c0-4.4-3.6-8-8-8z"}}]},name:"upload",theme:"outlined"},M=D,S=e(84089),A=function(t,R){return d.createElement(S.Z,(0,E.Z)({},t,{ref:R,icon:M}))},g=d.forwardRef(A),p=g},52688:function(X,T,e){var E=e(1413),d=e(45987),D=e(67294),M=e(44756),S=e(85893),A=["fieldProps","unCheckedChildren","checkedChildren","proFieldProps"],g=D.forwardRef(function(p,m){var t=p.fieldProps,R=p.unCheckedChildren,Z=p.checkedChildren,L=p.proFieldProps,x=(0,d.Z)(p,A);return(0,S.jsx)(M.Z,(0,E.Z)({valueType:"switch",fieldProps:(0,E.Z)({unCheckedChildren:R,checkedChildren:Z},t),ref:m,valuePropName:"checked",proFieldProps:L,filedConfig:{valuePropName:"checked",ignoreWidth:!0,customLightMode:!0}},x))});T.Z=g},5966:function(X,T,e){var E=e(97685),d=e(1413),D=e(45987),M=e(21770),S=e(72723),A=e(55241),g=e(97435),p=e(67294),m=e(44756),t=e(85893),R=["fieldProps","proFieldProps"],Z=["fieldProps","proFieldProps"],L="text",x=function(i){var n=i.fieldProps,y=i.proFieldProps,h=(0,D.Z)(i,R);return(0,t.jsx)(m.Z,(0,d.Z)({valueType:L,fieldProps:n,filedConfig:{valueType:L},proFieldProps:y},h))},O=function(i){var n=(0,M.Z)(i.open||!1,{value:i.open,onChange:i.onOpenChange}),y=(0,E.Z)(n,2),h=y[0],$=y[1];return(0,t.jsx)(S.Z.Item,{shouldUpdate:!0,noStyle:!0,children:function(w){var b,r=w.getFieldValue(i.name||[]);return(0,t.jsx)(A.Z,(0,d.Z)((0,d.Z)({getPopupContainer:function(a){return a&&a.parentNode?a.parentNode:a},onOpenChange:function(a){return $(a)},content:(0,t.jsxs)("div",{style:{padding:"4px 0"},children:[(b=i.statusRender)===null||b===void 0?void 0:b.call(i,r),i.strengthText?(0,t.jsx)("div",{style:{marginTop:10},children:(0,t.jsx)("span",{children:i.strengthText})}):null]}),overlayStyle:{width:240},placement:"rightTop"},i.popoverProps),{},{open:h,children:i.children}))}})},_=function(i){var n=i.fieldProps,y=i.proFieldProps,h=(0,D.Z)(i,Z),$=(0,p.useState)(!1),V=(0,E.Z)($,2),w=V[0],b=V[1];return n!=null&&n.statusRender&&h.name?(0,t.jsx)(O,{name:h.name,statusRender:n==null?void 0:n.statusRender,popoverProps:n==null?void 0:n.popoverProps,strengthText:n==null?void 0:n.strengthText,open:w,onOpenChange:b,children:(0,t.jsx)("div",{children:(0,t.jsx)(m.Z,(0,d.Z)({valueType:"password",fieldProps:(0,d.Z)((0,d.Z)({},(0,g.Z)(n,["statusRender","popoverProps","strengthText"])),{},{onBlur:function(l){var a;n==null||(a=n.onBlur)===null||a===void 0||a.call(n,l),b(!1)},onClick:function(l){var a;n==null||(a=n.onClick)===null||a===void 0||a.call(n,l),b(!0)}}),proFieldProps:y,filedConfig:{valueType:L}},h))})}):(0,t.jsx)(m.Z,(0,d.Z)({valueType:"password",fieldProps:n,proFieldProps:y,filedConfig:{valueType:L}},h))},W=x;W.Password=_,W.displayName="ProFormComponent",T.Z=W},80821:function(X,T,e){e.d(T,{Z:function(){return m}});var E=e(5574),d=e.n(E),D=e(24963),M=e(86738),S=e(28036),A=e(83062),g=e(67294),p=e(85893);function m(t){var R=(0,g.useState)(!1),Z=d()(R,2),L=Z[0],x=Z[1],O=(0,g.useContext)(D.Z),_=O.lang,W=O.notice,I=O.message,i=function(){x(!0),t.action().then(function(y){if(x(!1),typeof t.onSuccess=="function"&&t.onSuccess(y),t.messageSuccess){var h="";typeof t.messageSuccess=="function"?h=t.messageSuccess(y):h=t.messageSuccess,h=_("notification.".concat(h))+_("notification.title.success"),t.asynced?I.info(h):I.success(h)}}).catch(function(y){x(!1),typeof t.onError=="function"&&t.onError(y)})};return t.confirm?(0,p.jsx)(M.Z,{style:{width:500},title:t.confirmTitle?t.confirmTitle:_("notification.title.tip"),description:t.confirm,onConfirm:i,okText:"Yes",cancelText:"No",children:(0,p.jsx)(S.ZP,{disabled:t.disabled,icon:t.icon,loading:L,danger:t.danger,type:t.type,children:t.children})}):(0,p.jsx)(A.Z,{title:t.tips,children:(0,p.jsx)(S.ZP,{disabled:t.disabled,icon:t.icon,loading:L,onClick:i,danger:t.danger,type:t.type,children:t.children})})}},89063:function(X,T,e){e.d(T,{Z:function(){return p}});var E=e(24963),d=e(88484),D=e(62370),M=e(31418),S=e(28036),A=e(67294),g=e(85893);function p(m){var t=(0,A.useContext)(E.Z),R=t.message,Z=t.notice,L=t.lang,x=(0,A.useRef)(null),O=M.Z.useApp(),_=function(){x.current&&(x.current.click(),x.current.onchange=function(I){if(!I||!I.target)return"";var i=new FileReader;i.onload=function(y){var h,$,V=(h=y.target)===null||h===void 0?void 0:h.result;if(m.onLoad)try{m.onLoad&&m.onLoad(V)}catch(w){Z.error(w);return}typeof m.onImport=="function"&&(R.success("\u6210\u529F\u5BFC\u5165 ".concat(m.title)),m.onImport(V)),($=x.current)!==null&&$!==void 0&&$.value&&(x.current.value="")};var n=I.target;if(n.files)try{i.readAsText(n.files[0])}catch(y){Z.error("\u5BFC\u5165\u6587\u4EF6\u5FC5\u987B\u662F\u6587\u672C\u7C7B\u578B")}})};return(0,g.jsxs)(g.Fragment,{children:[(0,g.jsx)(D.Z,{children:(0,g.jsx)(S.ZP,{icon:(0,g.jsx)(d.Z,{}),block:!0,onClick:_,children:m.title})}),(0,g.jsx)("input",{style:{display:"none"},type:"file",ref:x,name:"importFileInput"})]})}},24963:function(X,T,e){var E=e(67294),d=(0,E.createContext)({});T.Z=d},53893:function(X,T,e){e.r(T),e.d(T,{default:function(){return o}});var E=e(15009),d=e.n(E),D=e(99289),M=e.n(D),S=e(5574),A=e.n(S),g=e(80821),p=e(184),m=e(5966),t=e(52688),R=e(97462),Z=e(62370),L=e(28036),x=e(86250),O=e(67294),_=e(91845),W=e(87662),I=e(89063),i=e(24963),n=e(85893),y=(0,O.forwardRef)(function(c,Y){var H;(0,O.useImperativeHandle)(Y,function(){return{edit:function(s){var v;(v=f.current)===null||v===void 0||v.setFieldsValue({name:s.name,title:s.title,address:s.address,enableTLS:s.enableTLS,tlsCa:s.tlsCa,tlsCert:s.tlsCert,tlsKey:s.tlsKey,enableComposePath:s.enableComposePath}),U(!0),u(s.name)}}});var N=(0,O.useState)(!1),z=A()(N,2),Q=z[0],U=z[1],f=(0,O.useRef)(),C=(0,O.useState)(""),F=A()(C,2),j=F[0],u=F[1],q=(0,O.useContext)(i.Z),J=q.lang;return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(L.ZP,{onClick:function(){var s;u(""),(s=f.current)===null||s===void 0||s.resetFields(),U(!0)},type:"primary",children:"\u6DFB\u52A0Docker\u73AF\u5883"}),(0,n.jsxs)(p.a,{drawerProps:{forceRender:!0},onOpenChange:function(s){U(s)},open:Q,width:800,formRef:f,title:(H=f.current)!==null&&H!==void 0&&H.getFieldValue&&f.current.getFieldValue("name")=="local"?"\u914D\u7F6E\u9ED8\u8BA4Docker\u5BA2\u6237\u7AEF":"\u6DFB\u52A0Docker\u73AF\u5883",onFinish:function(){var G=M()(d()().mark(function s(v){var P,B;return d()().wrap(function(k){for(;;)switch(k.prev=k.next){case 0:return P={name:v.name,title:v.title,address:v.address,tlsCa:v.tlsCa,tlsCert:v.tlsCert,tlsKey:v.tlsKey,enableTLS:v.enableTLS,enableComposePath:v.enableComposePath,composePath:v.enableComposePath?v.composePath:""},k.next=3,(0,W.ad)(P);case 3:return B=k.sent,c.onFinish&&c.onFinish(),k.abrupt("return",!0);case 6:case"end":return k.stop()}},s)}));return function(s){return G.apply(this,arguments)}}(),children:[(0,n.jsx)(m.Z,{label:"\u540D\u79F0",name:"title",required:!0,rules:[{required:!0}],fieldProps:{onChange:function(s){var v="";if(s.target.value&&!j){var P,B=(0,_.N9)(s.target.value.trim(),{toneType:"none",type:"array"});v=B.join(""),(P=f.current)===null||P===void 0||P.setFieldValue("name",v)}}}}),(0,n.jsx)(m.Z,{label:"\u6807\u8BC6",name:"name",required:!0,disabled:j!="",rules:[{required:!0}],placeholder:"\u6807\u8BC6Docker\u73AF\u5883\uFF0C\u53EA\u5141\u8BB8\u4E3A\u82F1\u6587\u6216\u662F\u6570\u5B57"}),(0,n.jsx)(m.Z,{label:"Docker Api \u5730\u5740",name:"address",tooltip:"\u8FDE\u63A5\u8FDC\u7A0B Docker \u65F6\u8BF7\u5148\u5F00\u542F Api \u5730\u5740\u8BBF\u95EE\u3002",placeholder:"\u4F8B\u5982\uFF1Aunix:///var/run/docker.sock\u3001tcp://192.16.0.5:2375"}),(0,n.jsxs)(x.Z,{gap:80,children:[(0,n.jsx)(t.Z,{label:"\u542F\u7528TLS",name:"enableTLS",tooltip:"\u751F\u6210\u6559\u7A0B\u89C1\uFF1Ahttps://donknap.github.io/dpanel-docs/#/zh-cn/manual/remote"}),(0,n.jsx)(R.Z,{name:["enableComposePath","name"],children:function(s){var v=s.name;if(v!="local")return(0,n.jsx)(t.Z,{label:J("system.env.createEnableComposePath"),name:"enableComposePath",tooltip:"\u5F00\u542F\u72EC\u7ACBcompose\u914D\u7F6E\u540E\uFF0C\u5207\u6362\u8FDC\u7A0B docker \u5BA2\u6237\u7AEF\u65F6\u5C06\u53EA\u4F1A\u8BFB\u53D6\u8BE5\u73AF\u5883\u4E13\u5C5E\u76EE\u5F55\u4E0B\u7684 compose \u4EFB\u52A1"})}})]}),(0,n.jsx)(R.Z,{name:["enableComposePath","name"],children:function(s){var v=s.enableComposePath,P=s.name;if(v)return(0,n.jsx)(m.Z,{label:J("system.env.createComposePath"),name:"composePath",disabled:!0,fieldProps:{value:"/dpanel/compose/compose-".concat(P!=null?P:"")}})}}),(0,n.jsx)(R.Z,{name:["enableTLS"],children:function(s){var v=s.enableTLS;if(v)return(0,n.jsxs)(x.Z,{gap:20,justify:"start",children:[(0,n.jsx)(Z.Z,{name:"tlsCa",label:"\u4E0A\u4F20\u5BA2\u6237\u7AEF\u8BC1\u4E66",children:(0,n.jsx)(I.Z,{title:"\u4E0A\u4F20CA\u8BC1\u4E66 ca.pem",onImport:function(B){var K;return(K=f.current)===null||K===void 0||K.setFieldValue("tlsCa",B),!0},onLoad:function(B){if(B.indexOf("CERTIFICATE")<0)throw new Error("\u5BFC\u5165ca.pem\u8BC1\u4E66\u9519\u8BEF");return!0}})}),(0,n.jsx)(Z.Z,{name:"tlsCert",label:" ",children:(0,n.jsx)(I.Z,{title:"\u4E0A\u4F20\u8BC1\u4E66\u6587\u4EF6 cert.pem",onImport:function(B){var K;return(K=f.current)===null||K===void 0||K.setFieldValue("tlsCert",B),!0},onLoad:function(B){if(B.indexOf("CERTIFICATE")<0)throw new Error("\u5BFC\u5165cert.pem\u8BC1\u4E66\u9519\u8BEF");return!0}})}),(0,n.jsx)(Z.Z,{label:" ",name:"tlsKey",children:(0,n.jsx)(I.Z,{title:"\u4E0A\u4F20\u5BC6\u94A5\u6587\u4EF6 key.pem",onImport:function(B){var K;return(K=f.current)===null||K===void 0||K.setFieldValue("tlsKey",B),!0},onLoad:function(B){if(B.indexOf("PRIVATE")<0)throw new Error("\u5BFC\u5165key.pem\u8BC1\u4E66\u9519\u8BEF");return!0}})})]})}})]})]})}),h=y,$=e(86548),V=e(90078),w=e(10641),b=e(63713),r=e(42075),l=e(96074),a=e(25593);function o(){var c=(0,O.useRef)(),Y=(0,O.useRef)(),H=(0,b.useSearchParams)(),N=A()(H,2),z=N[0],Q=N[1];return(0,n.jsx)(V._z,{header:{extra:[(0,n.jsx)(h,{ref:Y,onFinish:M()(d()().mark(function U(){var f,C,F;return d()().wrap(function(u){for(;;)switch(u.prev=u.next){case 0:if(!z.get("id")){u.next=6;break}return u.next=3,(0,W.vC)({name:(F=z.get("id"))!==null&&F!==void 0?F:"local"});case 3:return Q(""),window.location.href="/dpanel/ui/home",u.abrupt("return");case 6:!((f=c.current)===null||f===void 0)&&f.reloadAndRest&&((C=c.current)===null||C===void 0||C.reloadAndRest());case 7:case"end":return u.stop()}},U)}))},"dockerEnvCreate")]},children:(0,n.jsx)(w.Z,{rowKey:"name",columns:[{title:"\u6807\u8BC6",dataIndex:"name"},{title:"\u540D\u79F0",dataIndex:"title"},{title:"\u5730\u5740",dataIndex:"address"},{title:"\u64CD\u4F5C",width:100,search:!1,render:function(f,C,F,j,u){return(0,n.jsx)(r.Z,{split:(0,n.jsx)(l.Z,{type:"vertical"}),children:(0,n.jsx)(a.Z.Link,{onClick:function(){var J;(J=Y.current)===null||J===void 0||J.edit(C)},children:(0,n.jsx)($.Z,{})},C.name)})}}],pagination:!1,request:M()(d()().mark(function U(){var f;return d()().wrap(function(F){for(;;)switch(F.prev=F.next){case 0:return F.next=2,(0,W.Kg)();case 2:return f=F.sent,z.get("id")&&f.data.list.map(function(j){if(j.name==z.get("id")){var u;(u=Y.current)===null||u===void 0||u.edit(j)}}),F.abrupt("return",{data:f.data.list,total:f.data.list.length});case 5:case"end":return F.stop()}},U)})),search:!1,rowSelection:{defaultSelectedRowKeys:[],alwaysShowAlert:!0,getCheckboxProps:function(f){return{disabled:f.default}}},actionRef:c,tableAlertOptionRender:function(f){var C=f.selectedRowKeys;return(0,n.jsx)(r.Z,{size:16,children:(0,n.jsx)(g.Z,{danger:!0,type:"primary",action:function(){return(0,W._g)({name:C})},onSuccess:function(){var j,u;return!((j=c.current)===null||j===void 0)&&j.reloadAndRest&&((u=c.current)===null||u===void 0||u.reloadAndRest()),!0},onError:function(){var j,u;return!((j=c.current)===null||j===void 0)&&j.reset&&((u=c.current)===null||u===void 0||u.reset()),!0},messageSuccess:"delete",children:"\u6279\u91CF\u5220\u9664"})})}})})}},86250:function(X,T,e){e.d(T,{Z:function(){return b}});var E=e(67294),d=e(93967),D=e.n(d),M=e(98423),S=e(98065),A=e(53124),g=e(83559),p=e(83262);const m=["wrap","nowrap","wrap-reverse"],t=["flex-start","flex-end","start","end","center","space-between","space-around","space-evenly","stretch","normal","left","right"],R=["center","start","end","flex-start","flex-end","self-start","self-end","baseline","normal","stretch"],Z=(r,l)=>{const a=l.wrap===!0?"wrap":l.wrap;return{[`${r}-wrap-${a}`]:a&&m.includes(a)}},L=(r,l)=>{const a={};return R.forEach(o=>{a[`${r}-align-${o}`]=l.align===o}),a[`${r}-align-stretch`]=!l.align&&!!l.vertical,a},x=(r,l)=>{const a={};return t.forEach(o=>{a[`${r}-justify-${o}`]=l.justify===o}),a};function O(r,l){return D()(Object.assign(Object.assign(Object.assign({},Z(r,l)),L(r,l)),x(r,l)))}var _=O;const W=r=>{const{componentCls:l}=r;return{[l]:{display:"flex","&-vertical":{flexDirection:"column"},"&-rtl":{direction:"rtl"},"&:empty":{display:"none"}}}},I=r=>{const{componentCls:l}=r;return{[l]:{"&-gap-small":{gap:r.flexGapSM},"&-gap-middle":{gap:r.flexGap},"&-gap-large":{gap:r.flexGapLG}}}},i=r=>{const{componentCls:l}=r,a={};return m.forEach(o=>{a[`${l}-wrap-${o}`]={flexWrap:o}}),a},n=r=>{const{componentCls:l}=r,a={};return R.forEach(o=>{a[`${l}-align-${o}`]={alignItems:o}}),a},y=r=>{const{componentCls:l}=r,a={};return t.forEach(o=>{a[`${l}-justify-${o}`]={justifyContent:o}}),a},h=()=>({});var $=(0,g.I$)("Flex",r=>{const{paddingXS:l,padding:a,paddingLG:o}=r,c=(0,p.IX)(r,{flexGapSM:l,flexGap:a,flexGapLG:o});return[W(c),I(c),i(c),n(c),y(c)]},h,{resetStyle:!1}),V=function(r,l){var a={};for(var o in r)Object.prototype.hasOwnProperty.call(r,o)&&l.indexOf(o)<0&&(a[o]=r[o]);if(r!=null&&typeof Object.getOwnPropertySymbols=="function")for(var c=0,o=Object.getOwnPropertySymbols(r);c<o.length;c++)l.indexOf(o[c])<0&&Object.prototype.propertyIsEnumerable.call(r,o[c])&&(a[o[c]]=r[o[c]]);return a},b=E.forwardRef((r,l)=>{const{prefixCls:a,rootClassName:o,className:c,style:Y,flex:H,gap:N,children:z,vertical:Q=!1,component:U="div"}=r,f=V(r,["prefixCls","rootClassName","className","style","flex","gap","children","vertical","component"]),{flex:C,direction:F,getPrefixCls:j}=E.useContext(A.E_),u=j("flex",a),[q,J,G]=$(u),s=Q!=null?Q:C==null?void 0:C.vertical,v=D()(c,o,C==null?void 0:C.className,u,J,G,_(u,r),{[`${u}-rtl`]:F==="rtl",[`${u}-gap-${N}`]:(0,S.n)(N),[`${u}-vertical`]:s}),P=Object.assign(Object.assign({},C==null?void 0:C.style),Y);return H&&(P.flex=H),N&&!(0,S.n)(N)&&(P.gap=N),q(E.createElement(U,Object.assign({ref:l,className:v,style:P},(0,M.Z)(f,["justify","wrap","align"])),z))})}}]);