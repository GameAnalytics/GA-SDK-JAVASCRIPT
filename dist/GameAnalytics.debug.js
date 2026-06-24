(function(scope){
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(h,s){var f={},g=f.lib={},q=function(){},m=g.Base={extend:function(a){q.prototype=this;var c=new q;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=g.WordArray=m.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||k).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=m.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new r.init(c,a)}}),l=f.enc={},k=l.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
2),16)<<24-4*(b%8);return new r.init(d,c/2)}},n=l.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new r.init(d,c)}},j=l.Utf8={stringify:function(a){try{return decodeURIComponent(escape(n.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return n.parse(unescape(encodeURIComponent(a)))}},
u=g.BufferedBlockAlgorithm=m.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=j.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var g=0;g<a;g+=e)this._doProcessBlock(d,g);g=d.splice(0,a);c.sigBytes-=b}return new r.init(g,b)},clone:function(){var a=m.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});g.Hasher=u.extend({cfg:m.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new t.HMAC.init(a,
d)).finalize(c)}}});var t=f.algo={};return f}(Math);
(function(h){for(var s=CryptoJS,f=s.lib,g=f.WordArray,q=f.Hasher,f=s.algo,m=[],r=[],l=function(a){return 4294967296*(a-(a|0))|0},k=2,n=0;64>n;){var j;a:{j=k;for(var u=h.sqrt(j),t=2;t<=u;t++)if(!(j%t)){j=!1;break a}j=!0}j&&(8>n&&(m[n]=l(h.pow(k,0.5))),r[n]=l(h.pow(k,1/3)),n++);k++}var a=[],f=f.SHA256=q.extend({_doReset:function(){this._hash=new g.init(m.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],g=b[2],j=b[3],h=b[4],m=b[5],n=b[6],q=b[7],p=0;64>p;p++){if(16>p)a[p]=
c[d+p]|0;else{var k=a[p-15],l=a[p-2];a[p]=((k<<25|k>>>7)^(k<<14|k>>>18)^k>>>3)+a[p-7]+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+a[p-16]}k=q+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+(h&m^~h&n)+r[p]+a[p];l=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&g^f&g);q=n;n=m;m=h;h=j+k|0;j=g;g=f;f=e;e=k+l|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+g|0;b[3]=b[3]+j|0;b[4]=b[4]+h|0;b[5]=b[5]+m|0;b[6]=b[6]+n|0;b[7]=b[7]+q|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=q.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=q._createHelper(f);s.HmacSHA256=q._createHmacHelper(f)})(Math);
(function(){var h=CryptoJS,s=h.enc.Utf8;h.algo.HMAC=h.lib.Base.extend({init:function(f,g){f=this._hasher=new f.init;"string"==typeof g&&(g=s.parse(g));var h=f.blockSize,m=4*h;g.sigBytes>m&&(g=f.finalize(g));g.clamp();for(var r=this._oKey=g.clone(),l=this._iKey=g.clone(),k=r.words,n=l.words,j=0;j<h;j++)k[j]^=1549556828,n[j]^=909522486;r.sigBytes=l.sigBytes=m;this.reset()},reset:function(){var f=this._hasher;f.reset();f.update(this._iKey)},update:function(f){this._hasher.update(f);return this},finalize:function(f){var g=
this._hasher;f=g.finalize(f);g.reset();return g.finalize(this._oKey.clone().concat(f))}})})();

/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var h=CryptoJS,j=h.lib.WordArray;h.enc.Base64={stringify:function(b){var e=b.words,f=b.sigBytes,c=this._map;b.clamp();b=[];for(var a=0;a<f;a+=3)for(var d=(e[a>>>2]>>>24-8*(a%4)&255)<<16|(e[a+1>>>2]>>>24-8*((a+1)%4)&255)<<8|e[a+2>>>2]>>>24-8*((a+2)%4)&255,g=0;4>g&&a+0.75*g<f;g++)b.push(c.charAt(d>>>6*(3-g)&63));if(e=c.charAt(64))for(;b.length%4;)b.push(e);return b.join("")},parse:function(b){var e=b.length,f=this._map,c=f.charAt(64);c&&(c=b.indexOf(c),-1!=c&&(e=c));for(var c=[],a=0,d=0;d<
e;d++)if(d%4){var g=f.indexOf(b.charAt(d-1))<<2*(d%4),h=f.indexOf(b.charAt(d))>>>6-2*(d%4);c[a>>>2]|=(g|h)<<24-8*(a%4);a++}return j.create(c,a)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();

var gameanalytics;
(function (gameanalytics) {
    var EGAErrorSeverity;
    (function (EGAErrorSeverity) {
        EGAErrorSeverity[EGAErrorSeverity["Undefined"] = 0] = "Undefined";
        EGAErrorSeverity[EGAErrorSeverity["Debug"] = 1] = "Debug";
        EGAErrorSeverity[EGAErrorSeverity["Info"] = 2] = "Info";
        EGAErrorSeverity[EGAErrorSeverity["Warning"] = 3] = "Warning";
        EGAErrorSeverity[EGAErrorSeverity["Error"] = 4] = "Error";
        EGAErrorSeverity[EGAErrorSeverity["Critical"] = 5] = "Critical";
    })(EGAErrorSeverity = gameanalytics.EGAErrorSeverity || (gameanalytics.EGAErrorSeverity = {}));
    var EGAProgressionStatus;
    (function (EGAProgressionStatus) {
        EGAProgressionStatus[EGAProgressionStatus["Undefined"] = 0] = "Undefined";
        EGAProgressionStatus[EGAProgressionStatus["Start"] = 1] = "Start";
        EGAProgressionStatus[EGAProgressionStatus["Complete"] = 2] = "Complete";
        EGAProgressionStatus[EGAProgressionStatus["Fail"] = 3] = "Fail";
    })(EGAProgressionStatus = gameanalytics.EGAProgressionStatus || (gameanalytics.EGAProgressionStatus = {}));
    var EGAResourceFlowType;
    (function (EGAResourceFlowType) {
        EGAResourceFlowType[EGAResourceFlowType["Undefined"] = 0] = "Undefined";
        EGAResourceFlowType[EGAResourceFlowType["Source"] = 1] = "Source";
        EGAResourceFlowType[EGAResourceFlowType["Sink"] = 2] = "Sink";
    })(EGAResourceFlowType = gameanalytics.EGAResourceFlowType || (gameanalytics.EGAResourceFlowType = {}));
    var EGAAdAction;
    (function (EGAAdAction) {
        EGAAdAction[EGAAdAction["Undefined"] = 0] = "Undefined";
        EGAAdAction[EGAAdAction["Clicked"] = 1] = "Clicked";
        EGAAdAction[EGAAdAction["Show"] = 2] = "Show";
        EGAAdAction[EGAAdAction["FailedShow"] = 3] = "FailedShow";
        EGAAdAction[EGAAdAction["RewardReceived"] = 4] = "RewardReceived";
    })(EGAAdAction = gameanalytics.EGAAdAction || (gameanalytics.EGAAdAction = {}));
    var EGAAdError;
    (function (EGAAdError) {
        EGAAdError[EGAAdError["Undefined"] = 0] = "Undefined";
        EGAAdError[EGAAdError["Unknown"] = 1] = "Unknown";
        EGAAdError[EGAAdError["Offline"] = 2] = "Offline";
        EGAAdError[EGAAdError["NoFill"] = 3] = "NoFill";
        EGAAdError[EGAAdError["InternalError"] = 4] = "InternalError";
        EGAAdError[EGAAdError["InvalidRequest"] = 5] = "InvalidRequest";
        EGAAdError[EGAAdError["UnableToPrecache"] = 6] = "UnableToPrecache";
    })(EGAAdError = gameanalytics.EGAAdError || (gameanalytics.EGAAdError = {}));
    var EGAAdType;
    (function (EGAAdType) {
        EGAAdType[EGAAdType["Undefined"] = 0] = "Undefined";
        EGAAdType[EGAAdType["Video"] = 1] = "Video";
        EGAAdType[EGAAdType["RewardedVideo"] = 2] = "RewardedVideo";
        EGAAdType[EGAAdType["Playable"] = 3] = "Playable";
        EGAAdType[EGAAdType["Interstitial"] = 4] = "Interstitial";
        EGAAdType[EGAAdType["OfferWall"] = 5] = "OfferWall";
        EGAAdType[EGAAdType["Banner"] = 6] = "Banner";
    })(EGAAdType = gameanalytics.EGAAdType || (gameanalytics.EGAAdType = {}));
    var http;
    (function (http) {
        var EGAHTTPApiResponse;
        (function (EGAHTTPApiResponse) {
            EGAHTTPApiResponse[EGAHTTPApiResponse["NoResponse"] = 0] = "NoResponse";
            EGAHTTPApiResponse[EGAHTTPApiResponse["BadResponse"] = 1] = "BadResponse";
            EGAHTTPApiResponse[EGAHTTPApiResponse["RequestTimeout"] = 2] = "RequestTimeout";
            EGAHTTPApiResponse[EGAHTTPApiResponse["JsonEncodeFailed"] = 3] = "JsonEncodeFailed";
            EGAHTTPApiResponse[EGAHTTPApiResponse["JsonDecodeFailed"] = 4] = "JsonDecodeFailed";
            EGAHTTPApiResponse[EGAHTTPApiResponse["InternalServerError"] = 5] = "InternalServerError";
            EGAHTTPApiResponse[EGAHTTPApiResponse["BadRequest"] = 6] = "BadRequest";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Unauthorized"] = 7] = "Unauthorized";
            EGAHTTPApiResponse[EGAHTTPApiResponse["UnknownResponseCode"] = 8] = "UnknownResponseCode";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Ok"] = 9] = "Ok";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Created"] = 10] = "Created";
        })(EGAHTTPApiResponse = http.EGAHTTPApiResponse || (http.EGAHTTPApiResponse = {}));
    })(http = gameanalytics.http || (gameanalytics.http = {}));
    var events;
    (function (events) {
        var EGASdkErrorCategory;
        (function (EGASdkErrorCategory) {
            EGASdkErrorCategory[EGASdkErrorCategory["Undefined"] = 0] = "Undefined";
            EGASdkErrorCategory[EGASdkErrorCategory["EventValidation"] = 1] = "EventValidation";
            EGASdkErrorCategory[EGASdkErrorCategory["Database"] = 2] = "Database";
            EGASdkErrorCategory[EGASdkErrorCategory["Init"] = 3] = "Init";
            EGASdkErrorCategory[EGASdkErrorCategory["Http"] = 4] = "Http";
            EGASdkErrorCategory[EGASdkErrorCategory["Json"] = 5] = "Json";
        })(EGASdkErrorCategory = events.EGASdkErrorCategory || (events.EGASdkErrorCategory = {}));
        var EGASdkErrorArea;
        (function (EGASdkErrorArea) {
            EGASdkErrorArea[EGASdkErrorArea["Undefined"] = 0] = "Undefined";
            EGASdkErrorArea[EGASdkErrorArea["BusinessEvent"] = 1] = "BusinessEvent";
            EGASdkErrorArea[EGASdkErrorArea["ResourceEvent"] = 2] = "ResourceEvent";
            EGASdkErrorArea[EGASdkErrorArea["ProgressionEvent"] = 3] = "ProgressionEvent";
            EGASdkErrorArea[EGASdkErrorArea["DesignEvent"] = 4] = "DesignEvent";
            EGASdkErrorArea[EGASdkErrorArea["ErrorEvent"] = 5] = "ErrorEvent";
            EGASdkErrorArea[EGASdkErrorArea["InitHttp"] = 9] = "InitHttp";
            EGASdkErrorArea[EGASdkErrorArea["EventsHttp"] = 10] = "EventsHttp";
            EGASdkErrorArea[EGASdkErrorArea["ProcessEvents"] = 11] = "ProcessEvents";
            EGASdkErrorArea[EGASdkErrorArea["AddEventsToStore"] = 12] = "AddEventsToStore";
            EGASdkErrorArea[EGASdkErrorArea["AdEvent"] = 20] = "AdEvent";
        })(EGASdkErrorArea = events.EGASdkErrorArea || (events.EGASdkErrorArea = {}));
        var EGASdkErrorAction;
        (function (EGASdkErrorAction) {
            EGASdkErrorAction[EGASdkErrorAction["Undefined"] = 0] = "Undefined";
            EGASdkErrorAction[EGASdkErrorAction["InvalidCurrency"] = 1] = "InvalidCurrency";
            EGASdkErrorAction[EGASdkErrorAction["InvalidShortString"] = 2] = "InvalidShortString";
            EGASdkErrorAction[EGASdkErrorAction["InvalidEventPartLength"] = 3] = "InvalidEventPartLength";
            EGASdkErrorAction[EGASdkErrorAction["InvalidEventPartCharacters"] = 4] = "InvalidEventPartCharacters";
            EGASdkErrorAction[EGASdkErrorAction["InvalidStore"] = 5] = "InvalidStore";
            EGASdkErrorAction[EGASdkErrorAction["InvalidFlowType"] = 6] = "InvalidFlowType";
            EGASdkErrorAction[EGASdkErrorAction["StringEmptyOrNull"] = 7] = "StringEmptyOrNull";
            EGASdkErrorAction[EGASdkErrorAction["NotFoundInAvailableCurrencies"] = 8] = "NotFoundInAvailableCurrencies";
            EGASdkErrorAction[EGASdkErrorAction["InvalidAmount"] = 9] = "InvalidAmount";
            EGASdkErrorAction[EGASdkErrorAction["NotFoundInAvailableItemTypes"] = 10] = "NotFoundInAvailableItemTypes";
            EGASdkErrorAction[EGASdkErrorAction["WrongProgressionOrder"] = 11] = "WrongProgressionOrder";
            EGASdkErrorAction[EGASdkErrorAction["InvalidEventIdLength"] = 12] = "InvalidEventIdLength";
            EGASdkErrorAction[EGASdkErrorAction["InvalidEventIdCharacters"] = 13] = "InvalidEventIdCharacters";
            EGASdkErrorAction[EGASdkErrorAction["InvalidProgressionStatus"] = 15] = "InvalidProgressionStatus";
            EGASdkErrorAction[EGASdkErrorAction["InvalidSeverity"] = 16] = "InvalidSeverity";
            EGASdkErrorAction[EGASdkErrorAction["InvalidLongString"] = 17] = "InvalidLongString";
            EGASdkErrorAction[EGASdkErrorAction["DatabaseTooLarge"] = 18] = "DatabaseTooLarge";
            EGASdkErrorAction[EGASdkErrorAction["DatabaseOpenOrCreate"] = 19] = "DatabaseOpenOrCreate";
            EGASdkErrorAction[EGASdkErrorAction["JsonError"] = 25] = "JsonError";
            EGASdkErrorAction[EGASdkErrorAction["FailHttpJsonDecode"] = 29] = "FailHttpJsonDecode";
            EGASdkErrorAction[EGASdkErrorAction["FailHttpJsonEncode"] = 30] = "FailHttpJsonEncode";
            EGASdkErrorAction[EGASdkErrorAction["InvalidAdAction"] = 31] = "InvalidAdAction";
            EGASdkErrorAction[EGASdkErrorAction["InvalidAdType"] = 32] = "InvalidAdType";
            EGASdkErrorAction[EGASdkErrorAction["InvalidString"] = 33] = "InvalidString";
        })(EGASdkErrorAction = events.EGASdkErrorAction || (events.EGASdkErrorAction = {}));
        var EGASdkErrorParameter;
        (function (EGASdkErrorParameter) {
            EGASdkErrorParameter[EGASdkErrorParameter["Undefined"] = 0] = "Undefined";
            EGASdkErrorParameter[EGASdkErrorParameter["Currency"] = 1] = "Currency";
            EGASdkErrorParameter[EGASdkErrorParameter["CartType"] = 2] = "CartType";
            EGASdkErrorParameter[EGASdkErrorParameter["ItemType"] = 3] = "ItemType";
            EGASdkErrorParameter[EGASdkErrorParameter["ItemId"] = 4] = "ItemId";
            EGASdkErrorParameter[EGASdkErrorParameter["Store"] = 5] = "Store";
            EGASdkErrorParameter[EGASdkErrorParameter["FlowType"] = 6] = "FlowType";
            EGASdkErrorParameter[EGASdkErrorParameter["Amount"] = 7] = "Amount";
            EGASdkErrorParameter[EGASdkErrorParameter["Progression01"] = 8] = "Progression01";
            EGASdkErrorParameter[EGASdkErrorParameter["Progression02"] = 9] = "Progression02";
            EGASdkErrorParameter[EGASdkErrorParameter["Progression03"] = 10] = "Progression03";
            EGASdkErrorParameter[EGASdkErrorParameter["EventId"] = 11] = "EventId";
            EGASdkErrorParameter[EGASdkErrorParameter["ProgressionStatus"] = 12] = "ProgressionStatus";
            EGASdkErrorParameter[EGASdkErrorParameter["Severity"] = 13] = "Severity";
            EGASdkErrorParameter[EGASdkErrorParameter["Message"] = 14] = "Message";
            EGASdkErrorParameter[EGASdkErrorParameter["AdAction"] = 15] = "AdAction";
            EGASdkErrorParameter[EGASdkErrorParameter["AdType"] = 16] = "AdType";
            EGASdkErrorParameter[EGASdkErrorParameter["AdSdkName"] = 17] = "AdSdkName";
            EGASdkErrorParameter[EGASdkErrorParameter["AdPlacement"] = 18] = "AdPlacement";
        })(EGASdkErrorParameter = events.EGASdkErrorParameter || (events.EGASdkErrorParameter = {}));
    })(events = gameanalytics.events || (gameanalytics.events = {}));
})(gameanalytics || (gameanalytics = {}));
var public_enums;
(function (public_enums) {
    var EGAErrorSeverity;
    (function (EGAErrorSeverity) {
        EGAErrorSeverity[EGAErrorSeverity["Undefined"] = 0] = "Undefined";
        EGAErrorSeverity[EGAErrorSeverity["Debug"] = 1] = "Debug";
        EGAErrorSeverity[EGAErrorSeverity["Info"] = 2] = "Info";
        EGAErrorSeverity[EGAErrorSeverity["Warning"] = 3] = "Warning";
        EGAErrorSeverity[EGAErrorSeverity["Error"] = 4] = "Error";
        EGAErrorSeverity[EGAErrorSeverity["Critical"] = 5] = "Critical";
    })(EGAErrorSeverity = public_enums.EGAErrorSeverity || (public_enums.EGAErrorSeverity = {}));
    var EGAProgressionStatus;
    (function (EGAProgressionStatus) {
        EGAProgressionStatus[EGAProgressionStatus["Undefined"] = 0] = "Undefined";
        EGAProgressionStatus[EGAProgressionStatus["Start"] = 1] = "Start";
        EGAProgressionStatus[EGAProgressionStatus["Complete"] = 2] = "Complete";
        EGAProgressionStatus[EGAProgressionStatus["Fail"] = 3] = "Fail";
    })(EGAProgressionStatus = public_enums.EGAProgressionStatus || (public_enums.EGAProgressionStatus = {}));
    var EGAResourceFlowType;
    (function (EGAResourceFlowType) {
        EGAResourceFlowType[EGAResourceFlowType["Undefined"] = 0] = "Undefined";
        EGAResourceFlowType[EGAResourceFlowType["Source"] = 1] = "Source";
        EGAResourceFlowType[EGAResourceFlowType["Sink"] = 2] = "Sink";
    })(EGAResourceFlowType = public_enums.EGAResourceFlowType || (public_enums.EGAResourceFlowType = {}));
    var EGAAdAction;
    (function (EGAAdAction) {
        EGAAdAction[EGAAdAction["Undefined"] = 0] = "Undefined";
        EGAAdAction[EGAAdAction["Clicked"] = 1] = "Clicked";
        EGAAdAction[EGAAdAction["Show"] = 2] = "Show";
        EGAAdAction[EGAAdAction["FailedShow"] = 3] = "FailedShow";
        EGAAdAction[EGAAdAction["RewardReceived"] = 4] = "RewardReceived";
    })(EGAAdAction = public_enums.EGAAdAction || (public_enums.EGAAdAction = {}));
    var EGAAdError;
    (function (EGAAdError) {
        EGAAdError[EGAAdError["Undefined"] = 0] = "Undefined";
        EGAAdError[EGAAdError["Unknown"] = 1] = "Unknown";
        EGAAdError[EGAAdError["Offline"] = 2] = "Offline";
        EGAAdError[EGAAdError["NoFill"] = 3] = "NoFill";
        EGAAdError[EGAAdError["InternalError"] = 4] = "InternalError";
        EGAAdError[EGAAdError["InvalidRequest"] = 5] = "InvalidRequest";
        EGAAdError[EGAAdError["UnableToPrecache"] = 6] = "UnableToPrecache";
    })(EGAAdError = public_enums.EGAAdError || (public_enums.EGAAdError = {}));
    var EGAAdType;
    (function (EGAAdType) {
        EGAAdType[EGAAdType["Undefined"] = 0] = "Undefined";
        EGAAdType[EGAAdType["Video"] = 1] = "Video";
        EGAAdType[EGAAdType["RewardedVideo"] = 2] = "RewardedVideo";
        EGAAdType[EGAAdType["Playable"] = 3] = "Playable";
        EGAAdType[EGAAdType["Interstitial"] = 4] = "Interstitial";
        EGAAdType[EGAAdType["OfferWall"] = 5] = "OfferWall";
        EGAAdType[EGAAdType["Banner"] = 6] = "Banner";
    })(EGAAdType = public_enums.EGAAdType || (public_enums.EGAAdType = {}));
})(public_enums || (public_enums = {}));
var gameanalytics;
(function (gameanalytics) {
    var logging;
    (function (logging) {
        var EGALoggerMessageType;
        (function (EGALoggerMessageType) {
            EGALoggerMessageType[EGALoggerMessageType["Error"] = 0] = "Error";
            EGALoggerMessageType[EGALoggerMessageType["Warning"] = 1] = "Warning";
            EGALoggerMessageType[EGALoggerMessageType["Info"] = 2] = "Info";
            EGALoggerMessageType[EGALoggerMessageType["Debug"] = 3] = "Debug";
        })(EGALoggerMessageType || (EGALoggerMessageType = {}));
        var GALogger = (function () {
            function GALogger() {
                GALogger.debugEnabled = true;
            }
            GALogger.setInfoLog = function (value) {
                GALogger.instance.infoLogEnabled = value;
            };
            GALogger.setVerboseLog = function (value) {
                GALogger.instance.infoLogVerboseEnabled = value;
            };
            GALogger.i = function (format) {
                if (!GALogger.instance.infoLogEnabled) {
                    return;
                }
                var message = "Info/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            };
            GALogger.w = function (format) {
                var message = "Warning/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Warning);
            };
            GALogger.e = function (format) {
                var message = "Error/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Error);
            };
            GALogger.ii = function (format) {
                if (!GALogger.instance.infoLogVerboseEnabled) {
                    return;
                }
                var message = "Verbose/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            };
            GALogger.d = function (format) {
                if (!GALogger.debugEnabled) {
                    return;
                }
                var message = "Debug/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Debug);
            };
            GALogger.prototype.sendNotificationMessage = function (message, type) {
                switch (type) {
                    case EGALoggerMessageType.Error:
                        {
                            console.error(message);
                        }
                        break;
                    case EGALoggerMessageType.Warning:
                        {
                            console.warn(message);
                        }
                        break;
                    case EGALoggerMessageType.Debug:
                        {
                            if (typeof console.debug === "function") {
                                console.debug(message);
                            }
                            else {
                                console.log(message);
                            }
                        }
                        break;
                    case EGALoggerMessageType.Info:
                        {
                            console.log(message);
                        }
                        break;
                }
            };
            GALogger.instance = new GALogger();
            GALogger.Tag = "GameAnalytics";
            return GALogger;
        }());
        logging.GALogger = GALogger;
    })(logging = gameanalytics.logging || (gameanalytics.logging = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var utilities;
    (function (utilities) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = (function () {
            function GAUtilities() {
            }
            GAUtilities.getHmac = function (key, data) {
                var encryptedMessage = CryptoJS.HmacSHA256(data, key);
                return CryptoJS.enc.Base64.stringify(encryptedMessage);
            };
            GAUtilities.stringMatch = function (s, pattern) {
                if (!s || !pattern) {
                    return false;
                }
                return pattern.test(s);
            };
            GAUtilities.joinStringArray = function (v, delimiter) {
                var result = "";
                for (var i = 0, il = v.length; i < il; i++) {
                    if (i > 0) {
                        result += delimiter;
                    }
                    result += v[i];
                }
                return result;
            };
            GAUtilities.stringArrayContainsString = function (array, search) {
                if (array.length === 0) {
                    return false;
                }
                for (var s in array) {
                    if (array[s] === search) {
                        return true;
                    }
                }
                return false;
            };
            GAUtilities.encode64 = function (input) {
                input = encodeURI(input);
                var output = "";
                var chr1, chr2, chr3 = 0;
                var enc1, enc2, enc3, enc4 = 0;
                var i = 0;
                do {
                    chr1 = input.charCodeAt(i++);
                    chr2 = input.charCodeAt(i++);
                    chr3 = input.charCodeAt(i++);
                    enc1 = chr1 >> 2;
                    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                    enc4 = chr3 & 63;
                    if (isNaN(chr2)) {
                        enc3 = enc4 = 64;
                    }
                    else if (isNaN(chr3)) {
                        enc4 = 64;
                    }
                    output = output +
                        GAUtilities.keyStr.charAt(enc1) +
                        GAUtilities.keyStr.charAt(enc2) +
                        GAUtilities.keyStr.charAt(enc3) +
                        GAUtilities.keyStr.charAt(enc4);
                    chr1 = chr2 = chr3 = 0;
                    enc1 = enc2 = enc3 = enc4 = 0;
                } while (i < input.length);
                return output;
            };
            GAUtilities.decode64 = function (input) {
                var output = "";
                var chr1, chr2, chr3 = 0;
                var enc1, enc2, enc3, enc4 = 0;
                var i = 0;
                var base64test = /[^A-Za-z0-9\+\/\=]/g;
                if (base64test.exec(input)) {
                    GALogger.w("There were invalid base64 characters in the input text. Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='. Expect errors in decoding.");
                }
                input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
                do {
                    enc1 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc2 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc3 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc4 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    chr1 = (enc1 << 2) | (enc2 >> 4);
                    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                    chr3 = ((enc3 & 3) << 6) | enc4;
                    output = output + String.fromCharCode(chr1);
                    if (enc3 != 64) {
                        output = output + String.fromCharCode(chr2);
                    }
                    if (enc4 != 64) {
                        output = output + String.fromCharCode(chr3);
                    }
                    chr1 = chr2 = chr3 = 0;
                    enc1 = enc2 = enc3 = enc4 = 0;
                } while (i < input.length);
                return decodeURI(output);
            };
            GAUtilities.timeIntervalSince1970 = function () {
                var date = new Date();
                return Math.round(date.getTime() / 1000);
            };
            GAUtilities.createGuid = function () {
                return ("10000000-1000-4000-8000-100000000000").replace(/[018]/g, function (c) { return (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16); });
            };
            GAUtilities.keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            return GAUtilities;
        }());
        utilities.GAUtilities = GAUtilities;
    })(utilities = gameanalytics.utilities || (gameanalytics.utilities = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var validators;
    (function (validators) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var EGASdkErrorCategory = gameanalytics.events.EGASdkErrorCategory;
        var EGASdkErrorArea = gameanalytics.events.EGASdkErrorArea;
        var EGASdkErrorAction = gameanalytics.events.EGASdkErrorAction;
        var EGASdkErrorParameter = gameanalytics.events.EGASdkErrorParameter;
        var ValidationResult = (function () {
            function ValidationResult(category, area, action, parameter, reason) {
                this.category = category;
                this.area = area;
                this.action = action;
                this.parameter = parameter;
                this.reason = reason;
            }
            return ValidationResult;
        }());
        validators.ValidationResult = ValidationResult;
        var GAValidator = (function () {
            function GAValidator() {
            }
            GAValidator.validateBusinessEvent = function (currency, amount, cartType, itemType, itemId) {
                if (!GAValidator.validateCurrency(currency)) {
                    GALogger.w("Validation fail - business event - currency: Cannot be (null) and need to be A-Z, 3 characters and in the standard at openexchangerates.org. Failed currency: " + currency);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidCurrency, EGASdkErrorParameter.Currency, currency);
                }
                if (amount < 0) {
                    GALogger.w("Validation fail - business event - amount. Cannot be less than 0. Failed amount: " + amount);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidAmount, EGASdkErrorParameter.Amount, amount + "");
                }
                if (!GAValidator.validateShortString(cartType, true)) {
                    GALogger.w("Validation fail - business event - cartType. Cannot be above 32 length. String: " + cartType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidShortString, EGASdkErrorParameter.CartType, cartType);
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - business event - itemId. Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemId, itemId);
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - business event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemId, itemId);
                }
                return null;
            };
            GAValidator.validateResourceEvent = function (flowType, currency, amount, itemType, itemId, availableCurrencies, availableItemTypes) {
                if (flowType == gameanalytics.EGAResourceFlowType.Undefined) {
                    GALogger.w("Validation fail - resource event - flowType: Invalid flow type.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidFlowType, EGASdkErrorParameter.FlowType, "");
                }
                if (!currency) {
                    GALogger.w("Validation fail - resource event - currency: Cannot be (null)");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.StringEmptyOrNull, EGASdkErrorParameter.Currency, "");
                }
                if (!GAUtilities.stringArrayContainsString(availableCurrencies, currency)) {
                    GALogger.w("Validation fail - resource event - currency: Not found in list of pre-defined available resource currencies. String: " + currency);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.NotFoundInAvailableCurrencies, EGASdkErrorParameter.Currency, currency);
                }
                if (!(amount > 0)) {
                    GALogger.w("Validation fail - resource event - amount: Float amount cannot be 0 or negative. Value: " + amount);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidAmount, EGASdkErrorParameter.Amount, amount + "");
                }
                if (!itemType) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null)");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.StringEmptyOrNull, EGASdkErrorParameter.ItemType, "");
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAUtilities.stringArrayContainsString(availableItemTypes, itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Not found in list of pre-defined available resource itemTypes. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.NotFoundInAvailableItemTypes, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemId, itemId);
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemId, itemId);
                }
                return null;
            };
            GAValidator.validateProgressionEvent = function (progressionStatus, progression01, progression02, progression03) {
                if (progressionStatus == gameanalytics.EGAProgressionStatus.Undefined) {
                    GALogger.w("Validation fail - progression event: Invalid progression status.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidProgressionStatus, EGASdkErrorParameter.ProgressionStatus, "");
                }
                if (progression03 && !(progression02 || !progression01)) {
                    GALogger.w("Validation fail - progression event: 03 found but 01+02 are invalid. Progression must be set as either 01, 01+02 or 01+02+03.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, progression01 + ":" + progression02 + ":" + progression03);
                }
                else if (progression02 && !progression01) {
                    GALogger.w("Validation fail - progression event: 02 found but not 01. Progression must be set as either 01, 01+02 or 01+02+03");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, progression01 + ":" + progression02 + ":" + progression03);
                }
                else if (!progression01) {
                    GALogger.w("Validation fail - progression event: progression01 not valid. Progressions must be set as either 01, 01+02 or 01+02+03");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, (progression01 ? progression01 : "") + ":" + (progression02 ? progression02 : "") + ":" + (progression03 ? progression03 : ""));
                }
                if (!GAValidator.validateEventPartLength(progression01, false)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot be (null), empty or above 64 characters. String: " + progression01);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression01, progression01);
                }
                if (!GAValidator.validateEventPartCharacters(progression01)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression01);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression01, progression01);
                }
                if (progression02) {
                    if (!GAValidator.validateEventPartLength(progression02, true)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot be empty or above 64 characters. String: " + progression02);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression02, progression02);
                    }
                    if (!GAValidator.validateEventPartCharacters(progression02)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression02);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression02, progression02);
                    }
                }
                if (progression03) {
                    if (!GAValidator.validateEventPartLength(progression03, true)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot be empty or above 64 characters. String: " + progression03);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression03, progression03);
                    }
                    if (!GAValidator.validateEventPartCharacters(progression03)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression03);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression03, progression03);
                    }
                }
                return null;
            };
            GAValidator.validateDesignEvent = function (eventId) {
                if (!GAValidator.validateEventIdLength(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Cannot be (null) or empty. Only 5 event parts allowed seperated by :. Each part need to be 64 characters or less. String: " + eventId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.DesignEvent, EGASdkErrorAction.InvalidEventIdLength, EGASdkErrorParameter.EventId, eventId);
                }
                if (!GAValidator.validateEventIdCharacters(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Non valid characters. Only allowed A-z, 0-9, -_., ()!?. String: " + eventId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.DesignEvent, EGASdkErrorAction.InvalidEventIdCharacters, EGASdkErrorParameter.EventId, eventId);
                }
                return null;
            };
            GAValidator.validateErrorEvent = function (severity, message) {
                if (severity == gameanalytics.EGAErrorSeverity.Undefined) {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ErrorEvent, EGASdkErrorAction.InvalidSeverity, EGASdkErrorParameter.Severity, "");
                }
                if (!GAValidator.validateLongString(message, true)) {
                    GALogger.w("Validation fail - error event - message: Message cannot be above 8192 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ErrorEvent, EGASdkErrorAction.InvalidLongString, EGASdkErrorParameter.Message, message);
                }
                return null;
            };
            GAValidator.validateAdEvent = function (adAction, adType, adSdkName, adPlacement) {
                if (adAction == gameanalytics.EGAAdAction.Undefined) {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidAdAction, EGASdkErrorParameter.AdAction, "");
                }
                if (adType == gameanalytics.EGAAdType.Undefined) {
                    GALogger.w("Validation fail - ad event - adType: Ad type was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidAdType, EGASdkErrorParameter.AdType, "");
                }
                if (!GAValidator.validateShortString(adSdkName, false)) {
                    GALogger.w("Validation fail - ad event - message: Ad SDK name cannot be above 32 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidShortString, EGASdkErrorParameter.AdSdkName, adSdkName);
                }
                if (!GAValidator.validateString(adPlacement, false)) {
                    GALogger.w("Validation fail - ad event - message: Ad placement cannot be above 64 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidString, EGASdkErrorParameter.AdPlacement, adPlacement);
                }
                return null;
            };
            GAValidator.validateSdkErrorEvent = function (gameKey, gameSecret, category, area, action) {
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    return false;
                }
                if (category === EGASdkErrorCategory.Undefined) {
                    GALogger.w("Validation fail - sdk error event - type: Category was unsupported value.");
                    return false;
                }
                if (area === EGASdkErrorArea.Undefined) {
                    GALogger.w("Validation fail - sdk error event - type: Area was unsupported value.");
                    return false;
                }
                if (action === EGASdkErrorAction.Undefined) {
                    GALogger.w("Validation fail - sdk error event - type: Action was unsupported value.");
                    return false;
                }
                return true;
            };
            GAValidator.validateKeys = function (gameKey, gameSecret) {
                if (GAUtilities.stringMatch(gameKey, /^[A-z0-9]{32}$/)) {
                    if (GAUtilities.stringMatch(gameSecret, /^[A-z0-9]{40}$/)) {
                        return true;
                    }
                }
                return false;
            };
            GAValidator.validateCurrency = function (currency) {
                if (!currency) {
                    return false;
                }
                if (!GAUtilities.stringMatch(currency, /^[A-Z]{3}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventPartLength = function (eventPart, allowNull) {
                if (allowNull && !eventPart) {
                    return true;
                }
                if (!eventPart) {
                    return false;
                }
                if (eventPart.length > 64) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventPartCharacters = function (eventPart) {
                if (!GAUtilities.stringMatch(eventPart, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventIdLength = function (eventId) {
                if (!eventId) {
                    return false;
                }
                if (!GAUtilities.stringMatch(eventId, /^[^:]{1,64}(?::[^:]{1,64}){0,4}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventIdCharacters = function (eventId) {
                if (!eventId) {
                    return false;
                }
                if (!GAUtilities.stringMatch(eventId, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}(:[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}){0,4}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateAndCleanInitRequestResponse = function (initResponse, configsCreated) {
                if (initResponse == null) {
                    GALogger.w("validateInitRequestResponse failed - no response dictionary.");
                    return null;
                }
                var validatedDict = {};
                try {
                    var serverTsNumber = initResponse["server_ts"];
                    if (serverTsNumber > 0) {
                        validatedDict["server_ts"] = serverTsNumber;
                    }
                    else {
                        GALogger.w("validateInitRequestResponse failed - invalid value in 'server_ts' field.");
                        return null;
                    }
                }
                catch (e) {
                    GALogger.w("validateInitRequestResponse failed - invalid type in 'server_ts' field. type=" + typeof initResponse["server_ts"] + ", value=" + initResponse["server_ts"] + ", " + e);
                    return null;
                }
                if (configsCreated) {
                    try {
                        var configurations = initResponse["configs"];
                        validatedDict["configs"] = configurations;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs' field. type=" + typeof initResponse["configs"] + ", value=" + initResponse["configs"] + ", " + e);
                        return null;
                    }
                    try {
                        var configs_hash = initResponse["configs_hash"];
                        validatedDict["configs_hash"] = configs_hash;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs_hash' field. type=" + typeof initResponse["configs_hash"] + ", value=" + initResponse["configs_hash"] + ", " + e);
                        return null;
                    }
                    try {
                        var ab_id = initResponse["ab_id"];
                        validatedDict["ab_id"] = ab_id;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_id' field. type=" + typeof initResponse["ab_id"] + ", value=" + initResponse["ab_id"] + ", " + e);
                        return null;
                    }
                    try {
                        var ab_variant_id = initResponse["ab_variant_id"];
                        validatedDict["ab_variant_id"] = ab_variant_id;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_variant_id' field. type=" + typeof initResponse["ab_variant_id"] + ", value=" + initResponse["ab_variant_id"] + ", " + e);
                        return null;
                    }
                }
                return validatedDict;
            };
            GAValidator.validateBuild = function (build) {
                if (!GAValidator.validateShortString(build, false)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateSdkWrapperVersion = function (wrapperVersion) {
                if (!GAUtilities.stringMatch(wrapperVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold|godot|flutter) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEngineVersion = function (engineVersion) {
                if (!engineVersion || !GAUtilities.stringMatch(engineVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold|godot) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateUserId = function (uId) {
                if (!GAValidator.validateString(uId, false)) {
                    GALogger.w("Validation fail - user id: id cannot be (null), empty or above 64 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateShortString = function (shortString, canBeEmpty) {
                if (canBeEmpty && !shortString) {
                    return true;
                }
                if (!shortString || shortString.length > 32) {
                    return false;
                }
                return true;
            };
            GAValidator.validateString = function (s, canBeEmpty) {
                if (canBeEmpty && !s) {
                    return true;
                }
                if (!s || s.length > 64) {
                    return false;
                }
                return true;
            };
            GAValidator.validateLongString = function (longString, canBeEmpty) {
                if (canBeEmpty && !longString) {
                    return true;
                }
                if (!longString || longString.length > 8192) {
                    return false;
                }
                return true;
            };
            GAValidator.validateConnectionType = function (connectionType) {
                return GAUtilities.stringMatch(connectionType, /^(wwan|wifi|lan|offline)$/);
            };
            GAValidator.validateCustomDimensions = function (customDimensions) {
                return GAValidator.validateArrayOfStrings(20, 32, false, "custom dimensions", customDimensions);
            };
            GAValidator.validateResourceCurrencies = function (resourceCurrencies) {
                if (!GAValidator.validateArrayOfStrings(20, 64, false, "resource currencies", resourceCurrencies)) {
                    return false;
                }
                for (var i = 0; i < resourceCurrencies.length; ++i) {
                    if (!GAUtilities.stringMatch(resourceCurrencies[i], /^[A-Za-z]+$/)) {
                        GALogger.w("resource currencies validation failed: a resource currency can only be A-Z, a-z. String was: " + resourceCurrencies[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateResourceItemTypes = function (resourceItemTypes) {
                if (!GAValidator.validateArrayOfStrings(20, 32, false, "resource item types", resourceItemTypes)) {
                    return false;
                }
                for (var i = 0; i < resourceItemTypes.length; ++i) {
                    if (!GAValidator.validateEventPartCharacters(resourceItemTypes[i])) {
                        GALogger.w("resource item types validation failed: a resource item type cannot contain other characters than A-z, 0-9, -_., ()!?. String was: " + resourceItemTypes[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateDimension01 = function (dimension01, availableDimensions) {
                if (!dimension01) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension01)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateDimension02 = function (dimension02, availableDimensions) {
                if (!dimension02) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension02)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateDimension03 = function (dimension03, availableDimensions) {
                if (!dimension03) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension03)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateArrayOfStrings = function (maxCount, maxStringLength, allowNoValues, logTag, arrayOfStrings) {
                var arrayTag = logTag;
                if (!arrayTag) {
                    arrayTag = "Array";
                }
                if (!arrayOfStrings) {
                    GALogger.w(arrayTag + " validation failed: array cannot be null. ");
                    return false;
                }
                if (allowNoValues == false && arrayOfStrings.length == 0) {
                    GALogger.w(arrayTag + " validation failed: array cannot be empty. ");
                    return false;
                }
                if (maxCount > 0 && arrayOfStrings.length > maxCount) {
                    GALogger.w(arrayTag + " validation failed: array cannot exceed " + maxCount + " values. It has " + arrayOfStrings.length + " values.");
                    return false;
                }
                for (var i = 0; i < arrayOfStrings.length; ++i) {
                    var stringLength = !arrayOfStrings[i] ? 0 : arrayOfStrings[i].length;
                    if (stringLength === 0) {
                        GALogger.w(arrayTag + " validation failed: contained an empty string. Array=" + JSON.stringify(arrayOfStrings));
                        return false;
                    }
                    if (maxStringLength > 0 && stringLength > maxStringLength) {
                        GALogger.w(arrayTag + " validation failed: a string exceeded max allowed length (which is: " + maxStringLength + "). String was: " + arrayOfStrings[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateClientTs = function (clientTs) {
                if (clientTs < (0) || clientTs > (99999999999)) {
                    return false;
                }
                return true;
            };
            return GAValidator;
        }());
        validators.GAValidator = GAValidator;
    })(validators = gameanalytics.validators || (gameanalytics.validators = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var device;
    (function (device) {
        var NameValueVersion = (function () {
            function NameValueVersion(name, value, version) {
                this.name = name;
                this.value = value;
                this.version = version;
            }
            return NameValueVersion;
        }());
        device.NameValueVersion = NameValueVersion;
        var NameVersion = (function () {
            function NameVersion(name, version) {
                this.name = name;
                this.version = version;
            }
            return NameVersion;
        }());
        device.NameVersion = NameVersion;
        var GADevice = (function () {
            function GADevice() {
            }
            GADevice.touch = function () {
            };
            GADevice.getRelevantSdkVersion = function () {
                if (GADevice.sdkGameEngineVersion) {
                    return GADevice.sdkGameEngineVersion;
                }
                return GADevice.sdkWrapperVersion;
            };
            GADevice.getConnectionType = function () {
                return GADevice.connectionType;
            };
            GADevice.updateConnectionType = function () {
                if (navigator.onLine) {
                    if (GADevice.buildPlatform === "ios" || GADevice.buildPlatform === "android") {
                        GADevice.connectionType = "wwan";
                    }
                    else {
                        GADevice.connectionType = "lan";
                    }
                }
                else {
                    GADevice.connectionType = "offline";
                }
            };
            GADevice.getOSVersionString = function () {
                return GADevice.buildPlatform + " " + GADevice.osVersionPair.version;
            };
            GADevice.runtimePlatformToString = function () {
                return GADevice.osVersionPair.name;
            };
            GADevice.getBrowserVersionString = function () {
                var ua = navigator.userAgent;
                var tem;
                var M = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident|fbav(?=\/))\/?\s*(\d+)/i) || [];
                if (M.length == 0) {
                    if (GADevice.buildPlatform === "ios") {
                        return "webkit_" + GADevice.osVersion;
                    }
                }
                if (/trident/i.test(M[1])) {
                    tem = /\brv[ :]+(\d+)/g.exec(ua) || [];
                    return 'IE ' + (tem[1] || '');
                }
                if (M[1] === 'Chrome') {
                    tem = ua.match(/\b(OPR|Edge|UBrowser)\/(\d+)/);
                    if (tem != null) {
                        return tem.slice(1).join(' ').replace('OPR', 'Opera').replace('UBrowser', 'UC').toLowerCase();
                    }
                }
                if (M[1] && M[1].toLowerCase() === 'fbav') {
                    M[1] = "facebook";
                    if (M[2]) {
                        return "facebook " + M[2];
                    }
                }
                var MString = M[2] ? [M[1], M[2]] : [navigator.appName, navigator.appVersion, '-?'];
                if ((tem = ua.match(/version\/(\d+)/i)) != null) {
                    MString.splice(1, 1, tem[1]);
                }
                return MString.join(' ').toLowerCase();
            };
            GADevice.getDeviceModel = function () {
                var result = "unknown";
                return result;
            };
            GADevice.getDeviceManufacturer = function () {
                var result = "unknown";
                return result;
            };
            GADevice.matchItem = function (agent, data) {
                var result = new NameVersion("unknown", "0.0.0");
                var i = 0;
                var j = 0;
                var regex;
                var regexv;
                var match;
                var matches;
                var mathcesResult;
                var version;
                for (i = 0; i < data.length; i += 1) {
                    regex = new RegExp(data[i].value, 'i');
                    match = regex.test(agent);
                    if (match) {
                        regexv = new RegExp(data[i].version + '[- /:;]([\\d._]+)', 'i');
                        matches = agent.match(regexv);
                        version = '';
                        if (matches) {
                            if (matches[1]) {
                                mathcesResult = matches[1];
                            }
                        }
                        if (mathcesResult) {
                            var matchesArray = mathcesResult.split(/[._]+/);
                            for (j = 0; j < Math.min(matchesArray.length, 3); j += 1) {
                                version += matchesArray[j] + (j < Math.min(matchesArray.length, 3) - 1 ? '.' : '');
                            }
                        }
                        else {
                            version = '0.0.0';
                        }
                        result.name = data[i].name;
                        result.version = version;
                        return result;
                    }
                }
                return result;
            };
            GADevice.sdkWrapperVersion = "javascript 5.0.0";
            GADevice.osVersionPair = GADevice.matchItem([
                navigator.platform,
                navigator.userAgent,
                navigator.appVersion,
                navigator.vendor
            ].join(' '), [
                new NameValueVersion("windows_phone", "Windows Phone", "OS"),
                new NameValueVersion("windows", "Win", "NT"),
                new NameValueVersion("ios", "iPhone", "OS"),
                new NameValueVersion("ios", "iPad", "OS"),
                new NameValueVersion("ios", "iPod", "OS"),
                new NameValueVersion("android", "Android", "Android"),
                new NameValueVersion("blackBerry", "BlackBerry", "/"),
                new NameValueVersion("mac_osx", "Mac", "OS X"),
                new NameValueVersion("tizen", "Tizen", "Tizen"),
                new NameValueVersion("linux", "Linux", "rv"),
                new NameValueVersion("kai_os", "KAIOS", "KAIOS")
            ]);
            GADevice.buildPlatform = GADevice.runtimePlatformToString();
            GADevice.deviceModel = GADevice.getDeviceModel();
            GADevice.deviceManufacturer = GADevice.getDeviceManufacturer();
            GADevice.osVersion = GADevice.getOSVersionString();
            GADevice.browserVersion = GADevice.getBrowserVersionString();
            return GADevice;
        }());
        device.GADevice = GADevice;
    })(device = gameanalytics.device || (gameanalytics.device = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var store;
    (function (store_1) {
        var GALogger = gameanalytics.logging.GALogger;
        var EGAStoreArgsOperator;
        (function (EGAStoreArgsOperator) {
            EGAStoreArgsOperator[EGAStoreArgsOperator["Equal"] = 0] = "Equal";
            EGAStoreArgsOperator[EGAStoreArgsOperator["LessOrEqual"] = 1] = "LessOrEqual";
            EGAStoreArgsOperator[EGAStoreArgsOperator["NotEqual"] = 2] = "NotEqual";
        })(EGAStoreArgsOperator = store_1.EGAStoreArgsOperator || (store_1.EGAStoreArgsOperator = {}));
        var EGAStore;
        (function (EGAStore) {
            EGAStore[EGAStore["Events"] = 0] = "Events";
            EGAStore[EGAStore["Sessions"] = 1] = "Sessions";
            EGAStore[EGAStore["Progression"] = 2] = "Progression";
        })(EGAStore = store_1.EGAStore || (store_1.EGAStore = {}));
        var GAStore = (function () {
            function GAStore() {
                this.eventsStore = [];
                this.sessionsStore = [];
                this.progressionStore = [];
                this.storeItems = {};
                try {
                    if (typeof localStorage === 'object') {
                        localStorage.setItem('testingLocalStorage', 'yes');
                        localStorage.removeItem('testingLocalStorage');
                        GAStore.storageAvailable = true;
                    }
                    else {
                        GAStore.storageAvailable = false;
                    }
                }
                catch (e) {
                }
                GALogger.d("Storage is available?: " + GAStore.storageAvailable);
            }
            GAStore.isStorageAvailable = function () {
                return GAStore.storageAvailable;
            };
            GAStore.isStoreTooLargeForEvents = function () {
                return GAStore.instance.eventsStore.length + GAStore.instance.sessionsStore.length > GAStore.MaxNumberOfEntries;
            };
            GAStore.select = function (store, args, sort, maxCount) {
                if (args === void 0) { args = []; }
                if (sort === void 0) { sort = false; }
                if (maxCount === void 0) { maxCount = 0; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return null;
                }
                var result = [];
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var add = true;
                    for (var j = 0; j < args.length; ++j) {
                        var argsEntry = args[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        add = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        add = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        add = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        add = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            add = false;
                        }
                        if (!add) {
                            break;
                        }
                    }
                    if (add) {
                        result.push(entry);
                    }
                }
                if (sort) {
                    result.sort(function (a, b) {
                        return a["client_ts"] - b["client_ts"];
                    });
                }
                if (maxCount > 0 && result.length > maxCount) {
                    result = result.slice(0, maxCount + 1);
                }
                return result;
            };
            GAStore.update = function (store, setArgs, whereArgs) {
                if (whereArgs === void 0) { whereArgs = []; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return false;
                }
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var update = true;
                    for (var j = 0; j < whereArgs.length; ++j) {
                        var argsEntry = whereArgs[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        update = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        update = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        update = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        update = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            update = false;
                        }
                        if (!update) {
                            break;
                        }
                    }
                    if (update) {
                        for (var j = 0; j < setArgs.length; ++j) {
                            var setArgsEntry = setArgs[j];
                            entry[setArgsEntry[0]] = setArgsEntry[1];
                        }
                    }
                }
                return true;
            };
            GAStore["delete"] = function (store, args) {
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return;
                }
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var del = true;
                    for (var j = 0; j < args.length; ++j) {
                        var argsEntry = args[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        del = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        del = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        del = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        del = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            del = false;
                        }
                        if (!del) {
                            break;
                        }
                    }
                    if (del) {
                        currentStore.splice(i, 1);
                        --i;
                    }
                }
            };
            GAStore.insert = function (store, newEntry, replace, replaceKey) {
                if (replace === void 0) { replace = false; }
                if (replaceKey === void 0) { replaceKey = null; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return;
                }
                if (replace) {
                    if (!replaceKey) {
                        return;
                    }
                    var replaced = false;
                    for (var i = 0; i < currentStore.length; ++i) {
                        var entry = currentStore[i];
                        if (entry[replaceKey] == newEntry[replaceKey]) {
                            for (var s in newEntry) {
                                entry[s] = newEntry[s];
                            }
                            replaced = true;
                            break;
                        }
                    }
                    if (!replaced) {
                        currentStore.push(newEntry);
                    }
                }
                else {
                    currentStore.push(newEntry);
                }
            };
            GAStore.save = function (gameKey) {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot save.");
                    return;
                }
                localStorage.setItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.EventsStoreKey), JSON.stringify(GAStore.instance.eventsStore));
                localStorage.setItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.SessionsStoreKey), JSON.stringify(GAStore.instance.sessionsStore));
                localStorage.setItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ProgressionStoreKey), JSON.stringify(GAStore.instance.progressionStore));
                localStorage.setItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ItemsStoreKey), JSON.stringify(GAStore.instance.storeItems));
            };
            GAStore.load = function (gameKey) {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot load.");
                    return;
                }
                try {
                    GAStore.instance.eventsStore = JSON.parse(localStorage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.EventsStoreKey)));
                    if (!GAStore.instance.eventsStore) {
                        GAStore.instance.eventsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'events' store. Using empty store.");
                    GAStore.instance.eventsStore = [];
                }
                try {
                    GAStore.instance.sessionsStore = JSON.parse(localStorage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.SessionsStoreKey)));
                    if (!GAStore.instance.sessionsStore) {
                        GAStore.instance.sessionsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'sessions' store. Using empty store.");
                    GAStore.instance.sessionsStore = [];
                }
                try {
                    GAStore.instance.progressionStore = JSON.parse(localStorage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ProgressionStoreKey)));
                    if (!GAStore.instance.progressionStore) {
                        GAStore.instance.progressionStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'progression' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
                try {
                    GAStore.instance.storeItems = JSON.parse(localStorage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ItemsStoreKey)));
                    if (!GAStore.instance.storeItems) {
                        GAStore.instance.storeItems = {};
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'items' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
            };
            GAStore.setItem = function (gameKey, key, value) {
                var keyWithPrefix = GAStore.StringFormat(GAStore.KeyFormat, gameKey, key);
                if (!value) {
                    if (keyWithPrefix in GAStore.instance.storeItems) {
                        delete GAStore.instance.storeItems[keyWithPrefix];
                    }
                }
                else {
                    GAStore.instance.storeItems[keyWithPrefix] = value;
                }
            };
            GAStore.getItem = function (gameKey, key) {
                var keyWithPrefix = GAStore.StringFormat(GAStore.KeyFormat, gameKey, key);
                if (keyWithPrefix in GAStore.instance.storeItems) {
                    return GAStore.instance.storeItems[keyWithPrefix];
                }
                else {
                    return null;
                }
            };
            GAStore.getStore = function (store) {
                switch (store) {
                    case EGAStore.Events:
                        {
                            return GAStore.instance.eventsStore;
                        }
                    case EGAStore.Sessions:
                        {
                            return GAStore.instance.sessionsStore;
                        }
                    case EGAStore.Progression:
                        {
                            return GAStore.instance.progressionStore;
                        }
                    default:
                        {
                            GALogger.w("GAStore.getStore(): Cannot find store: " + store);
                            return null;
                        }
                }
            };
            GAStore.instance = new GAStore();
            GAStore.MaxNumberOfEntries = 2000;
            GAStore.StringFormat = function (str) {
                var args = [];
                for (var _i = 1; _i < arguments.length; _i++) {
                    args[_i - 1] = arguments[_i];
                }
                return str.replace(/{(\d+)}/g, function (_, index) { return args[index] || ''; });
            };
            GAStore.KeyFormat = "GA::{0}::{1}";
            GAStore.EventsStoreKey = "ga_event";
            GAStore.SessionsStoreKey = "ga_session";
            GAStore.ProgressionStoreKey = "ga_progression";
            GAStore.ItemsStoreKey = "ga_items";
            return GAStore;
        }());
        store_1.GAStore = GAStore;
    })(store = gameanalytics.store || (gameanalytics.store = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var state;
    (function (state) {
        var GAValidator = gameanalytics.validators.GAValidator;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GALogger = gameanalytics.logging.GALogger;
        var GAStore = gameanalytics.store.GAStore;
        var GADevice = gameanalytics.device.GADevice;
        var EGAStore = gameanalytics.store.EGAStore;
        var EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        var GAState = (function () {
            function GAState() {
                this.availableCustomDimensions01 = [];
                this.availableCustomDimensions02 = [];
                this.availableCustomDimensions03 = [];
                this.currentGlobalCustomEventFields = {};
                this.availableResourceCurrencies = [];
                this.availableResourceItemTypes = [];
                this.configurations = {};
                this.trackingConfigurations = [];
                this.remoteConfigsListeners = [];
                this.beforeUnloadListeners = [];
                this.sdkConfigDefault = {};
                this.sdkConfig = {};
                this.progressionTries = {};
                this._isEventSubmissionEnabled = true;
                this.isUnloading = false;
            }
            GAState.setUserId = function (userId) {
                GAState.instance.userId = userId;
                GAState.cacheIdentifier();
            };
            GAState.getIdentifier = function () {
                return GAState.instance.identifier;
            };
            GAState.setExtUserId = function (uid) {
                GAState.instance.extUserId = uid;
            };
            GAState.getExtUserId = function () {
                return GAState.instance.extUserId;
            };
            GAState.isInitialized = function () {
                return GAState.instance.initialized;
            };
            GAState.setInitialized = function (value) {
                GAState.instance.initialized = value;
            };
            GAState.getSessionStart = function () {
                return GAState.instance.sessionStart;
            };
            GAState.getSessionNum = function () {
                return GAState.instance.sessionNum;
            };
            GAState.getTransactionNum = function () {
                return GAState.instance.transactionNum;
            };
            GAState.getSessionId = function () {
                return GAState.instance.sessionId;
            };
            GAState.getCurrentCustomDimension01 = function () {
                return GAState.instance.currentCustomDimension01;
            };
            GAState.getCurrentCustomDimension02 = function () {
                return GAState.instance.currentCustomDimension02;
            };
            GAState.getCurrentCustomDimension03 = function () {
                return GAState.instance.currentCustomDimension03;
            };
            GAState.getGameKey = function () {
                return GAState.instance.gameKey;
            };
            GAState.getGameSecret = function () {
                return GAState.instance.gameSecret;
            };
            GAState.getAvailableCustomDimensions01 = function () {
                return GAState.instance.availableCustomDimensions01;
            };
            GAState.setAvailableCustomDimensions01 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions01 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom01 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableCustomDimensions02 = function () {
                return GAState.instance.availableCustomDimensions02;
            };
            GAState.setAvailableCustomDimensions02 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions02 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom02 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableCustomDimensions03 = function () {
                return GAState.instance.availableCustomDimensions03;
            };
            GAState.setAvailableCustomDimensions03 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions03 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom03 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableResourceCurrencies = function () {
                return GAState.instance.availableResourceCurrencies;
            };
            GAState.setAvailableResourceCurrencies = function (value) {
                if (!GAValidator.validateResourceCurrencies(value)) {
                    return;
                }
                GAState.instance.availableResourceCurrencies = value;
                GALogger.i("Set available resource currencies: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableResourceItemTypes = function () {
                return GAState.instance.availableResourceItemTypes;
            };
            GAState.setAvailableResourceItemTypes = function (value) {
                if (!GAValidator.validateResourceItemTypes(value)) {
                    return;
                }
                GAState.instance.availableResourceItemTypes = value;
                GALogger.i("Set available resource item types: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getBuild = function () {
                return GAState.instance.build;
            };
            GAState.setBuild = function (value) {
                GAState.instance.build = value;
                GALogger.i("Set build version: " + value);
            };
            GAState.getUseManualSessionHandling = function () {
                return GAState.instance.useManualSessionHandling;
            };
            GAState.isEventSubmissionEnabled = function () {
                return GAState.instance._isEventSubmissionEnabled;
            };
            GAState.getABTestingId = function () {
                return GAState.instance.abId;
            };
            GAState.getABTestingVariantId = function () {
                return GAState.instance.abVariantId;
            };
            GAState.prototype.setDefaultId = function (value) {
                this.defaultUserId = !value ? "" : value;
                GAState.cacheIdentifier();
            };
            GAState.getDefaultId = function () {
                return GAState.instance.defaultUserId;
            };
            GAState.getSdkConfig = function () {
                {
                    var first;
                    var count = 0;
                    for (var json in GAState.instance.sdkConfig) {
                        if (count === 0) {
                            first = json;
                        }
                        ++count;
                    }
                    if (first && count > 0) {
                        return GAState.instance.sdkConfig;
                    }
                }
                {
                    var first;
                    var count = 0;
                    for (var json in GAState.instance.sdkConfigCached) {
                        if (count === 0) {
                            first = json;
                        }
                        ++count;
                    }
                    if (first && count > 0) {
                        return GAState.instance.sdkConfigCached;
                    }
                }
                return GAState.instance.sdkConfigDefault;
            };
            GAState.isEnabled = function () {
                if (!GAState.instance.initAuthorized) {
                    return false;
                }
                else {
                    return true;
                }
            };
            GAState.setCustomDimension01 = function (dimension) {
                GAState.instance.currentCustomDimension01 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension01Key, dimension);
                GALogger.i("Set custom01 dimension value: " + dimension);
            };
            GAState.setCustomDimension02 = function (dimension) {
                GAState.instance.currentCustomDimension02 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension02Key, dimension);
                GALogger.i("Set custom02 dimension value: " + dimension);
            };
            GAState.setCustomDimension03 = function (dimension) {
                GAState.instance.currentCustomDimension03 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension03Key, dimension);
                GALogger.i("Set custom03 dimension value: " + dimension);
            };
            GAState.incrementSessionNum = function () {
                var sessionNumInt = GAState.getSessionNum() + 1;
                GAState.instance.sessionNum = sessionNumInt;
            };
            GAState.incrementTransactionNum = function () {
                var transactionNumInt = GAState.getTransactionNum() + 1;
                GAState.instance.transactionNum = transactionNumInt;
            };
            GAState.incrementProgressionTries = function (progression) {
                var tries = GAState.getProgressionTries(progression) + 1;
                GAState.instance.progressionTries[progression] = tries;
                var values = {};
                values["progression"] = progression;
                values["tries"] = tries;
                GAStore.insert(EGAStore.Progression, values, true, "progression");
            };
            GAState.getProgressionTries = function (progression) {
                if (progression in GAState.instance.progressionTries) {
                    return GAState.instance.progressionTries[progression];
                }
                else {
                    return 0;
                }
            };
            GAState.clearProgressionTries = function (progression) {
                if (progression in GAState.instance.progressionTries) {
                    delete GAState.instance.progressionTries[progression];
                }
                var parms = [];
                parms.push(["progression", EGAStoreArgsOperator.Equal, progression]);
                GAStore["delete"](EGAStore.Progression, parms);
            };
            GAState.setKeys = function (gameKey, gameSecret) {
                GAState.instance.gameKey = gameKey;
                GAState.instance.gameSecret = gameSecret;
            };
            GAState.setManualSessionHandling = function (flag) {
                GAState.instance.useManualSessionHandling = flag;
                GALogger.i("Use manual session handling: " + flag);
            };
            GAState.setEnabledEventSubmission = function (flag) {
                GAState.instance._isEventSubmissionEnabled = flag;
            };
            GAState.getEventAnnotations = function () {
                var annotations = {};
                annotations["v"] = 2;
                annotations["event_uuid"] = GAUtilities.createGuid();
                annotations["user_id"] = GAState.instance.identifier;
                if (GAState.instance.extUserId && GAState.instance.extUserId.length > 0) {
                    annotations["user_id_ext"] = GAState.instance.extUserId;
                }
                annotations["client_ts"] = GAState.getClientTsAdjusted();
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                annotations["os_version"] = GADevice.osVersion;
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                annotations["device"] = GADevice.deviceModel;
                annotations["browser_version"] = GADevice.browserVersion;
                annotations["platform"] = GADevice.buildPlatform;
                annotations["session_id"] = GAState.instance.sessionId;
                annotations[GAState.SessionNumKey] = GAState.instance.sessionNum;
                var connection_type = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type)) {
                    annotations["connection_type"] = connection_type;
                }
                if (GADevice.gameEngineVersion) {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }
                if (GAState.instance.trackingConfigurations && GAState.instance.trackingConfigurations.length > 0) {
                    annotations["configurations_v3"] = GAState.instance.trackingConfigurations;
                }
                if (GAState.instance.abId) {
                    annotations["ab_id"] = GAState.instance.abId;
                }
                if (GAState.instance.abVariantId) {
                    annotations["ab_variant_id"] = GAState.instance.abVariantId;
                }
                if (GAState.instance.build) {
                    annotations["build"] = GAState.instance.build;
                }
                return annotations;
            };
            GAState.getSdkErrorEventAnnotations = function () {
                var annotations = {};
                annotations["v"] = 2;
                annotations["event_uuid"] = GAUtilities.createGuid();
                annotations["category"] = GAState.CategorySdkError;
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                annotations["os_version"] = GADevice.osVersion;
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                annotations["device"] = GADevice.deviceModel;
                annotations["platform"] = GADevice.buildPlatform;
                var connection_type = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type)) {
                    annotations["connection_type"] = connection_type;
                }
                if (GADevice.gameEngineVersion) {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }
                return annotations;
            };
            GAState.getInitAnnotations = function () {
                var initAnnotations = {};
                if (!GAState.getIdentifier()) {
                    GAState.cacheIdentifier();
                }
                GAStore.setItem(GAState.getGameKey(), GAState.LastUsedIdentifierKey, GAState.getIdentifier());
                initAnnotations["user_id"] = GAState.getIdentifier();
                initAnnotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                initAnnotations["os_version"] = GADevice.osVersion;
                initAnnotations["platform"] = GADevice.buildPlatform;
                if (GAState.getBuild()) {
                    initAnnotations["build"] = GAState.getBuild();
                }
                else {
                    initAnnotations["build"] = null;
                }
                initAnnotations["session_num"] = GAState.getSessionNum();
                initAnnotations["random_salt"] = GAState.getSessionNum();
                return initAnnotations;
            };
            GAState.getClientTsAdjusted = function () {
                var clientTs = GAUtilities.timeIntervalSince1970();
                var clientTsAdjustedInteger = clientTs + GAState.instance.clientServerTimeOffset;
                if (GAValidator.validateClientTs(clientTsAdjustedInteger)) {
                    return clientTsAdjustedInteger;
                }
                else {
                    return clientTs;
                }
            };
            GAState.sessionIsStarted = function () {
                return GAState.instance.sessionStart != 0;
            };
            GAState.cacheIdentifier = function () {
                if (GAState.instance.userId) {
                    GAState.instance.identifier = GAState.instance.userId;
                }
                else if (GAState.instance.defaultUserId) {
                    GAState.instance.identifier = GAState.instance.defaultUserId;
                }
                GALogger.d("identifier, {clean:" + GAState.instance.identifier + "}");
            };
            GAState.ensurePersistedStates = function () {
                if (GAStore.isStorageAvailable()) {
                    GAStore.load(GAState.getGameKey());
                }
                var instance = GAState.instance;
                instance.setDefaultId(GAStore.getItem(GAState.getGameKey(), GAState.DefaultUserIdKey) != null ? GAStore.getItem(GAState.getGameKey(), GAState.DefaultUserIdKey) : GAUtilities.createGuid());
                instance.sessionNum = GAStore.getItem(GAState.getGameKey(), GAState.SessionNumKey) != null ? Number(GAStore.getItem(GAState.getGameKey(), GAState.SessionNumKey)) : 0.0;
                instance.transactionNum = GAStore.getItem(GAState.getGameKey(), GAState.TransactionNumKey) != null ? Number(GAStore.getItem(GAState.getGameKey(), GAState.TransactionNumKey)) : 0.0;
                if (instance.currentCustomDimension01) {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension01Key, instance.currentCustomDimension01);
                }
                else {
                    instance.currentCustomDimension01 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension01Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension01Key) : "";
                    if (instance.currentCustomDimension01) {
                        GALogger.d("Dimension01 found in cache: " + instance.currentCustomDimension01);
                    }
                }
                if (instance.currentCustomDimension02) {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension02Key, instance.currentCustomDimension02);
                }
                else {
                    instance.currentCustomDimension02 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension02Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension02Key) : "";
                    if (instance.currentCustomDimension02) {
                        GALogger.d("Dimension02 found in cache: " + instance.currentCustomDimension02);
                    }
                }
                if (instance.currentCustomDimension03) {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension03Key, instance.currentCustomDimension03);
                }
                else {
                    instance.currentCustomDimension03 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension03Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension03Key) : "";
                    if (instance.currentCustomDimension03) {
                        GALogger.d("Dimension03 found in cache: " + instance.currentCustomDimension03);
                    }
                }
                var sdkConfigCachedString = GAStore.getItem(GAState.getGameKey(), GAState.SdkConfigCachedKey) != null ? GAStore.getItem(GAState.getGameKey(), GAState.SdkConfigCachedKey) : "";
                if (sdkConfigCachedString) {
                    var sdkConfigCached = JSON.parse(GAUtilities.decode64(sdkConfigCachedString));
                    if (sdkConfigCached) {
                        var lastUsedIdentifier = GAStore.getItem(GAState.getGameKey(), GAState.LastUsedIdentifierKey);
                        GALogger.d("lastUsedIdentifier=" + lastUsedIdentifier + ", GAState.getIdentifier()=" + GAState.getIdentifier());
                        if (lastUsedIdentifier != null && lastUsedIdentifier != GAState.getIdentifier()) {
                            GALogger.w("New identifier spotted compared to last one used, clearing cached configs hash!!");
                            if (sdkConfigCached["configs_hash"]) {
                                delete sdkConfigCached["configs_hash"];
                            }
                        }
                        instance.sdkConfigCached = sdkConfigCached;
                    }
                }
                {
                    var currentSdkConfig = GAState.getSdkConfig();
                    instance.configsHash = currentSdkConfig["configs_hash"] ? currentSdkConfig["configs_hash"] : "";
                    instance.abId = currentSdkConfig["ab_id"] ? currentSdkConfig["ab_id"] : "";
                    instance.abVariantId = currentSdkConfig["ab_variant_id"] ? currentSdkConfig["ab_variant_id"] : "";
                }
                var results_ga_progression = GAStore.select(EGAStore.Progression);
                if (results_ga_progression) {
                    for (var i = 0; i < results_ga_progression.length; ++i) {
                        var result = results_ga_progression[i];
                        if (result) {
                            instance.progressionTries[result["progression"]] = result["tries"];
                        }
                    }
                }
            };
            GAState.calculateServerTimeOffset = function (serverTs) {
                var clientTs = GAUtilities.timeIntervalSince1970();
                return serverTs - clientTs;
            };
            GAState.formatString = function (s, args) {
                var formatted = s;
                for (var i = 0; i < args.length; i++) {
                    var regexp = new RegExp('\\{' + i + '\\}', 'gi');
                    formatted = formatted.replace(regexp, arguments[i]);
                }
                return formatted;
            };
            GAState.validateAndCleanCustomFields = function (fields, errorCallback) {
                if (errorCallback === void 0) { errorCallback = null; }
                var result = {};
                if (fields) {
                    var count = 0;
                    for (var key in fields) {
                        var value = fields[key];
                        if (!key || !value) {
                            var baseMessage = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its key or value is null";
                            var message = GAState.formatString(baseMessage, [key, value]);
                            GALogger.w(message);
                            if (errorCallback) {
                                errorCallback(baseMessage, message);
                            }
                        }
                        else if (count < GAState.MAX_CUSTOM_FIELDS_COUNT) {
                            var regex = new RegExp("^[a-zA-Z0-9_]{1," + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + "}$");
                            if (GAUtilities.stringMatch(key, regex)) {
                                var type = typeof value;
                                if (type === "string" || value instanceof String) {
                                    var valueAsString = value;
                                    if (valueAsString.length <= GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH && valueAsString.length > 0) {
                                        result[key] = valueAsString;
                                        ++count;
                                    }
                                    else {
                                        var baseMessage = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its value is an empty string or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH + ")";
                                        var message = GAState.formatString(baseMessage, [key, value]);
                                        GALogger.w(message);
                                        if (errorCallback) {
                                            errorCallback(baseMessage, message);
                                        }
                                    }
                                }
                                else if (type === "number" || value instanceof Number) {
                                    var valueAsNumber = value;
                                    result[key] = valueAsNumber;
                                    ++count;
                                }
                                else {
                                    var baseMessage = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its value is not a string or number";
                                    var message = GAState.formatString(baseMessage, [key, value]);
                                    GALogger.w(message);
                                    if (errorCallback) {
                                        errorCallback(baseMessage, message);
                                    }
                                }
                            }
                            else {
                                var baseMessage = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its key contains illegal character, is empty or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + ")";
                                var message = GAState.formatString(baseMessage, [key, value]);
                                GALogger.w(message);
                                if (errorCallback) {
                                    errorCallback(baseMessage, message);
                                }
                            }
                        }
                        else {
                            var baseMessage = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because it exceeds the max number of custom fields (" + GAState.MAX_CUSTOM_FIELDS_COUNT + ")";
                            var message = GAState.formatString(baseMessage, [key, value]);
                            GALogger.w(message);
                            if (errorCallback) {
                                errorCallback(baseMessage, message);
                            }
                        }
                    }
                }
                return result;
            };
            GAState.validateAndFixCurrentDimensions = function () {
                if (!GAValidator.validateDimension01(GAState.getCurrentCustomDimension01(), GAState.getAvailableCustomDimensions01())) {
                    GALogger.d("Invalid dimension01 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension01());
                    GAState.setCustomDimension01("");
                }
                if (!GAValidator.validateDimension02(GAState.getCurrentCustomDimension02(), GAState.getAvailableCustomDimensions02())) {
                    GALogger.d("Invalid dimension02 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension02());
                    GAState.setCustomDimension02("");
                }
                if (!GAValidator.validateDimension03(GAState.getCurrentCustomDimension03(), GAState.getAvailableCustomDimensions03())) {
                    GALogger.d("Invalid dimension03 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension03());
                    GAState.setCustomDimension03("");
                }
            };
            GAState.getConfigurationStringValue = function (key, defaultValue) {
                if (GAState.instance.configurations[key]) {
                    return GAState.instance.configurations[key].toString();
                }
                else {
                    return defaultValue;
                }
            };
            GAState.getConfigurationJsonValue = function (key, defaultValue) {
                if (GAState.instance.configurations[key]) {
                    return GAState.instance.configurations[key];
                }
                else {
                    return defaultValue;
                }
            };
            GAState.isRemoteConfigsReady = function () {
                return GAState.instance.remoteConfigsIsReady;
            };
            GAState.addRemoteConfigsListener = function (listener) {
                if (GAState.instance.remoteConfigsListeners.indexOf(listener) < 0) {
                    GAState.instance.remoteConfigsListeners.push(listener);
                }
            };
            GAState.removeRemoteConfigsListener = function (listener) {
                var index = GAState.instance.remoteConfigsListeners.indexOf(listener);
                if (index > -1) {
                    GAState.instance.remoteConfigsListeners.splice(index, 1);
                }
            };
            GAState.getRemoteConfigsContentAsString = function () {
                return JSON.stringify(GAState.instance.configurations);
            };
            GAState.populateConfigurations = function (sdkConfig) {
                var configurations = sdkConfig["configs"];
                GAState.instance.trackingConfigurations = [];
                if (configurations) {
                    GAState.instance.configurations = {};
                    for (var i = 0; i < configurations.length; ++i) {
                        var configuration = configurations[i];
                        if (configuration) {
                            var key = configuration["key"];
                            var value = configuration["value"];
                            var start_ts = configuration["start_ts"] ? configuration["start_ts"] : Number.MIN_VALUE;
                            var end_ts = configuration["end_ts"] ? configuration["end_ts"] : Number.MAX_VALUE;
                            var client_ts_adjusted = GAState.getClientTsAdjusted();
                            if (key && value && client_ts_adjusted > start_ts && client_ts_adjusted < end_ts) {
                                GAState.instance.configurations[key] = value;
                                GALogger.d("configuration added: " + JSON.stringify(configuration));
                            }
                            var trackConfig = {};
                            trackConfig["key"] = configuration["key"];
                            trackConfig["id"] = configuration["id"];
                            trackConfig["vsn"] = configuration["vsn"];
                            this.instance.trackingConfigurations.push(trackConfig);
                        }
                    }
                }
                GAState.instance.remoteConfigsIsReady = true;
                var listeners = GAState.instance.remoteConfigsListeners;
                for (var i = 0; i < listeners.length; ++i) {
                    if (listeners[i]) {
                        listeners[i].onRemoteConfigsUpdated();
                    }
                }
            };
            GAState.addOnBeforeUnloadListener = function (listener) {
                if (GAState.instance.beforeUnloadListeners.indexOf(listener) < 0) {
                    GAState.instance.beforeUnloadListeners.push(listener);
                }
            };
            GAState.removeOnBeforeUnloadListener = function (listener) {
                var index = GAState.instance.beforeUnloadListeners.indexOf(listener);
                if (index > -1) {
                    GAState.instance.beforeUnloadListeners.splice(index, 1);
                }
            };
            GAState.notifyBeforeUnloadListeners = function () {
                var listeners = GAState.instance.beforeUnloadListeners;
                for (var i = 0; i < listeners.length; ++i) {
                    if (listeners[i]) {
                        listeners[i].onBeforeUnload();
                    }
                }
            };
            GAState.CategorySdkError = "sdk_error";
            GAState.MAX_CUSTOM_FIELDS_COUNT = 50;
            GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH = 64;
            GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH = 256;
            GAState.instance = new GAState();
            GAState.DefaultUserIdKey = "default_user_id";
            GAState.SessionNumKey = "session_num";
            GAState.TransactionNumKey = "transaction_num";
            GAState.Dimension01Key = "dimension01";
            GAState.Dimension02Key = "dimension02";
            GAState.Dimension03Key = "dimension03";
            GAState.SdkConfigCachedKey = "sdk_config_cached";
            GAState.LastUsedIdentifierKey = "last_used_identifier";
            return GAState;
        }());
        state.GAState = GAState;
    })(state = gameanalytics.state || (gameanalytics.state = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var tasks;
    (function (tasks) {
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GALogger = gameanalytics.logging.GALogger;
        var SdkErrorTask = (function () {
            function SdkErrorTask() {
            }
            SdkErrorTask.execute = function (url, type, payloadData, secretKey) {
                var now = new Date();
                if (!SdkErrorTask.timestampMap[type]) {
                    SdkErrorTask.timestampMap[type] = now;
                }
                if (!SdkErrorTask.countMap[type]) {
                    SdkErrorTask.countMap[type] = 0;
                }
                var diff = now.getTime() - SdkErrorTask.timestampMap[type].getTime();
                var diffSeconds = diff / 1000;
                if (diffSeconds >= 3600) {
                    SdkErrorTask.timestampMap[type] = now;
                    SdkErrorTask.countMap[type] = 0;
                }
                if (SdkErrorTask.countMap[type] >= SdkErrorTask.MaxCount) {
                    return;
                }
                var hashHmac = GAUtilities.getHmac(secretKey, payloadData);
                var request = new XMLHttpRequest();
                request.onreadystatechange = function () {
                    if (request.readyState === 4) {
                        if (!request.responseText) {
                            GALogger.d("sdk error failed. Might be no connection. Description: " + request.statusText + ", Status code: " + request.status);
                            return;
                        }
                        if (request.status != 200) {
                            GALogger.w("sdk error failed. response code not 200. status code: " + request.status + ", description: " + request.statusText + ", body: " + request.responseText);
                            return;
                        }
                        else {
                            SdkErrorTask.countMap[type] = SdkErrorTask.countMap[type] + 1;
                        }
                    }
                };
                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");
                request.setRequestHeader("Authorization", hashHmac);
                try {
                    request.send(payloadData);
                }
                catch (e) {
                    console.error(e);
                }
            };
            SdkErrorTask.MaxCount = 10;
            SdkErrorTask.countMap = {};
            SdkErrorTask.timestampMap = {};
            return SdkErrorTask;
        }());
        tasks.SdkErrorTask = SdkErrorTask;
    })(tasks = gameanalytics.tasks || (gameanalytics.tasks = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var http;
    (function (http) {
        var GAState = gameanalytics.state.GAState;
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GAValidator = gameanalytics.validators.GAValidator;
        var SdkErrorTask = gameanalytics.tasks.SdkErrorTask;
        var EGASdkErrorCategory = gameanalytics.events.EGASdkErrorCategory;
        var EGASdkErrorArea = gameanalytics.events.EGASdkErrorArea;
        var EGASdkErrorAction = gameanalytics.events.EGASdkErrorAction;
        var EGASdkErrorParameter = gameanalytics.events.EGASdkErrorParameter;
        var GAHTTPApi = (function () {
            function GAHTTPApi() {
                this.protocol = "https";
                this.hostName = "api.gameanalytics.com";
                this.version = "v2";
                this.remoteConfigsVersion = "v1";
                this.baseUrl = this.protocol + "://" + this.hostName + "/" + this.version;
                this.remoteConfigsBaseUrl = this.protocol + "://" + this.hostName + "/remote_configs/" + this.remoteConfigsVersion;
                this.initializeUrlPath = "init";
                this.eventsUrlPath = "events";
                this.useGzip = false;
            }
            GAHTTPApi.prototype.requestInit = function (configsHash, callback) {
                var gameKey = GAState.getGameKey();
                var url = this.remoteConfigsBaseUrl + "/" + this.initializeUrlPath + "?game_key=" + gameKey + "&interval_seconds=0&configs_hash=" + configsHash + "&config_vsn_supported=3";
                GALogger.d("Sending 'init' URL: " + url);
                var initAnnotations = GAState.getInitAnnotations();
                var JSONstring = JSON.stringify(initAnnotations);
                if (!JSONstring) {
                    callback(http.EGAHTTPApiResponse.JsonEncodeFailed, null);
                    return;
                }
                var payloadData = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs = [];
                extraArgs.push(JSONstring);
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.initRequestCallback, callback);
            };
            GAHTTPApi.prototype.sendEventsInArray = function (eventArray, requestId, callback) {
                if (eventArray.length == 0) {
                    GALogger.d("sendEventsInArray called with missing eventArray");
                    return;
                }
                var gameKey = GAState.getGameKey();
                var url = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);
                var JSONstring = JSON.stringify(eventArray);
                if (!JSONstring) {
                    GALogger.d("sendEventsInArray JSON encoding failed of eventArray");
                    callback(http.EGAHTTPApiResponse.JsonEncodeFailed, null, requestId, eventArray.length);
                    return;
                }
                var payloadData = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs = [];
                extraArgs.push(JSONstring);
                extraArgs.push(requestId);
                extraArgs.push(eventArray.length.toString());
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.sendEventInArrayRequestCallback, callback);
            };
            GAHTTPApi.prototype.sendSdkErrorEvent = function (category, area, action, parameter, reason, gameKey, secretKey) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateSdkErrorEvent(gameKey, secretKey, category, area, action)) {
                    return;
                }
                var url = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);
                var payloadJSONString = "";
                var errorType = "";
                var json = GAState.getSdkErrorEventAnnotations();
                var categoryString = GAHTTPApi.sdkErrorCategoryString(category);
                json["error_category"] = categoryString;
                errorType += categoryString;
                var areaString = GAHTTPApi.sdkErrorAreaString(area);
                json["error_area"] = areaString;
                errorType += ":" + areaString;
                var actionString = GAHTTPApi.sdkErrorActionString(action);
                json["error_action"] = actionString;
                var parameterString = GAHTTPApi.sdkErrorParameterString(parameter);
                if (parameterString.length > 0) {
                    json["error_parameter"] = parameterString;
                }
                if (reason.length > 0) {
                    var reasonTrimmed = reason;
                    if (reason.length > GAHTTPApi.MAX_ERROR_MESSAGE_LENGTH) {
                        var reasonTrimmed = reason.substring(0, GAHTTPApi.MAX_ERROR_MESSAGE_LENGTH);
                    }
                    json["reason"] = reasonTrimmed;
                }
                var eventArray = [];
                eventArray.push(json);
                payloadJSONString = JSON.stringify(eventArray);
                if (!payloadJSONString) {
                    GALogger.w("sendSdkErrorEvent: JSON encoding failed.");
                    return;
                }
                GALogger.d("sendSdkErrorEvent json: " + payloadJSONString);
                SdkErrorTask.execute(url, errorType, payloadJSONString, secretKey);
            };
            GAHTTPApi.sendEventInArrayRequestCallback = function (request, url, callback, extra) {
                if (extra === void 0) { extra = null; }
                var authorization = extra[0];
                var JSONstring = extra[1];
                var requestId = extra[2];
                var eventCount = parseInt(extra[3]);
                var body = "";
                var responseCode = 0;
                body = request.responseText;
                responseCode = request.status;
                GALogger.d("events request content: " + body);
                var requestResponseEnum = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Events");
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.Created && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed events Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, requestId, eventCount);
                    return;
                }
                var requestJsonDict = body ? JSON.parse(body) : {};
                if (requestJsonDict == null) {
                    callback(http.EGAHTTPApiResponse.JsonDecodeFailed, null, requestId, eventCount);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Http, EGASdkErrorArea.EventsHttp, EGASdkErrorAction.FailHttpJsonDecode, EGASdkErrorParameter.Undefined, body, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                if (requestResponseEnum == http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Events Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                }
                callback(requestResponseEnum, requestJsonDict, requestId, eventCount);
            };
            GAHTTPApi.sendRequest = function (url, payloadData, extraArgs, gzip, callback, callback2) {
                var request = new XMLHttpRequest();
                var key = GAState.getGameSecret();
                var authorization = GAUtilities.getHmac(key, payloadData);
                var args = [];
                args.push(authorization);
                for (var s in extraArgs) {
                    args.push(extraArgs[s]);
                }
                request.onreadystatechange = function () {
                    if (request.readyState === 4) {
                        callback(request, url, callback2, args);
                    }
                };
                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");
                request.setRequestHeader("Authorization", authorization);
                if (gzip) {
                    throw new Error("gzip not supported");
                }
                try {
                    request.send(payloadData);
                }
                catch (e) {
                    console.error(e.stack);
                }
            };
            GAHTTPApi.initRequestCallback = function (request, url, callback, extra) {
                if (extra === void 0) { extra = null; }
                var authorization = extra[0];
                var JSONstring = extra[1];
                var body = "";
                var responseCode = 0;
                body = request.responseText;
                responseCode = request.status;
                GALogger.d("init request content : " + body + ", JSONstring: " + JSONstring);
                var requestJsonDict = body ? JSON.parse(body) : {};
                var requestResponseEnum = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Init");
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.Created && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }
                if (requestJsonDict == null) {
                    GALogger.d("Failed Init Call. Json decoding failed");
                    callback(http.EGAHTTPApiResponse.JsonDecodeFailed, null, "", 0);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Http, EGASdkErrorArea.InitHttp, EGASdkErrorAction.FailHttpJsonDecode, EGASdkErrorParameter.Undefined, body, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                if (requestResponseEnum === http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }
                var validatedInitValues = GAValidator.validateAndCleanInitRequestResponse(requestJsonDict, requestResponseEnum === http.EGAHTTPApiResponse.Created);
                if (!validatedInitValues) {
                    callback(http.EGAHTTPApiResponse.BadResponse, null, "", 0);
                    return;
                }
                callback(requestResponseEnum, validatedInitValues, "", 0);
            };
            GAHTTPApi.prototype.createPayloadData = function (payload, gzip) {
                var payloadData;
                if (gzip) {
                    throw new Error("gzip not supported");
                }
                else {
                    payloadData = payload;
                }
                return payloadData;
            };
            GAHTTPApi.prototype.processRequestResponse = function (responseCode, responseMessage, body, requestId) {
                if (!body) {
                    GALogger.d(requestId + " request. failed. Might be no connection. Description: " + responseMessage + ", Status code: " + responseCode);
                    return http.EGAHTTPApiResponse.NoResponse;
                }
                if (responseCode === 200) {
                    return http.EGAHTTPApiResponse.Ok;
                }
                if (responseCode === 201) {
                    return http.EGAHTTPApiResponse.Created;
                }
                if (responseCode === 0 || responseCode === 401) {
                    GALogger.d(requestId + " request. 401 - Unauthorized.");
                    return http.EGAHTTPApiResponse.Unauthorized;
                }
                if (responseCode === 400) {
                    GALogger.d(requestId + " request. 400 - Bad Request.");
                    return http.EGAHTTPApiResponse.BadRequest;
                }
                if (responseCode === 500) {
                    GALogger.d(requestId + " request. 500 - Internal Server Error.");
                    return http.EGAHTTPApiResponse.InternalServerError;
                }
                return http.EGAHTTPApiResponse.UnknownResponseCode;
            };
            GAHTTPApi.sdkErrorCategoryString = function (value) {
                switch (value) {
                    case EGASdkErrorCategory.EventValidation:
                        return "event_validation";
                    case EGASdkErrorCategory.Database:
                        return "db";
                    case EGASdkErrorCategory.Init:
                        return "init";
                    case EGASdkErrorCategory.Http:
                        return "http";
                    case EGASdkErrorCategory.Json:
                        return "json";
                    default:
                        break;
                }
                return "";
            };
            GAHTTPApi.sdkErrorAreaString = function (value) {
                switch (value) {
                    case EGASdkErrorArea.BusinessEvent:
                        return "business";
                    case EGASdkErrorArea.ResourceEvent:
                        return "resource";
                    case EGASdkErrorArea.ProgressionEvent:
                        return "progression";
                    case EGASdkErrorArea.DesignEvent:
                        return "design";
                    case EGASdkErrorArea.ErrorEvent:
                        return "error";
                    case EGASdkErrorArea.InitHttp:
                        return "init_http";
                    case EGASdkErrorArea.EventsHttp:
                        return "events_http";
                    case EGASdkErrorArea.ProcessEvents:
                        return "process_events";
                    case EGASdkErrorArea.AddEventsToStore:
                        return "add_events_to_store";
                    default:
                        break;
                }
                return "";
            };
            GAHTTPApi.sdkErrorActionString = function (value) {
                switch (value) {
                    case EGASdkErrorAction.InvalidCurrency:
                        return "invalid_currency";
                    case EGASdkErrorAction.InvalidShortString:
                        return "invalid_short_string";
                    case EGASdkErrorAction.InvalidEventPartLength:
                        return "invalid_event_part_length";
                    case EGASdkErrorAction.InvalidEventPartCharacters:
                        return "invalid_event_part_characters";
                    case EGASdkErrorAction.InvalidStore:
                        return "invalid_store";
                    case EGASdkErrorAction.InvalidFlowType:
                        return "invalid_flow_type";
                    case EGASdkErrorAction.StringEmptyOrNull:
                        return "string_empty_or_null";
                    case EGASdkErrorAction.NotFoundInAvailableCurrencies:
                        return "not_found_in_available_currencies";
                    case EGASdkErrorAction.InvalidAmount:
                        return "invalid_amount";
                    case EGASdkErrorAction.NotFoundInAvailableItemTypes:
                        return "not_found_in_available_item_types";
                    case EGASdkErrorAction.WrongProgressionOrder:
                        return "wrong_progression_order";
                    case EGASdkErrorAction.InvalidEventIdLength:
                        return "invalid_event_id_length";
                    case EGASdkErrorAction.InvalidEventIdCharacters:
                        return "invalid_event_id_characters";
                    case EGASdkErrorAction.InvalidProgressionStatus:
                        return "invalid_progression_status";
                    case EGASdkErrorAction.InvalidSeverity:
                        return "invalid_severity";
                    case EGASdkErrorAction.InvalidLongString:
                        return "invalid_long_string";
                    case EGASdkErrorAction.DatabaseTooLarge:
                        return "db_too_large";
                    case EGASdkErrorAction.DatabaseOpenOrCreate:
                        return "db_open_or_create";
                    case EGASdkErrorAction.JsonError:
                        return "json_error";
                    case EGASdkErrorAction.FailHttpJsonDecode:
                        return "fail_http_json_decode";
                    case EGASdkErrorAction.FailHttpJsonEncode:
                        return "fail_http_json_encode";
                    default:
                        break;
                }
                return "";
            };
            GAHTTPApi.sdkErrorParameterString = function (value) {
                switch (value) {
                    case EGASdkErrorParameter.Currency:
                        return "currency";
                    case EGASdkErrorParameter.CartType:
                        return "cart_type";
                    case EGASdkErrorParameter.ItemType:
                        return "item_type";
                    case EGASdkErrorParameter.ItemId:
                        return "item_id";
                    case EGASdkErrorParameter.Store:
                        return "store";
                    case EGASdkErrorParameter.FlowType:
                        return "flow_type";
                    case EGASdkErrorParameter.Amount:
                        return "amount";
                    case EGASdkErrorParameter.Progression01:
                        return "progression01";
                    case EGASdkErrorParameter.Progression02:
                        return "progression02";
                    case EGASdkErrorParameter.Progression03:
                        return "progression03";
                    case EGASdkErrorParameter.EventId:
                        return "event_id";
                    case EGASdkErrorParameter.ProgressionStatus:
                        return "progression_status";
                    case EGASdkErrorParameter.Severity:
                        return "severity";
                    case EGASdkErrorParameter.Message:
                        return "message";
                    default:
                        break;
                }
                return "";
            };
            GAHTTPApi.instance = new GAHTTPApi();
            GAHTTPApi.MAX_ERROR_MESSAGE_LENGTH = 256;
            return GAHTTPApi;
        }());
        http.GAHTTPApi = GAHTTPApi;
    })(http = gameanalytics.http || (gameanalytics.http = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var health;
    (function (health) {
        var GAHealth = (function () {
            function GAHealth() {
            }
            GAHealth.reset = function () {
                GAHealth.frameAccum = 0;
                GAHealth.frameCount = 0;
                GAHealth.fpsTimer = 0;
                GAHealth.memTimer = 0;
            };
            GAHealth.sampleMemory = function () {
                if (typeof performance === 'undefined' || !performance.memory) {
                    return;
                }
                var mem = performance.memory;
                var deviceBytes = GAHealth.getDeviceMemoryBytes();
                if (deviceBytes > 0) {
                    var sysPct = Math.min(100, Math.max(0, Math.round(mem.totalJSHeapSize / deviceBytes * 100)));
                    GAHealth.memSysBuckets[sysPct]++;
                }
                if (mem.jsHeapSizeLimit > 0) {
                    var appPct = Math.min(100, Math.max(0, Math.round(mem.usedJSHeapSize / mem.jsHeapSizeLimit * 100)));
                    GAHealth.memAppBuckets[appPct]++;
                }
            };
            GAHealth.getGpuModel = function () {
                if (GAHealth._gpuModel !== null) {
                    return GAHealth._gpuModel;
                }
                GAHealth._gpuModel = '';
                try {
                    if (typeof document !== 'undefined') {
                        var canvas = document.createElement('canvas');
                        var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                        if (gl) {
                            var ext = gl.getExtension('WEBGL_debug_renderer_info');
                            if (ext) {
                                GAHealth._gpuModel = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                            }
                        }
                    }
                }
                catch (e) { }
                return GAHealth._gpuModel;
            };
            GAHealth.getHardware = function () {
                if (GAHealth._hardware !== null) {
                    return GAHealth._hardware;
                }
                GAHealth._hardware = 'unknown';
                return GAHealth._hardware;
            };
            GAHealth.getDeviceMemoryBytes = function () {
                return (typeof navigator !== 'undefined' && navigator.deviceMemory)
                    ? navigator.deviceMemory * 1073741824
                    : 0;
            };
            GAHealth.getScreenResolution = function () {
                if (GAHealth._screenResolution !== null) {
                    return GAHealth._screenResolution;
                }
                var w = (typeof screen !== 'undefined') ? screen.width : 0;
                var h = (typeof screen !== 'undefined') ? screen.height : 0;
                GAHealth._screenResolution = w + 'x' + h;
                return GAHealth._screenResolution;
            };
            GAHealth.configure = function (enabled) {
                GAHealth._enabled = enabled;
                if (enabled) {
                    GAHealth.startTracking();
                }
                else {
                    GAHealth.stopTracking();
                }
            };
            GAHealth.startTracking = function () {
                if (typeof requestAnimationFrame === 'undefined') {
                    return;
                }
                GAHealth.reset();
                GAHealth.fpsBuckets = new Array(GAHealth.FPS_MAX + 1).fill(0);
                GAHealth.memSysBuckets = new Array(101).fill(0);
                GAHealth.memAppBuckets = new Array(101).fill(0);
                GAHealth.lastFrameTime = (typeof performance !== 'undefined') ? performance.now() : Date.now();
                var tick = function (now) {
                    if (!GAHealth._enabled) {
                        return;
                    }
                    var delta = now - GAHealth.lastFrameTime;
                    if (delta > 0) {
                        GAHealth.frameAccum += 1000 / delta;
                        GAHealth.frameCount++;
                        GAHealth.fpsTimer += delta;
                        GAHealth.memTimer += delta;
                        if (GAHealth.fpsTimer >= 1000) {
                            var avgFps = Math.min(GAHealth.FPS_MAX, Math.max(0, Math.round(GAHealth.frameAccum / GAHealth.frameCount)));
                            GAHealth.fpsBuckets[avgFps]++;
                            GAHealth.frameAccum = 0;
                            GAHealth.frameCount = 0;
                            GAHealth.fpsTimer -= 1000;
                        }
                        if (GAHealth.memTimer >= GAHealth.MEM_INTERVAL) {
                            GAHealth.sampleMemory();
                            GAHealth.memTimer -= GAHealth.MEM_INTERVAL;
                        }
                    }
                    GAHealth.lastFrameTime = now;
                    GAHealth.rafId = requestAnimationFrame(tick);
                };
                GAHealth.rafId = requestAnimationFrame(tick);
            };
            GAHealth.stopTracking = function () {
                if (typeof cancelAnimationFrame !== 'undefined' && GAHealth.rafId) {
                    cancelAnimationFrame(GAHealth.rafId);
                    GAHealth.rafId = 0;
                }
            };
            GAHealth.getSnapshot = function () {
                var memMb = -1;
                if (typeof performance !== 'undefined' && performance.memory) {
                    memMb = Math.round(performance.memory.usedJSHeapSize / 1048576);
                }
                return {
                    memory_used_mb: memMb,
                    hardware_concurrency: (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : 1,
                    screen_width: (typeof screen !== 'undefined') ? screen.width : 0,
                    screen_height: (typeof screen !== 'undefined') ? screen.height : 0,
                    cpu_model: 'unknown',
                    hardware: GAHealth.getHardware(),
                    gpu_model: GAHealth.getGpuModel(),
                    screen_resolution: GAHealth.getScreenResolution()
                };
            };
            GAHealth.addHealthAnnotations = function (out) {
                out['cpu_model'] = 'unknown';
                out['hardware'] = GAHealth.getHardware();
                var gpuModel = GAHealth.getGpuModel();
                if (gpuModel) {
                    out['gpu_model'] = gpuModel;
                }
                var numCores = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : 0;
                if (numCores > 0) {
                    out['cpu_num_cores'] = numCores;
                }
            };
            GAHealth.addPerformanceData = function (out) {
                out['fps_data_table'] = GAHealth.fpsBuckets.slice();
                if (GAHealth.getDeviceMemoryBytes() > 0) {
                    out['memory_sys_data_table'] = GAHealth.memSysBuckets.slice();
                    out['memory_app_data_table'] = GAHealth.memAppBuckets.slice();
                }
            };
            GAHealth.addSDKInitData = function (out) {
                var bootTime = (typeof performance !== 'undefined') ? Math.round(performance.now()) : -1;
                if (bootTime > 0) {
                    out['app_boot_time'] = bootTime;
                }
            };
            GAHealth.isEnabled = function () {
                return GAHealth._enabled;
            };
            GAHealth.FPS_MAX = 120;
            GAHealth.MEM_INTERVAL = 5000;
            GAHealth._enabled = false;
            GAHealth.rafId = 0;
            GAHealth.lastFrameTime = 0;
            GAHealth.fpsBuckets = [];
            GAHealth.frameAccum = 0;
            GAHealth.frameCount = 0;
            GAHealth.fpsTimer = 0;
            GAHealth.memTimer = 0;
            GAHealth.memSysBuckets = [];
            GAHealth.memAppBuckets = [];
            GAHealth._gpuModel = null;
            GAHealth._hardware = null;
            GAHealth._screenResolution = null;
            return GAHealth;
        }());
        health.GAHealth = GAHealth;
    })(health = gameanalytics.health || (gameanalytics.health = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var events;
    (function (events_1) {
        var GAStore = gameanalytics.store.GAStore;
        var EGAStore = gameanalytics.store.EGAStore;
        var EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        var GAState = gameanalytics.state.GAState;
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
        var GAHTTPApi = gameanalytics.http.GAHTTPApi;
        var GAValidator = gameanalytics.validators.GAValidator;
        var GAEvents = (function () {
            function GAEvents() {
            }
            GAEvents.customEventFieldsErrorCallback = function (baseMessage, message) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var now = new Date();
                if (!GAEvents.timestampMap[baseMessage]) {
                    GAEvents.timestampMap[baseMessage] = now;
                }
                if (!GAEvents.countMap[baseMessage]) {
                    GAEvents.countMap[baseMessage] = 0;
                }
                var diff = now.getTime() - GAEvents.timestampMap[baseMessage].getTime();
                var diffSeconds = diff / 1000;
                if (diffSeconds >= 3600) {
                    GAEvents.timestampMap[baseMessage] = now;
                    GAEvents.countMap[baseMessage] = 0;
                }
                if (GAEvents.countMap[baseMessage] >= GAEvents.MAX_ERROR_COUNT) {
                    return;
                }
                gameanalytics.threading.GAThreading.performTaskOnGAThread(function () {
                    GAEvents.addErrorEvent(gameanalytics.EGAErrorSeverity.Warning, message, null, true);
                    GAEvents.countMap[baseMessage] = GAEvents.countMap[baseMessage] + 1;
                });
            };
            GAEvents.addSessionStartEvent = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var eventDict = {};
                eventDict["category"] = GAEvents.CategorySessionStart;
                GAState.incrementSessionNum();
                GAStore.setItem(GAState.getGameKey(), GAState.SessionNumKey, GAState.getSessionNum().toString());
                GAEvents.addDimensionsToEvent(eventDict);
                var fieldsToUse = GAState.instance.currentGlobalCustomEventFields;
                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GAEvents.addEventToStore(eventDict);
                GALogger.i("Add SESSION START event");
                GAEvents.processEvents(GAEvents.CategorySessionStart, false);
            };
            GAEvents.addSessionEndEvent = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var session_start_ts = GAState.getSessionStart();
                var client_ts_adjusted = GAState.getClientTsAdjusted();
                var sessionLength = client_ts_adjusted - session_start_ts;
                if (sessionLength < 0) {
                    GALogger.w("Session length was calculated to be less then 0. Should not be possible. Resetting to 0.");
                    sessionLength = 0;
                }
                var eventDict = {};
                eventDict["category"] = GAEvents.CategorySessionEnd;
                eventDict["length"] = sessionLength;
                GAEvents.addDimensionsToEvent(eventDict);
                var fieldsToUse = GAState.instance.currentGlobalCustomEventFields;
                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GAEvents.addEventToStore(eventDict);
                GALogger.i("Add SESSION END event.");
                GAEvents.processEvents("", false);
            };
            GAEvents.addSDKInitEvent = function () {
                try {
                    if (!GAState.isEventSubmissionEnabled()) {
                        return;
                    }
                    if (!gameanalytics.health.GAHealth.isEnabled()) {
                        return;
                    }
                    if (GAEvents.wasSDKInitEventSent) {
                        return;
                    }
                    GAEvents.wasSDKInitEventSent = true;
                    var eventDict = {};
                    eventDict["category"] = GAEvents.CategorySDKInit;
                    var sessionNum = GAState.getSessionNum();
                    eventDict["is_first_sdk_init"] = sessionNum === 1;
                    gameanalytics.health.GAHealth.addHealthAnnotations(eventDict);
                    gameanalytics.health.GAHealth.addSDKInitData(eventDict);
                    GAEvents.addDimensionsToEvent(eventDict);
                    GALogger.i("Added sdk init event");
                    GAEvents.addEventToStore(eventDict);
                }
                catch (e) {
                    GALogger.e("addSDKInitEvent - Exception thrown: " + e);
                }
            };
            GAEvents.addHealthEvent = function () {
                try {
                    if (!GAState.isEventSubmissionEnabled()) {
                        return;
                    }
                    if (!gameanalytics.health.GAHealth.isEnabled()) {
                        return;
                    }
                    var eventDict = {};
                    eventDict["category"] = GAEvents.CategoryHealth;
                    gameanalytics.health.GAHealth.addHealthAnnotations(eventDict);
                    gameanalytics.health.GAHealth.addPerformanceData(eventDict);
                    GAEvents.addDimensionsToEvent(eventDict);
                    GALogger.i("Added health event");
                    GAEvents.addEventToStore(eventDict);
                }
                catch (e) {
                    GALogger.e("addHealthEvent - Exception thrown: " + e);
                }
            };
            GAEvents.addBusinessEvent = function (currency, amount, itemType, itemId, cartType, fields, mergeFields) {
                if (cartType === void 0) { cartType = null; }
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var validationResult = GAValidator.validateBusinessEvent(currency, amount, cartType, itemType, itemId);
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                var eventDict = {};
                GAState.incrementTransactionNum();
                GAStore.setItem(GAState.getGameKey(), GAState.TransactionNumKey, GAState.getTransactionNum().toString());
                eventDict["event_id"] = itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryBusiness;
                eventDict["currency"] = currency;
                eventDict["amount"] = amount;
                eventDict[GAState.TransactionNumKey] = GAState.getTransactionNum();
                if (cartType) {
                    eventDict["cart_type"] = cartType;
                }
                GAEvents.addDimensionsToEvent(eventDict);
                var fieldsToUse = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (var key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }
                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }
                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addResourceEvent = function (flowType, currency, amount, itemType, itemId, fields, mergeFields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var validationResult = GAValidator.validateResourceEvent(flowType, currency, amount, itemType, itemId, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes());
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                if (flowType === gameanalytics.EGAResourceFlowType.Sink) {
                    amount *= -1;
                }
                var eventDict = {};
                var flowTypeString = GAEvents.resourceFlowTypeToString(flowType);
                eventDict["event_id"] = flowTypeString + ":" + currency + ":" + itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryResource;
                eventDict["amount"] = amount;
                GAEvents.addDimensionsToEvent(eventDict);
                var fieldsToUse = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (var key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }
                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }
                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score, sendScore, fields, mergeFields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var progressionStatusString = GAEvents.progressionStatusToString(progressionStatus);
                var validationResult = GAValidator.validateProgressionEvent(progressionStatus, progression01, progression02, progression03);
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                var eventDict = {};
                var progressionIdentifier;
                if (!progression02) {
                    progressionIdentifier = progression01;
                }
                else if (!progression03) {
                    progressionIdentifier = progression01 + ":" + progression02;
                }
                else {
                    progressionIdentifier = progression01 + ":" + progression02 + ":" + progression03;
                }
                eventDict["category"] = GAEvents.CategoryProgression;
                eventDict["event_id"] = progressionStatusString + ":" + progressionIdentifier;
                var attempt_num = 0;
                if (sendScore && progressionStatus != gameanalytics.EGAProgressionStatus.Start) {
                    eventDict["score"] = Math.round(score);
                }
                if (progressionStatus === gameanalytics.EGAProgressionStatus.Fail) {
                    GAState.incrementProgressionTries(progressionIdentifier);
                }
                if (progressionStatus === gameanalytics.EGAProgressionStatus.Complete) {
                    GAState.incrementProgressionTries(progressionIdentifier);
                    attempt_num = GAState.getProgressionTries(progressionIdentifier);
                    eventDict["attempt_num"] = attempt_num;
                    GAState.clearProgressionTries(progressionIdentifier);
                }
                GAEvents.addDimensionsToEvent(eventDict);
                var fieldsToUse = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (var key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }
                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }
                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addDesignEvent = function (eventId, value, sendValue, fields, mergeFields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var validationResult = GAValidator.validateDesignEvent(eventId);
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryDesign;
                eventData["event_id"] = eventId;
                if (sendValue) {
                    eventData["value"] = value;
                }
                GAEvents.addDimensionsToEvent(eventData);
                var fieldsToUse = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (var key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }
                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }
                GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.addErrorEvent = function (severity, message, fields, mergeFields, skipAddingFields) {
                if (skipAddingFields === void 0) { skipAddingFields = false; }
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var severityString = GAEvents.errorSeverityToString(severity);
                var validationResult = GAValidator.validateErrorEvent(severity, message);
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryError;
                eventData["severity"] = severityString;
                eventData["message"] = message;
                GAEvents.addDimensionsToEvent(eventData);
                if (!skipAddingFields) {
                    var fieldsToUse = {};
                    if (fields && Object.keys(fields).length > 0) {
                        for (var key in fields) {
                            fieldsToUse[key] = fields[key];
                        }
                    }
                    else {
                        for (var key in GAState.instance.currentGlobalCustomEventFields) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                    if (mergeFields && fields && Object.keys(fields).length > 0) {
                        for (var key in GAState.instance.currentGlobalCustomEventFields) {
                            if (!fieldsToUse[key]) {
                                fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                            }
                        }
                    }
                    GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                }
                GALogger.i("Add ERROR event: {severity:" + severityString + ", message:" + message + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.addAdEvent = function (adAction, adType, adSdkName, adPlacement, noAdReason, duration, sendDuration, fields, mergeFields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var adActionString = GAEvents.adActionToString(adAction);
                var adTypeString = GAEvents.adTypeToString(adType);
                var noAdReasonString = GAEvents.adErrorToString(noAdReason);
                var validationResult = GAValidator.validateAdEvent(adAction, adType, adSdkName, adPlacement);
                if (validationResult != null) {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryAds;
                eventData["ad_sdk_name"] = adSdkName;
                eventData["ad_placement"] = adPlacement;
                eventData["ad_type"] = adTypeString;
                eventData["ad_action"] = adActionString;
                if (adAction == gameanalytics.EGAAdAction.FailedShow && noAdReasonString.length > 0) {
                    eventData["ad_fail_show_reason"] = noAdReasonString;
                }
                if (sendDuration && (adType == gameanalytics.EGAAdType.RewardedVideo || adType == gameanalytics.EGAAdType.Video)) {
                    eventData["ad_duration"] = duration;
                }
                GAEvents.addDimensionsToEvent(eventData);
                var fieldsToUse = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (var key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }
                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (var key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }
                GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                GALogger.i("Add AD event: {ad_sdk_name:" + adSdkName + ", ad_placement:" + adPlacement + ", ad_type:" + adTypeString + ", ad_action:" + adActionString + ((adAction == gameanalytics.EGAAdAction.FailedShow && noAdReasonString.length > 0) ? (", ad_fail_show_reason:" + noAdReasonString) : "") + ((sendDuration && (adType == gameanalytics.EGAAdType.RewardedVideo || adType == gameanalytics.EGAAdType.Video)) ? (", ad_duration:" + duration) : "") + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.processEvents = function (category, performCleanUp) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                try {
                    var requestIdentifier = GAUtilities.createGuid();
                    if (performCleanUp) {
                        GAEvents.cleanupEvents();
                        GAEvents.fixMissingSessionEndEvents();
                    }
                    var selectArgs = [];
                    selectArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);
                    var updateWhereArgs = [];
                    updateWhereArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);
                    if (category) {
                        selectArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                        updateWhereArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                    }
                    var updateSetArgs = [];
                    updateSetArgs.push(["status", requestIdentifier]);
                    var events = GAStore.select(EGAStore.Events, selectArgs);
                    if (!events || events.length == 0) {
                        GALogger.i("Event queue: No events to send");
                        GAEvents.updateSessionStore();
                        return;
                    }
                    if (events.length > GAEvents.MaxEventCount) {
                        events = GAStore.select(EGAStore.Events, selectArgs, true, GAEvents.MaxEventCount);
                        if (!events) {
                            return;
                        }
                        var lastItem = events[events.length - 1];
                        var lastTimestamp = lastItem["client_ts"];
                        selectArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);
                        events = GAStore.select(EGAStore.Events, selectArgs);
                        if (!events) {
                            return;
                        }
                        updateWhereArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);
                    }
                    GALogger.i("Event queue: Sending " + events.length + " events.");
                    if (!GAStore.update(EGAStore.Events, updateSetArgs, updateWhereArgs)) {
                        return;
                    }
                    var payloadArray = [];
                    for (var i = 0; i < events.length; ++i) {
                        var ev = events[i];
                        var eventDict = JSON.parse(GAUtilities.decode64(ev["event"]));
                        if (eventDict.length != 0) {
                            var clientTs = eventDict["client_ts"];
                            if (clientTs && !GAValidator.validateClientTs(clientTs)) {
                                delete eventDict["client_ts"];
                            }
                            payloadArray.push(eventDict);
                        }
                    }
                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e) {
                    GALogger.e("Error during ProcessEvents(): " + e.stack);
                    GAHTTPApi.instance.sendSdkErrorEvent(events_1.EGASdkErrorCategory.Json, events_1.EGASdkErrorArea.ProcessEvents, events_1.EGASdkErrorAction.JsonError, events_1.EGASdkErrorParameter.Undefined, e.stack, GAState.getGameKey(), GAState.getGameSecret());
                }
            };
            GAEvents.processEventsCallback = function (responseEnum, dataDict, requestId, eventCount) {
                var requestIdWhereArgs = [];
                requestIdWhereArgs.push(["status", EGAStoreArgsOperator.Equal, requestId]);
                if (responseEnum === EGAHTTPApiResponse.Ok) {
                    GAStore["delete"](EGAStore.Events, requestIdWhereArgs);
                    GALogger.i("Event queue: " + eventCount + " events sent.");
                }
                else {
                    if (responseEnum === EGAHTTPApiResponse.NoResponse) {
                        var setArgs = [];
                        setArgs.push(["status", "new"]);
                        GALogger.w("Event queue: Failed to send events to collector - Retrying next time");
                        GAStore.update(EGAStore.Events, setArgs, requestIdWhereArgs);
                    }
                    else {
                        if (dataDict) {
                            var json;
                            var count = 0;
                            for (var j in dataDict) {
                                if (count == 0) {
                                    json = dataDict[j];
                                }
                                ++count;
                            }
                            if (responseEnum === EGAHTTPApiResponse.BadRequest && json.constructor === Array) {
                                GALogger.w("Event queue: " + eventCount + " events sent. " + count + " events failed GA server validation.");
                            }
                            else {
                                GALogger.w("Event queue: Failed to send events.");
                            }
                        }
                        else {
                            GALogger.w("Event queue: Failed to send events.");
                        }
                        GAStore["delete"](EGAStore.Events, requestIdWhereArgs);
                    }
                }
            };
            GAEvents.cleanupEvents = function () {
                GAStore.update(EGAStore.Events, [["status", "new"]]);
            };
            GAEvents.fixMissingSessionEndEvents = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var args = [];
                args.push(["session_id", EGAStoreArgsOperator.NotEqual, GAState.getSessionId()]);
                var sessions = GAStore.select(EGAStore.Sessions, args);
                if (!sessions || sessions.length == 0) {
                    return;
                }
                GALogger.i(sessions.length + " session(s) located with missing session_end event.");
                for (var i = 0; i < sessions.length; ++i) {
                    var sessionEndEvent = JSON.parse(GAUtilities.decode64(sessions[i]["event"]));
                    var event_ts = sessionEndEvent["client_ts"];
                    var start_ts = sessions[i]["timestamp"];
                    var length = event_ts - start_ts;
                    length = Math.max(0, length);
                    if (length === null)
                        length = 0;
                    GALogger.d("fixMissingSessionEndEvents length calculated: " + length);
                    sessionEndEvent["category"] = GAEvents.CategorySessionEnd;
                    sessionEndEvent["length"] = length;
                    GAEvents.addEventToStore(sessionEndEvent);
                }
            };
            GAEvents.addEventToStore = function (eventData) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAState.isInitialized()) {
                    GALogger.w("Could not add event: SDK is not initialized");
                    return;
                }
                try {
                    if (GAStore.isStoreTooLargeForEvents() && !GAUtilities.stringMatch(eventData["category"], /^(user|session_end|business)$/)) {
                        GALogger.w("Database too large. Event has been blocked.");
                        GAHTTPApi.instance.sendSdkErrorEvent(events_1.EGASdkErrorCategory.Database, events_1.EGASdkErrorArea.AddEventsToStore, events_1.EGASdkErrorAction.DatabaseTooLarge, events_1.EGASdkErrorParameter.Undefined, "", GAState.getGameKey(), GAState.getGameSecret());
                        return;
                    }
                    var ev = GAState.getEventAnnotations();
                    for (var e in eventData) {
                        ev[e] = eventData[e];
                    }
                    var json = JSON.stringify(ev);
                    GALogger.ii("Event added to queue: " + json);
                    var values = {};
                    values["status"] = "new";
                    values["category"] = ev["category"];
                    values["session_id"] = ev["session_id"];
                    values["client_ts"] = ev["client_ts"];
                    values["event"] = GAUtilities.encode64(JSON.stringify(ev));
                    GAStore.insert(EGAStore.Events, values);
                    if (eventData["category"] == GAEvents.CategorySessionEnd) {
                        GAStore["delete"](EGAStore.Sessions, [["session_id", EGAStoreArgsOperator.Equal, ev["session_id"]]]);
                    }
                    else {
                        GAEvents.updateSessionStore();
                    }
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save(GAState.getGameKey());
                    }
                }
                catch (e) {
                    GALogger.e("addEventToStore: error");
                    GALogger.e(e.stack);
                    GAHTTPApi.instance.sendSdkErrorEvent(events_1.EGASdkErrorCategory.Database, events_1.EGASdkErrorArea.AddEventsToStore, events_1.EGASdkErrorAction.DatabaseTooLarge, events_1.EGASdkErrorParameter.Undefined, e.stack, GAState.getGameKey(), GAState.getGameSecret());
                }
            };
            GAEvents.updateSessionStore = function () {
                if (GAState.sessionIsStarted()) {
                    var values = {};
                    values["session_id"] = GAState.instance.sessionId;
                    values["timestamp"] = GAState.getSessionStart();
                    var ev = GAState.getEventAnnotations();
                    GAEvents.addDimensionsToEvent(ev);
                    var fieldsToUse = GAState.instance.currentGlobalCustomEventFields;
                    GAEvents.addCustomFieldsToEvent(ev, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                    values["event"] = GAUtilities.encode64(JSON.stringify(ev));
                    GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save(GAState.getGameKey());
                    }
                }
            };
            GAEvents.addDimensionsToEvent = function (eventData) {
                if (!eventData) {
                    return;
                }
                if (GAState.getCurrentCustomDimension01()) {
                    eventData["custom_01"] = GAState.getCurrentCustomDimension01();
                }
                if (GAState.getCurrentCustomDimension02()) {
                    eventData["custom_02"] = GAState.getCurrentCustomDimension02();
                }
                if (GAState.getCurrentCustomDimension03()) {
                    eventData["custom_03"] = GAState.getCurrentCustomDimension03();
                }
            };
            GAEvents.addCustomFieldsToEvent = function (eventData, fields) {
                if (!eventData) {
                    return;
                }
                if (fields && Object.keys(fields).length > 0) {
                    eventData["custom_fields"] = fields;
                }
            };
            GAEvents.resourceFlowTypeToString = function (value) {
                if (value == gameanalytics.EGAResourceFlowType.Source || value == gameanalytics.EGAResourceFlowType[gameanalytics.EGAResourceFlowType.Source]) {
                    return "Source";
                }
                else if (value == gameanalytics.EGAResourceFlowType.Sink || value == gameanalytics.EGAResourceFlowType[gameanalytics.EGAResourceFlowType.Sink]) {
                    return "Sink";
                }
                else {
                    return "";
                }
            };
            GAEvents.progressionStatusToString = function (value) {
                if (value == gameanalytics.EGAProgressionStatus.Start || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Start]) {
                    return "Start";
                }
                else if (value == gameanalytics.EGAProgressionStatus.Complete || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Complete]) {
                    return "Complete";
                }
                else if (value == gameanalytics.EGAProgressionStatus.Fail || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Fail]) {
                    return "Fail";
                }
                else {
                    return "";
                }
            };
            GAEvents.errorSeverityToString = function (value) {
                if (value == gameanalytics.EGAErrorSeverity.Debug || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Debug]) {
                    return "debug";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Info || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Info]) {
                    return "info";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Warning || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Warning]) {
                    return "warning";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Error || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Error]) {
                    return "error";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Critical || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Critical]) {
                    return "critical";
                }
                else {
                    return "";
                }
            };
            GAEvents.adActionToString = function (value) {
                if (value == gameanalytics.EGAAdAction.Clicked || value == gameanalytics.EGAAdAction[gameanalytics.EGAAdAction.Clicked]) {
                    return "clicked";
                }
                else if (value == gameanalytics.EGAAdAction.Show || value == gameanalytics.EGAAdAction[gameanalytics.EGAAdAction.Show]) {
                    return "show";
                }
                else if (value == gameanalytics.EGAAdAction.FailedShow || value == gameanalytics.EGAAdAction[gameanalytics.EGAAdAction.FailedShow]) {
                    return "failed_show";
                }
                else if (value == gameanalytics.EGAAdAction.RewardReceived || value == gameanalytics.EGAAdAction[gameanalytics.EGAAdAction.RewardReceived]) {
                    return "reward_received";
                }
                else {
                    return "";
                }
            };
            GAEvents.adErrorToString = function (value) {
                if (value == gameanalytics.EGAAdError.Unknown || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.Unknown]) {
                    return "unknown";
                }
                else if (value == gameanalytics.EGAAdError.Offline || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.Offline]) {
                    return "offline";
                }
                else if (value == gameanalytics.EGAAdError.NoFill || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.NoFill]) {
                    return "no_fill";
                }
                else if (value == gameanalytics.EGAAdError.InternalError || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.InternalError]) {
                    return "internal_error";
                }
                else if (value == gameanalytics.EGAAdError.InvalidRequest || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.InvalidRequest]) {
                    return "invalid_request";
                }
                else if (value == gameanalytics.EGAAdError.UnableToPrecache || value == gameanalytics.EGAAdError[gameanalytics.EGAAdError.UnableToPrecache]) {
                    return "unable_to_precache";
                }
                else {
                    return "";
                }
            };
            GAEvents.adTypeToString = function (value) {
                if (value == gameanalytics.EGAAdType.Video || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.Video]) {
                    return "video";
                }
                else if (value == gameanalytics.EGAAdType.RewardedVideo || value == gameanalytics.EGAAdError[gameanalytics.EGAAdType.RewardedVideo]) {
                    return "rewarded_video";
                }
                else if (value == gameanalytics.EGAAdType.Playable || value == gameanalytics.EGAAdError[gameanalytics.EGAAdType.Playable]) {
                    return "playable";
                }
                else if (value == gameanalytics.EGAAdType.Interstitial || value == gameanalytics.EGAAdError[gameanalytics.EGAAdType.Interstitial]) {
                    return "interstitial";
                }
                else if (value == gameanalytics.EGAAdType.OfferWall || value == gameanalytics.EGAAdError[gameanalytics.EGAAdType.OfferWall]) {
                    return "offer_wall";
                }
                else if (value == gameanalytics.EGAAdType.Banner || value == gameanalytics.EGAAdError[gameanalytics.EGAAdType.Banner]) {
                    return "banner";
                }
                else {
                    return "";
                }
            };
            GAEvents.CategorySessionStart = "user";
            GAEvents.CategorySessionEnd = "session_end";
            GAEvents.CategoryDesign = "design";
            GAEvents.CategoryBusiness = "business";
            GAEvents.CategoryProgression = "progression";
            GAEvents.CategoryResource = "resource";
            GAEvents.CategoryError = "error";
            GAEvents.CategoryAds = "ads";
            GAEvents.CategorySDKInit = "sdk_init";
            GAEvents.CategoryHealth = "health";
            GAEvents.MaxEventCount = 500;
            GAEvents.MAX_ERROR_COUNT = 10;
            GAEvents.countMap = {};
            GAEvents.timestampMap = {};
            GAEvents.wasSDKInitEventSent = false;
            return GAEvents;
        }());
        events_1.GAEvents = GAEvents;
    })(events = gameanalytics.events || (gameanalytics.events = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAState = gameanalytics.state.GAState;
        var GAEvents = gameanalytics.events.GAEvents;
        var GAThreading = (function () {
            function GAThreading() {
                this.taskQueue = [];
                this.isRunning = false;
                setInterval(GAThreading.run, 100);
            }
            GAThreading.performTaskOnGAThread = function (taskBlock) {
                GAThreading.instance.taskQueue.push(taskBlock);
            };
            GAThreading.ensureEventQueueIsRunning = function () {
                if (!GAThreading.instance.isRunning) {
                    GAThreading.instance.isRunning = true;
                    GAThreading.eventIntervalId = setInterval(function () { return GAThreading.performTaskOnGAThread(GAThreading.processEventQueue); }, GAThreading.ProcessEventsIntervalInSeconds * 1000);
                }
            };
            GAThreading.endSessionAndStopQueue = function () {
                if (GAState.isInitialized()) {
                    GALogger.i("Ending session.");
                    GAThreading.stopEventQueue();
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAEvents.addHealthEvent();
                        GAEvents.addSessionEndEvent();
                        GAState.instance.sessionStart = 0;
                    }
                }
            };
            GAThreading.stopEventQueue = function () {
                clearInterval(GAThreading.eventIntervalId);
                GAThreading.instance.isRunning = false;
            };
            GAThreading.setEventProcessInterval = function (interval) {
                if (interval > 0) {
                    GAThreading.ProcessEventsIntervalInSeconds = interval;
                }
            };
            GAThreading.run = function () {
                while (GAThreading.instance.taskQueue.length > 0) {
                    var task = GAThreading.instance.taskQueue.shift();
                    if (task) {
                        try {
                            task();
                        }
                        catch (e) {
                            GALogger.e("Error on GA thread");
                            GALogger.e(e.stack);
                        }
                    }
                }
            };
            GAThreading.processEventQueue = function () {
                GALogger.d("Processing event queue...");
                GAEvents.processEvents("", true);
            };
            GAThreading.instance = new GAThreading();
            GAThreading.ProcessEventsIntervalInSeconds = 8.0;
            return GAThreading;
        }());
        threading.GAThreading = GAThreading;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var GAThreading = gameanalytics.threading.GAThreading;
    var GALogger = gameanalytics.logging.GALogger;
    var GAStore = gameanalytics.store.GAStore;
    var GAState = gameanalytics.state.GAState;
    var GAHTTPApi = gameanalytics.http.GAHTTPApi;
    var GADevice = gameanalytics.device.GADevice;
    var GAValidator = gameanalytics.validators.GAValidator;
    var EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
    var GAUtilities = gameanalytics.utilities.GAUtilities;
    var GAEvents = gameanalytics.events.GAEvents;
    var GameAnalytics = (function () {
        function GameAnalytics() {
        }
        GameAnalytics.getGlobalObject = function () {
            if (typeof globalThis !== 'undefined') {
                return globalThis;
            }
            if (typeof self !== 'undefined') {
                return self;
            }
            if (typeof window !== 'undefined') {
                return window;
            }
            if (typeof global !== 'undefined') {
                return global;
            }
            return undefined;
        };
        GameAnalytics.init = function () {
            GADevice.touch();
            GameAnalytics.methodMap['configureAvailableCustomDimensions01'] = GameAnalytics.configureAvailableCustomDimensions01;
            GameAnalytics.methodMap['configureAvailableCustomDimensions02'] = GameAnalytics.configureAvailableCustomDimensions02;
            GameAnalytics.methodMap['configureAvailableCustomDimensions03'] = GameAnalytics.configureAvailableCustomDimensions03;
            GameAnalytics.methodMap['configureAvailableResourceCurrencies'] = GameAnalytics.configureAvailableResourceCurrencies;
            GameAnalytics.methodMap['configureAvailableResourceItemTypes'] = GameAnalytics.configureAvailableResourceItemTypes;
            GameAnalytics.methodMap['configureBuild'] = GameAnalytics.configureBuild;
            GameAnalytics.methodMap['configureSdkGameEngineVersion'] = GameAnalytics.configureSdkGameEngineVersion;
            GameAnalytics.methodMap['configureGameEngineVersion'] = GameAnalytics.configureGameEngineVersion;
            GameAnalytics.methodMap['configureUserId'] = GameAnalytics.configureUserId;
            GameAnalytics.methodMap['getUserId'] = GameAnalytics.getUserId;
            GameAnalytics.methodMap['setExtUserId'] = GameAnalytics.setExtUserId;
            GameAnalytics.methodMap['getExtUserId'] = GameAnalytics.getExtUserId;
            GameAnalytics.methodMap['initialize'] = GameAnalytics.initialize;
            GameAnalytics.methodMap['addBusinessEvent'] = GameAnalytics.addBusinessEvent;
            GameAnalytics.methodMap['addResourceEvent'] = GameAnalytics.addResourceEvent;
            GameAnalytics.methodMap['addProgressionEvent'] = GameAnalytics.addProgressionEvent;
            GameAnalytics.methodMap['addDesignEvent'] = GameAnalytics.addDesignEvent;
            GameAnalytics.methodMap['addErrorEvent'] = GameAnalytics.addErrorEvent;
            GameAnalytics.methodMap['addAdEvent'] = GameAnalytics.addAdEvent;
            GameAnalytics.methodMap['setEnabledInfoLog'] = GameAnalytics.setEnabledInfoLog;
            GameAnalytics.methodMap['setEnabledVerboseLog'] = GameAnalytics.setEnabledVerboseLog;
            GameAnalytics.methodMap['setEnabledManualSessionHandling'] = GameAnalytics.setEnabledManualSessionHandling;
            GameAnalytics.methodMap['setEnabledEventSubmission'] = GameAnalytics.setEnabledEventSubmission;
            GameAnalytics.methodMap['enableHealthEvent'] = GameAnalytics.enableHealthEvent;
            GameAnalytics.methodMap['setCustomDimension01'] = GameAnalytics.setCustomDimension01;
            GameAnalytics.methodMap['setCustomDimension02'] = GameAnalytics.setCustomDimension02;
            GameAnalytics.methodMap['setCustomDimension03'] = GameAnalytics.setCustomDimension03;
            GameAnalytics.methodMap['setGlobalCustomEventFields'] = GameAnalytics.setGlobalCustomEventFields;
            GameAnalytics.methodMap['setEventProcessInterval'] = GameAnalytics.setEventProcessInterval;
            GameAnalytics.methodMap['startSession'] = GameAnalytics.startSession;
            GameAnalytics.methodMap['endSession'] = GameAnalytics.endSession;
            GameAnalytics.methodMap['onStop'] = GameAnalytics.onStop;
            GameAnalytics.methodMap['onResume'] = GameAnalytics.onResume;
            GameAnalytics.methodMap['addRemoteConfigsListener'] = GameAnalytics.addRemoteConfigsListener;
            GameAnalytics.methodMap['removeRemoteConfigsListener'] = GameAnalytics.removeRemoteConfigsListener;
            GameAnalytics.methodMap['getRemoteConfigsValueAsString'] = GameAnalytics.getRemoteConfigsValueAsString;
            GameAnalytics.methodMap['getRemoteConfigsValueAsJSON'] = GameAnalytics.getRemoteConfigsValueAsJSON;
            GameAnalytics.methodMap['isRemoteConfigsReady'] = GameAnalytics.isRemoteConfigsReady;
            GameAnalytics.methodMap['getRemoteConfigsContentAsString'] = GameAnalytics.getRemoteConfigsContentAsString;
            GameAnalytics.methodMap['addOnBeforeUnloadListener'] = GameAnalytics.addOnBeforeUnloadListener;
            GameAnalytics.methodMap['removeOnBeforeUnloadListener'] = GameAnalytics.removeOnBeforeUnloadListener;
            if (typeof GameAnalytics.getGlobalObject() !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics'] !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics']['q'] !== 'undefined') {
                var q = GameAnalytics.getGlobalObject()['GameAnalytics']['q'];
                for (var i in q) {
                    GameAnalytics.gaCommand.apply(null, q[i]);
                }
            }
            window.addEventListener("beforeunload", function (e) {
                console.log('addEventListener unload');
                GAState.instance.isUnloading = true;
                GAState.notifyBeforeUnloadListeners();
                GAThreading.endSessionAndStopQueue();
                GAState.instance.isUnloading = false;
            });
        };
        GameAnalytics.gaCommand = function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            if (args.length > 0) {
                if (args[0] in gameanalytics.GameAnalytics.methodMap) {
                    if (args.length > 1) {
                        gameanalytics.GameAnalytics.methodMap[args[0]].apply(null, Array.prototype.slice.call(args, 1));
                    }
                    else {
                        gameanalytics.GameAnalytics.methodMap[args[0]]();
                    }
                }
            }
        };
        GameAnalytics.configureAvailableCustomDimensions01 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions01(customDimensions);
            });
        };
        GameAnalytics.configureAvailableCustomDimensions02 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions02(customDimensions);
            });
        };
        GameAnalytics.configureAvailableCustomDimensions03 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions03(customDimensions);
            });
        };
        GameAnalytics.configureAvailableResourceCurrencies = function (resourceCurrencies) {
            if (resourceCurrencies === void 0) { resourceCurrencies = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available resource currencies must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceCurrencies(resourceCurrencies);
            });
        };
        GameAnalytics.configureAvailableResourceItemTypes = function (resourceItemTypes) {
            if (resourceItemTypes === void 0) { resourceItemTypes = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available resource item types must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceItemTypes(resourceItemTypes);
            });
        };
        GameAnalytics.configureBuild = function (build) {
            if (build === void 0) { build = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Build version must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateBuild(build)) {
                    GALogger.i("Validation fail - configure build: Cannot be null, empty or above 32 length. String: " + build);
                    return;
                }
                GAState.setBuild(build);
            });
        };
        GameAnalytics.configureSdkGameEngineVersion = function (sdkGameEngineVersion) {
            if (sdkGameEngineVersion === void 0) { sdkGameEngineVersion = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    return;
                }
                if (!GAValidator.validateSdkWrapperVersion(sdkGameEngineVersion)) {
                    GALogger.i("Validation fail - configure sdk version: Sdk version not supported. String: " + sdkGameEngineVersion);
                    return;
                }
                GADevice.sdkGameEngineVersion = sdkGameEngineVersion;
            });
        };
        GameAnalytics.configureGameEngineVersion = function (gameEngineVersion) {
            if (gameEngineVersion === void 0) { gameEngineVersion = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    return;
                }
                if (!GAValidator.validateEngineVersion(gameEngineVersion)) {
                    GALogger.i("Validation fail - configure game engine version: Game engine version not supported. String: " + gameEngineVersion);
                    return;
                }
                GADevice.gameEngineVersion = gameEngineVersion;
            });
        };
        GameAnalytics.configureUserId = function (uId) {
            if (uId === void 0) { uId = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("A custom user id must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateUserId(uId)) {
                    GALogger.i("Validation fail - configure user_id: Cannot be null, empty or above 64 length. Will use default user_id method. Used string: " + uId);
                    return;
                }
                GAState.setUserId(uId);
            });
        };
        GameAnalytics.setExtUserId = function (uId) {
            if (uId === void 0) { uId = ""; }
            GAThreading.performTaskOnGAThread(function () {
                GAState.setExtUserId(uId);
            });
        };
        GameAnalytics.getExtUserId = function () {
            return GAState.getExtUserId();
        };
        GameAnalytics.getUserId = function () {
            return GAState.getIdentifier();
        };
        GameAnalytics.initialize = function (gameKey, gameSecret) {
            if (gameKey === void 0) { gameKey = ""; }
            if (gameSecret === void 0) { gameSecret = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("SDK already initialized. Can only be called once.");
                    return;
                }
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    GALogger.w("SDK failed initialize. Game key or secret key is invalid. Can only contain characters A-z 0-9, gameKey is 32 length, gameSecret is 40 length. Failed keys - gameKey: " + gameKey + ", secretKey: " + gameSecret);
                    return;
                }
                GAState.setKeys(gameKey, gameSecret);
                GameAnalytics.internalInitialize();
            });
        };
        GameAnalytics.addBusinessEvent = function (currency, amount, itemType, itemId, cartType, customFields, mergeFields) {
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            if (cartType === void 0) { cartType = ""; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                        return;
                    }
                    GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                    return;
                }
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, customFields, mergeFields);
            }
        };
        GameAnalytics.addResourceEvent = function (flowType, currency, amount, itemType, itemId, customFields, mergeFields) {
            if (flowType === void 0) { flowType = gameanalytics.EGAResourceFlowType.Undefined; }
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                        return;
                    }
                    GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                    return;
                }
                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, customFields, mergeFields);
            }
        };
        GameAnalytics.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score, customFields, mergeFields) {
            if (progressionStatus === void 0) { progressionStatus = gameanalytics.EGAProgressionStatus.Undefined; }
            if (progression01 === void 0) { progression01 = ""; }
            if (progression02 === void 0) { progression02 = ""; }
            if (progression03 === void 0) { progression03 = ""; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                        return;
                    }
                    var sendScore = typeof score === "number";
                    GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                    return;
                }
                var sendScore = typeof score === "number";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, customFields, mergeFields);
            }
        };
        GameAnalytics.addDesignEvent = function (eventId, value, customFields, mergeFields) {
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                        return;
                    }
                    var sendValue = typeof value === "number";
                    GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                    return;
                }
                var sendValue = typeof value === "number";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, customFields, mergeFields);
            }
        };
        GameAnalytics.addErrorEvent = function (severity, message, customFields, mergeFields) {
            if (severity === void 0) { severity = gameanalytics.EGAErrorSeverity.Undefined; }
            if (message === void 0) { message = ""; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                        return;
                    }
                    GAEvents.addErrorEvent(severity, message, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                    return;
                }
                GAEvents.addErrorEvent(severity, message, customFields, mergeFields);
            }
        };
        GameAnalytics.addAdEventWithNoAdReason = function (adAction, adType, adSdkName, adPlacement, noAdReason, customFields, mergeFields) {
            if (adAction === void 0) { adAction = gameanalytics.EGAAdAction.Undefined; }
            if (adType === void 0) { adType = gameanalytics.EGAAdType.Undefined; }
            if (adSdkName === void 0) { adSdkName = ""; }
            if (adPlacement === void 0) { adPlacement = ""; }
            if (noAdReason === void 0) { noAdReason = gameanalytics.EGAAdError.Undefined; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, noAdReason, 0, false, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, noAdReason, 0, false, customFields, mergeFields);
            }
        };
        GameAnalytics.addAdEventWithDuration = function (adAction, adType, adSdkName, adPlacement, duration, customFields, mergeFields) {
            if (adAction === void 0) { adAction = gameanalytics.EGAAdAction.Undefined; }
            if (adType === void 0) { adType = gameanalytics.EGAAdType.Undefined; }
            if (adSdkName === void 0) { adSdkName = ""; }
            if (adPlacement === void 0) { adPlacement = ""; }
            if (duration === void 0) { duration = 0; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, gameanalytics.EGAAdError.Undefined, duration, true, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, gameanalytics.EGAAdError.Undefined, duration, true, customFields, mergeFields);
            }
        };
        GameAnalytics.addAdEvent = function (adAction, adType, adSdkName, adPlacement, customFields, mergeFields) {
            if (adAction === void 0) { adAction = gameanalytics.EGAAdAction.Undefined; }
            if (adType === void 0) { adType = gameanalytics.EGAAdType.Undefined; }
            if (adSdkName === void 0) { adSdkName = ""; }
            if (adPlacement === void 0) { adPlacement = ""; }
            if (customFields === void 0) { customFields = {}; }
            if (mergeFields === void 0) { mergeFields = false; }
            GADevice.updateConnectionType();
            if (!GAState.instance.isUnloading) {
                GAThreading.performTaskOnGAThread(function () {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, gameanalytics.EGAAdError.Undefined, 0, false, customFields, mergeFields);
                });
            }
            else {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, gameanalytics.EGAAdError.Undefined, 0, false, customFields, mergeFields);
            }
        };
        GameAnalytics.setEnabledInfoLog = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GALogger.setInfoLog(flag);
                    GALogger.i("Info logging enabled");
                }
                else {
                    GALogger.i("Info logging disabled");
                    GALogger.setInfoLog(flag);
                }
            });
        };
        GameAnalytics.setEnabledVerboseLog = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GALogger.setVerboseLog(flag);
                    GALogger.i("Verbose logging enabled");
                }
                else {
                    GALogger.i("Verbose logging disabled");
                    GALogger.setVerboseLog(flag);
                }
            });
        };
        GameAnalytics.setEnabledManualSessionHandling = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                GAState.setManualSessionHandling(flag);
            });
        };
        GameAnalytics.setEnabledEventSubmission = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GAState.setEnabledEventSubmission(flag);
                    GALogger.i("Event submission enabled");
                }
                else {
                    GALogger.i("Event submission disabled");
                    GAState.setEnabledEventSubmission(flag);
                }
            });
        };
        GameAnalytics.enableHealthEvent = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                gameanalytics.health.GAHealth.configure(flag);
            });
        };
        GameAnalytics.setCustomDimension01 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension01(dimension, GAState.getAvailableCustomDimensions01())) {
                    GALogger.w("Could not set custom01 dimension value to '" + dimension + "'. Value not found in available custom01 dimension values");
                    return;
                }
                GAState.setCustomDimension01(dimension);
            });
        };
        GameAnalytics.setCustomDimension02 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension02(dimension, GAState.getAvailableCustomDimensions02())) {
                    GALogger.w("Could not set custom02 dimension value to '" + dimension + "'. Value not found in available custom02 dimension values");
                    return;
                }
                GAState.setCustomDimension02(dimension);
            });
        };
        GameAnalytics.setCustomDimension03 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension03(dimension, GAState.getAvailableCustomDimensions03())) {
                    GALogger.w("Could not set custom03 dimension value to '" + dimension + "'. Value not found in available custom03 dimension values");
                    return;
                }
                GAState.setCustomDimension03(dimension);
            });
        };
        GameAnalytics.setGlobalCustomEventFields = function (customFields) {
            if (customFields === void 0) { customFields = {}; }
            GAThreading.performTaskOnGAThread(function () {
                GALogger.i("Set global custom event fields: " + JSON.stringify(customFields));
                GAState.instance.currentGlobalCustomEventFields = customFields;
            });
        };
        GameAnalytics.setEventProcessInterval = function (intervalInSeconds) {
            GAThreading.performTaskOnGAThread(function () {
                GAThreading.setEventProcessInterval(intervalInSeconds);
            });
        };
        GameAnalytics.startSession = function () {
            {
                if (!GAState.isInitialized()) {
                    return;
                }
                GAThreading.performTaskOnGAThread(function () {
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAThreading.endSessionAndStopQueue();
                    }
                    GameAnalytics.resumeSessionAndStartQueue();
                });
            }
        };
        GameAnalytics.endSession = function () {
            {
                GameAnalytics.onStop();
            }
        };
        GameAnalytics.onStop = function () {
            GAThreading.performTaskOnGAThread(function () {
                try {
                    GAThreading.endSessionAndStopQueue();
                }
                catch (Exception) {
                }
            });
        };
        GameAnalytics.onResume = function () {
            GAThreading.performTaskOnGAThread(function () {
                GameAnalytics.resumeSessionAndStartQueue();
            });
        };
        GameAnalytics.getRemoteConfigsValueAsString = function (key, defaultValue) {
            if (defaultValue === void 0) { defaultValue = null; }
            return GAState.getConfigurationStringValue(key, defaultValue);
        };
        GameAnalytics.getRemoteConfigsValueAsJSON = function (key, defaultValue) {
            if (defaultValue === void 0) { defaultValue = null; }
            return GAState.getConfigurationJsonValue(key, defaultValue);
        };
        GameAnalytics.isRemoteConfigsReady = function () {
            return GAState.isRemoteConfigsReady();
        };
        GameAnalytics.addRemoteConfigsListener = function (listener) {
            GAState.addRemoteConfigsListener(listener);
        };
        GameAnalytics.removeRemoteConfigsListener = function (listener) {
            GAState.removeRemoteConfigsListener(listener);
        };
        GameAnalytics.getRemoteConfigsContentAsString = function () {
            return GAState.getRemoteConfigsContentAsString();
        };
        GameAnalytics.getABTestingId = function () {
            return GAState.getABTestingId();
        };
        GameAnalytics.getABTestingVariantId = function () {
            return GAState.getABTestingVariantId();
        };
        GameAnalytics.addOnBeforeUnloadListener = function (listener) {
            GAState.addOnBeforeUnloadListener(listener);
        };
        GameAnalytics.removeOnBeforeUnloadListener = function (listener) {
            GAState.removeOnBeforeUnloadListener(listener);
        };
        GameAnalytics.internalInitialize = function () {
            GAState.ensurePersistedStates();
            GAStore.setItem(GAState.getGameKey(), GAState.DefaultUserIdKey, GAState.getDefaultId());
            GAState.setInitialized(true);
            GameAnalytics.newSession();
            if (GAState.isEnabled()) {
                GAThreading.ensureEventQueueIsRunning();
            }
        };
        GameAnalytics.newSession = function () {
            GALogger.i("Starting a new session.");
            GAState.validateAndFixCurrentDimensions();
            GAHTTPApi.instance.requestInit(GAState.instance.configsHash, GameAnalytics.startNewSessionCallback);
        };
        GameAnalytics.startNewSessionCallback = function (initResponse, initResponseDict) {
            if ((initResponse === EGAHTTPApiResponse.Ok || initResponse === EGAHTTPApiResponse.Created) && initResponseDict) {
                var timeOffsetSeconds = 0;
                if (initResponseDict["server_ts"]) {
                    var serverTs = initResponseDict["server_ts"];
                    timeOffsetSeconds = GAState.calculateServerTimeOffset(serverTs);
                }
                initResponseDict["time_offset"] = timeOffsetSeconds;
                if (initResponse != EGAHTTPApiResponse.Created) {
                    var currentSdkConfig = GAState.getSdkConfig();
                    if (currentSdkConfig["configs"]) {
                        initResponseDict["configs"] = currentSdkConfig["configs"];
                    }
                    if (currentSdkConfig["configs_hash"]) {
                        initResponseDict["configs_hash"] = currentSdkConfig["configs_hash"];
                    }
                    if (currentSdkConfig["ab_id"]) {
                        initResponseDict["ab_id"] = currentSdkConfig["ab_id"];
                    }
                    if (currentSdkConfig["ab_variant_id"]) {
                        initResponseDict["ab_variant_id"] = currentSdkConfig["ab_variant_id"];
                    }
                }
                GAState.instance.configsHash = initResponseDict["configs_hash"] ? initResponseDict["configs_hash"] : "";
                GAState.instance.abId = initResponseDict["ab_id"] ? initResponseDict["ab_id"] : "";
                GAState.instance.abVariantId = initResponseDict["ab_variant_id"] ? initResponseDict["ab_variant_id"] : "";
                GAStore.setItem(GAState.getGameKey(), GAState.SdkConfigCachedKey, GAUtilities.encode64(JSON.stringify(initResponseDict)));
                GAState.instance.sdkConfigCached = initResponseDict;
                GAState.instance.sdkConfig = initResponseDict;
                GAState.instance.initAuthorized = true;
            }
            else if (initResponse == EGAHTTPApiResponse.Unauthorized) {
                GALogger.w("Initialize SDK failed - Unauthorized");
                GAState.instance.initAuthorized = false;
            }
            else {
                if (initResponse === EGAHTTPApiResponse.NoResponse || initResponse === EGAHTTPApiResponse.RequestTimeout) {
                    GALogger.i("Init call (session start) failed - no response. Could be offline or timeout.");
                }
                else if (initResponse === EGAHTTPApiResponse.BadResponse || initResponse === EGAHTTPApiResponse.JsonEncodeFailed || initResponse === EGAHTTPApiResponse.JsonDecodeFailed) {
                    GALogger.i("Init call (session start) failed - bad response. Could be bad response from proxy or GA servers.");
                }
                else if (initResponse === EGAHTTPApiResponse.BadRequest || initResponse === EGAHTTPApiResponse.UnknownResponseCode) {
                    GALogger.i("Init call (session start) failed - bad request or unknown response.");
                }
                if (GAState.instance.sdkConfig == null) {
                    if (GAState.instance.sdkConfigCached != null) {
                        GALogger.i("Init call (session start) failed - using cached init values.");
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigCached;
                    }
                    else {
                        GALogger.i("Init call (session start) failed - using default init values.");
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigDefault;
                    }
                }
                else {
                    GALogger.i("Init call (session start) failed - using cached init values.");
                }
                GAState.instance.initAuthorized = true;
            }
            GAState.instance.clientServerTimeOffset = GAState.getSdkConfig()["time_offset"] ? GAState.getSdkConfig()["time_offset"] : 0;
            GAState.populateConfigurations(GAState.getSdkConfig());
            if (!GAState.isEnabled()) {
                GALogger.w("Could not start session: SDK is disabled.");
                GAThreading.stopEventQueue();
                return;
            }
            else {
                GAThreading.ensureEventQueueIsRunning();
            }
            var newSessionId = GAUtilities.createGuid();
            GAState.instance.sessionId = newSessionId;
            GAState.instance.sessionStart = GAState.getClientTsAdjusted();
            GAEvents.addSessionStartEvent();
            GAEvents.addSDKInitEvent();
        };
        GameAnalytics.resumeSessionAndStartQueue = function () {
            if (!GAState.isInitialized()) {
                return;
            }
            GALogger.i("Resuming session.");
            if (!GAState.sessionIsStarted()) {
                GameAnalytics.newSession();
            }
        };
        GameAnalytics.isSdkReady = function (needsInitialized, warn, message) {
            if (warn === void 0) { warn = true; }
            if (message === void 0) { message = ""; }
            if (message) {
                message = message + ": ";
            }
            if (needsInitialized && !GAState.isInitialized()) {
                if (warn) {
                    GALogger.w(message + "SDK is not initialized");
                }
                return false;
            }
            if (needsInitialized && !GAState.isEnabled()) {
                if (warn) {
                    GALogger.w(message + "SDK is disabled");
                }
                return false;
            }
            if (needsInitialized && !GAState.sessionIsStarted()) {
                if (warn) {
                    GALogger.w(message + "Session has not started yet");
                }
                return false;
            }
            return true;
        };
        GameAnalytics.methodMap = {};
        return GameAnalytics;
    }());
    gameanalytics.GameAnalytics = GameAnalytics;
})(gameanalytics || (gameanalytics = {}));
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9QdWJsaWNFbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2hlYWx0aC9HQUhlYWx0aC50cyIsInNyYy9ldmVudHMvR0FFdmVudHMudHMiLCJzcmMvdGhyZWFkaW5nL0dBVGhyZWFkaW5nLnRzIiwic3JjL0dhbWVBbmFseXRpY3MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsSUFBTyxhQUFhLENBdUpuQjtBQXZKRCxXQUFPLGFBQWE7SUFFaEIsSUFBWSxnQkFPWDtJQVBELFdBQVksZ0JBQWdCO1FBQ3hCLGlFQUFhLENBQUE7UUFDYix5REFBUyxDQUFBO1FBQ1QsdURBQVEsQ0FBQTtRQUNSLDZEQUFXLENBQUE7UUFDWCx5REFBUyxDQUFBO1FBQ1QsK0RBQVksQ0FBQTtJQUNoQixDQUFDLEVBUFcsZ0JBQWdCLEdBQWhCLDhCQUFnQixLQUFoQiw4QkFBZ0IsUUFPM0I7SUFFRCxJQUFZLG9CQUtYO0lBTEQsV0FBWSxvQkFBb0I7UUFDNUIseUVBQWEsQ0FBQTtRQUNiLGlFQUFTLENBQUE7UUFDVCx1RUFBWSxDQUFBO1FBQ1osK0RBQVEsQ0FBQTtJQUNaLENBQUMsRUFMVyxvQkFBb0IsR0FBcEIsa0NBQW9CLEtBQXBCLGtDQUFvQixRQUsvQjtJQUVELElBQVksbUJBSVg7SUFKRCxXQUFZLG1CQUFtQjtRQUMzQix1RUFBYSxDQUFBO1FBQ2IsaUVBQVUsQ0FBQTtRQUNWLDZEQUFRLENBQUE7SUFDWixDQUFDLEVBSlcsbUJBQW1CLEdBQW5CLGlDQUFtQixLQUFuQixp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QkFBQSxFQUFBLFlBQW1CO1lBRXhGLElBQUcsT0FBTyxFQUNWO2dCQUNJLE9BQU8sR0FBRyxPQUFPLEdBQUcsSUFBSSxDQUFDO2FBQzVCO1lBR0QsSUFBSSxnQkFBZ0IsSUFBSSxDQUFDLE9BQU8sQ0FBQyxhQUFhLEVBQUUsRUFDaEQ7Z0JBQ0ksSUFBSSxJQUFJLEVBQ1I7b0JBQ0ksUUFBUSxDQUFDLENBQUMsQ0FBQyxPQUFPLEdBQUcsd0JBQXdCLENBQUMsQ0FBQztpQkFDbEQ7Z0JBQ0QsT0FBTyxLQUFLLENBQUM7YUFDaEI7WUFFRCxJQUFJLGdCQUFnQixJQUFJLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxFQUM1QztnQkFDSSxJQUFJLElBQUksRUFDUjtvQkFDSSxRQUFRLENBQUMsQ0FBQyxDQUFDLE9BQU8sR0FBRyxpQkFBaUIsQ0FBQyxDQUFDO2lCQUMzQztnQkFDRCxPQUFPLEtBQUssQ0FBQzthQUNoQjtZQUVELElBQUksZ0JBQWdCLElBQUksQ0FBQyxPQUFPLENBQUMsZ0JBQWdCLEVBQUUsRUFDbkQ7Z0JBQ0ksSUFBSSxJQUFJLEVBQ1I7b0JBQ0ksUUFBUSxDQUFDLENBQUMsQ0FBQyxPQUFPLEdBQUcsNkJBQTZCLENBQUMsQ0FBQztpQkFDdkQ7Z0JBQ0QsT0FBTyxLQUFLLENBQUM7YUFDaEI7WUFDRCxPQUFPLElBQUksQ0FBQztRQUNoQixDQUFDO1FBcjNCSyx1QkFBUyxHQUEyQyxFQUFFLENBQUM7UUFzM0JqRSxvQkFBQztLQXgzQkQsQUF3M0JDLElBQUE7SUF4M0JZLDJCQUFhLGdCQXczQnpCLENBQUE7QUFDTCxDQUFDLEVBdjRCTSxhQUFhLEtBQWIsYUFBYSxRQXU0Qm5CO0FBQ0QsYUFBYSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUNuQyxJQUFJLGFBQWEsR0FBRyxhQUFhLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyIsImZpbGUiOiJkaXN0L0dhbWVBbmFseXRpY3MuZGVidWcuanMiLCJzb3VyY2VzQ29udGVudCI6WyJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHkge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBEZWJ1ZyA9IDEsXG4gICAgICAgIEluZm8gPSAyLFxuICAgICAgICBXYXJuaW5nID0gMyxcbiAgICAgICAgRXJyb3IgPSA0LFxuICAgICAgICBDcml0aWNhbCA9IDVcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FQcm9ncmVzc2lvblN0YXR1cyB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFN0YXJ0ID0gMSxcbiAgICAgICAgQ29tcGxldGUgPSAyLFxuICAgICAgICBGYWlsID0gM1xuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVJlc291cmNlRmxvd1R5cGUge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkQWN0aW9uIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgQ2xpY2tlZCA9IDEsXG4gICAgICAgIFNob3cgPSAyLFxuICAgICAgICBGYWlsZWRTaG93ID0gMyxcbiAgICAgICAgUmV3YXJkUmVjZWl2ZWQgPSA0XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRFcnJvciB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFVua25vd24gPSAxLFxuICAgICAgICBPZmZsaW5lID0gMixcbiAgICAgICAgTm9GaWxsID0gMyxcbiAgICAgICAgSW50ZXJuYWxFcnJvciA9IDQsXG4gICAgICAgIEludmFsaWRSZXF1ZXN0ID0gNSxcbiAgICAgICAgVW5hYmxlVG9QcmVjYWNoZSA9IDZcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZFR5cGUge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBWaWRlbyA9IDEsXG4gICAgICAgIFJld2FyZGVkVmlkZW8gPSAyLFxuICAgICAgICBQbGF5YWJsZSA9IDMsXG4gICAgICAgIEludGVyc3RpdGlhbCA9IDQsXG4gICAgICAgIE9mZmVyV2FsbCA9IDUsXG4gICAgICAgIEJhbm5lciA9IDZcbiAgICB9XG5cbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBjbGllbnRcbiAgICAgICAgICAgIE5vUmVzcG9uc2UsXG4gICAgICAgICAgICBCYWRSZXNwb25zZSxcbiAgICAgICAgICAgIFJlcXVlc3RUaW1lb3V0LCAvLyA0MDhcbiAgICAgICAgICAgIEpzb25FbmNvZGVGYWlsZWQsXG4gICAgICAgICAgICBKc29uRGVjb2RlRmFpbGVkLFxuICAgICAgICAgICAgLy8gc2VydmVyXG4gICAgICAgICAgICBJbnRlcm5hbFNlcnZlckVycm9yLFxuICAgICAgICAgICAgQmFkUmVxdWVzdCwgLy8gNDAwXG4gICAgICAgICAgICBVbmF1dGhvcml6ZWQsIC8vIDQwMVxuICAgICAgICAgICAgVW5rbm93blJlc3BvbnNlQ29kZSxcbiAgICAgICAgICAgIE9rLFxuICAgICAgICAgICAgQ3JlYXRlZFxuICAgICAgICB9XG4gICAgfVxuXG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcbiAgICB7XG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQ2F0ZWdvcnlcbiAgICAgICAge1xuICAgICAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgICAgIEV2ZW50VmFsaWRhdGlvbiA9IDEsXG4gICAgICAgICAgICBEYXRhYmFzZSA9IDIsXG4gICAgICAgICAgICBJbml0ID0gMyxcbiAgICAgICAgICAgIEh0dHAgPSA0LFxuICAgICAgICAgICAgSnNvbiA9IDVcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQXJlYVxuICAgICAgICB7XG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICAgICAgQnVzaW5lc3NFdmVudCA9IDEsXG4gICAgICAgICAgICBSZXNvdXJjZUV2ZW50ID0gMixcbiAgICAgICAgICAgIFByb2dyZXNzaW9uRXZlbnQgPSAzLFxuICAgICAgICAgICAgRGVzaWduRXZlbnQgPSA0LFxuICAgICAgICAgICAgRXJyb3JFdmVudCA9IDUsXG4gICAgICAgICAgICBJbml0SHR0cCA9IDksXG4gICAgICAgICAgICBFdmVudHNIdHRwID0gMTAsXG4gICAgICAgICAgICBQcm9jZXNzRXZlbnRzID0gMTEsXG4gICAgICAgICAgICBBZGRFdmVudHNUb1N0b3JlID0gMTIsXG4gICAgICAgICAgICBBZEV2ZW50ID0gMjBcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQWN0aW9uXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBJbnZhbGlkQ3VycmVuY3kgPSAxLFxuICAgICAgICAgICAgSW52YWxpZFNob3J0U3RyaW5nID0gMixcbiAgICAgICAgICAgIEludmFsaWRFdmVudFBhcnRMZW5ndGggPSAzLFxuICAgICAgICAgICAgSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMgPSA0LFxuICAgICAgICAgICAgSW52YWxpZFN0b3JlID0gNSxcbiAgICAgICAgICAgIEludmFsaWRGbG93VHlwZSA9IDYsXG4gICAgICAgICAgICBTdHJpbmdFbXB0eU9yTnVsbCA9IDcsXG4gICAgICAgICAgICBOb3RGb3VuZEluQXZhaWxhYmxlQ3VycmVuY2llcyA9IDgsXG4gICAgICAgICAgICBJbnZhbGlkQW1vdW50ID0gOSxcbiAgICAgICAgICAgIE5vdEZvdW5kSW5BdmFpbGFibGVJdGVtVHlwZXMgPSAxMCxcbiAgICAgICAgICAgIFdyb25nUHJvZ3Jlc3Npb25PcmRlciA9IDExLFxuICAgICAgICAgICAgSW52YWxpZEV2ZW50SWRMZW5ndGggPSAxMixcbiAgICAgICAgICAgIEludmFsaWRFdmVudElkQ2hhcmFjdGVycyA9IDEzLFxuICAgICAgICAgICAgSW52YWxpZFByb2dyZXNzaW9uU3RhdHVzID0gMTUsXG4gICAgICAgICAgICBJbnZhbGlkU2V2ZXJpdHkgPSAxNixcbiAgICAgICAgICAgIEludmFsaWRMb25nU3RyaW5nID0gMTcsXG4gICAgICAgICAgICBEYXRhYmFzZVRvb0xhcmdlID0gMTgsXG4gICAgICAgICAgICBEYXRhYmFzZU9wZW5PckNyZWF0ZSA9IDE5LFxuICAgICAgICAgICAgSnNvbkVycm9yID0gMjUsXG4gICAgICAgICAgICBGYWlsSHR0cEpzb25EZWNvZGUgPSAyOSxcbiAgICAgICAgICAgIEZhaWxIdHRwSnNvbkVuY29kZSA9IDMwLFxuICAgICAgICAgICAgSW52YWxpZEFkQWN0aW9uID0gMzEsXG4gICAgICAgICAgICBJbnZhbGlkQWRUeXBlID0gMzIsXG4gICAgICAgICAgICBJbnZhbGlkU3RyaW5nID0gMzNcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yUGFyYW1ldGVyXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBDdXJyZW5jeSA9IDEsXG4gICAgICAgICAgICBDYXJ0VHlwZSA9IDIsXG4gICAgICAgICAgICBJdGVtVHlwZSA9IDMsXG4gICAgICAgICAgICBJdGVtSWQgPSA0LFxuICAgICAgICAgICAgU3RvcmUgPSA1LFxuICAgICAgICAgICAgRmxvd1R5cGUgPSA2LFxuICAgICAgICAgICAgQW1vdW50ID0gNyxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uMDEgPSA4LFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24wMiA9IDksXG4gICAgICAgICAgICBQcm9ncmVzc2lvbjAzID0gMTAsXG4gICAgICAgICAgICBFdmVudElkID0gMTEsXG4gICAgICAgICAgICBQcm9ncmVzc2lvblN0YXR1cyA9IDEyLFxuICAgICAgICAgICAgU2V2ZXJpdHkgPSAxMyxcbiAgICAgICAgICAgIE1lc3NhZ2UgPSAxNCxcbiAgICAgICAgICAgIEFkQWN0aW9uID0gMTUsXG4gICAgICAgICAgICBBZFR5cGUgPSAxNixcbiAgICAgICAgICAgIEFkU2RrTmFtZSA9IDE3LFxuICAgICAgICAgICAgQWRQbGFjZW1lbnQgPSAxOFxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIHB1YmxpY19lbnVtc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHlcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIERlYnVnID0gMSxcbiAgICAgICAgSW5mbyA9IDIsXG4gICAgICAgIFdhcm5pbmcgPSAzLFxuICAgICAgICBFcnJvciA9IDQsXG4gICAgICAgIENyaXRpY2FsID0gNVxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVByb2dyZXNzaW9uU3RhdHVzXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTdGFydCA9IDEsXG4gICAgICAgIENvbXBsZXRlID0gMixcbiAgICAgICAgRmFpbCA9IDNcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkQWN0aW9uXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBDbGlja2VkID0gMSxcbiAgICAgICAgU2hvdyA9IDIsXG4gICAgICAgIEZhaWxlZFNob3cgPSAzLFxuICAgICAgICBSZXdhcmRSZWNlaXZlZCA9IDRcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZEVycm9yXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBVbmtub3duID0gMSxcbiAgICAgICAgT2ZmbGluZSA9IDIsXG4gICAgICAgIE5vRmlsbCA9IDMsXG4gICAgICAgIEludGVybmFsRXJyb3IgPSA0LFxuICAgICAgICBJbnZhbGlkUmVxdWVzdCA9IDUsXG4gICAgICAgIFVuYWJsZVRvUHJlY2FjaGUgPSA2XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBWaWRlbyA9IDEsXG4gICAgICAgIFJld2FyZGVkVmlkZW8gPSAyLFxuICAgICAgICBQbGF5YWJsZSA9IDMsXG4gICAgICAgIEludGVyc3RpdGlhbCA9IDQsXG4gICAgICAgIE9mZmVyV2FsbCA9IDUsXG4gICAgICAgIEJhbm5lciA9IDZcbiAgICB9XG59XG4iLCIvL0dBTE9HR0VSX1NUQVJUXG5tb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xuICAgIHtcbiAgICAgICAgZW51bSBFR0FMb2dnZXJNZXNzYWdlVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBFcnJvciA9IDAsXG4gICAgICAgICAgICBXYXJuaW5nID0gMSxcbiAgICAgICAgICAgIEluZm8gPSAyLFxuICAgICAgICAgICAgRGVidWcgPSAzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FMb2dnZXJcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUxvZ2dlciA9IG5ldyBHQUxvZ2dlcigpO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nVmVyYm9zZUVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGRlYnVnRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xuXG4gICAgICAgICAgICAvLyBGaWVsZHMgYW5kIHByb3BlcnRpZXM6IEVORFxuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kZWJ1Z0VuYWJsZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBTVEFSVFxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluZm9Mb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFZlcmJvc2VMb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiSW5mby9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB3KGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJXYXJuaW5nL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGUoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkVycm9yL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkluZm8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGQoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRGVidWcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh0eXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmc6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlb2YgY29uc29sZS5kZWJ1ZyA9PT0gXCJmdW5jdGlvblwiKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ldGhvZHM6IEVORFxuICAgICAgICB9XG4gICAgfVxufVxuLy9HQUxPR0dFUl9FTkRcbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB1dGlsaXRpZXNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FVdGlsaXRpZXNcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRIbWFjKGtleTpzdHJpbmcsIGRhdGE6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGVuY3J5cHRlZE1lc3NhZ2UgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KGRhdGEsIGtleSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ01hdGNoKHM6c3RyaW5nLCBwYXR0ZXJuOlJlZ0V4cCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighcyB8fCAhcGF0dGVybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF0dGVybi50ZXN0KHMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGpvaW5TdHJpbmdBcnJheSh2OkFycmF5PHN0cmluZz4sIGRlbGltaXRlcjpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwiXCI7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMCwgaWwgPSB2Lmxlbmd0aDsgaSA8IGlsOyBpKyspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoaSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSBkZWxpbWl0ZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IHZbaV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhcnJheTpBcnJheTxzdHJpbmc+LCBzZWFyY2g6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhcnJheS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGFycmF5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJyYXlbc10gPT09IHNlYXJjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBrZXlTdHI6c3RyaW5nID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlucHV0ID0gZW5jb2RlVVJJKGlucHV0KTtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIyID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG5cbiAgICAgICAgICAgICAgICAgICBlbmMxID0gY2hyMSA+PiAyO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSAoKGNocjEgJiAzKSA8PCA0KSB8IChjaHIyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSAoKGNocjIgJiAxNSkgPDwgMikgfCAoY2hyMyA+PiA2KTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gY2hyMyAmIDYzO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGlzTmFOKGNocjIpKVxuICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICBlbmMzID0gZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChpc05hTihjaHIzKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMxKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMyKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMzKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmM0KTtcbiAgICAgICAgICAgICAgICAgICBjaHIxID0gY2hyMiA9IGNocjMgPSAwO1xuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBlbmMyID0gZW5jMyA9IGVuYzQgPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gb3V0cHV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBvdXRwdXQ6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgY2hyMTpudW1iZXIsIGNocjI6bnVtYmVyLCBjaHIzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGVuYzE6bnVtYmVyLCBlbmMyOm51bWJlciwgZW5jMzpudW1iZXIsIGVuYzQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgaSA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyByZW1vdmUgYWxsIGNoYXJhY3RlcnMgdGhhdCBhcmUgbm90IEEtWiwgYS16LCAwLTksICssIC8sIG9yID1cbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0dGVzdCA9IC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZztcbiAgICAgICAgICAgICAgICBpZiAoYmFzZTY0dGVzdC5leGVjKGlucHV0KSkge1xuICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJUaGVyZSB3ZXJlIGludmFsaWQgYmFzZTY0IGNoYXJhY3RlcnMgaW4gdGhlIGlucHV0IHRleHQuIFZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGFyZSBBLVosIGEteiwgMC05LCAnKycsICcvJyxhbmQgJz0nLiBFeHBlY3QgZXJyb3JzIGluIGRlY29kaW5nLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5wdXQgPSBpbnB1dC5yZXBsYWNlKC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZywgXCJcIik7XG5cbiAgICAgICAgICAgICAgICBkb1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jMyA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IChlbmMxIDw8IDIpIHwgKGVuYzIgPj4gNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9ICgoZW5jMiAmIDE1KSA8PCA0KSB8IChlbmMzID4+IDIpO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSAoKGVuYzMgJiAzKSA8PCA2KSB8IGVuYzQ7XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjEpO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzMgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjIpO1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBpZiAoZW5jNCAhPSA2NCkge1xuICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArIFN0cmluZy5mcm9tQ2hhckNvZGUoY2hyMyk7XG4gICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gZGVjb2RlVVJJKG91dHB1dCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdGltZUludGVydmFsU2luY2UxOTcwKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBkYXRlOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBNYXRoLnJvdW5kKGRhdGUuZ2V0VGltZSgpIC8gMTAwMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlR3VpZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKFwiMTAwMDAwMDAtMTAwMC00MDAwLTgwMDAtMTAwMDAwMDAwMDAwXCIpLnJlcGxhY2UoL1swMThdL2csIGMgPT4gKCtjIF4gY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSgxKSlbMF0gJiAxNSA+PiArYyAvIDQpLnRvU3RyaW5nKDE2KSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdmFsaWRhdG9yc1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yQ2F0ZWdvcnkgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckNhdGVnb3J5O1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBcmVhID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JBcmVhO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBY3Rpb24gPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFjdGlvbjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yUGFyYW1ldGVyID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JQYXJhbWV0ZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIGNhdGVnb3J5OkVHQVNka0Vycm9yQ2F0ZWdvcnk7XG4gICAgICAgICAgICBwdWJsaWMgYXJlYTpFR0FTZGtFcnJvckFyZWE7XG4gICAgICAgICAgICBwdWJsaWMgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uO1xuICAgICAgICAgICAgcHVibGljIHBhcmFtZXRlcjpFR0FTZGtFcnJvclBhcmFtZXRlcjtcbiAgICAgICAgICAgIHB1YmxpYyByZWFzb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IoY2F0ZWdvcnk6RUdBU2RrRXJyb3JDYXRlZ29yeSwgYXJlYTpFR0FTZGtFcnJvckFyZWEsIGFjdGlvbjpFR0FTZGtFcnJvckFjdGlvbiwgcGFyYW1ldGVyOkVHQVNka0Vycm9yUGFyYW1ldGVyLCByZWFzb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuY2F0ZWdvcnkgPSBjYXRlZ29yeTtcbiAgICAgICAgICAgICAgICB0aGlzLmFyZWEgPSBhcmVhO1xuICAgICAgICAgICAgICAgIHRoaXMuYWN0aW9uID0gYWN0aW9uO1xuICAgICAgICAgICAgICAgIHRoaXMucGFyYW1ldGVyID0gcGFyYW1ldGVyO1xuICAgICAgICAgICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVmFsaWRhdG9yXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgY2FydFR5cGU6c3RyaW5nLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVuY3lcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VycmVuY3koY3VycmVuY3kpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbCkgYW5kIG5lZWQgdG8gYmUgQS1aLCAzIGNoYXJhY3RlcnMgYW5kIGluIHRoZSBzdGFuZGFyZCBhdCBvcGVuZXhjaGFuZ2VyYXRlcy5vcmcuIEZhaWxlZCBjdXJyZW5jeTogXCIgKyBjdXJyZW5jeSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRDdXJyZW5jeSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ3VycmVuY3ksIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoYW1vdW50IDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGFtb3VudC4gQ2Fubm90IGJlIGxlc3MgdGhhbiAwLiBGYWlsZWQgYW1vdW50OiBcIiArIGFtb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFtb3VudCwgYW1vdW50ICsgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY2FydFR5cGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY2FydFR5cGUuIENhbm5vdCBiZSBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBjYXJ0VHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTaG9ydFN0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ2FydFR5cGUsIGNhcnRUeXBlKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbVR5cGUsIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBjaGFyc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1UeXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1UeXBlLCBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbUlkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZC4gQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZCwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtSWQsIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBhdmFpbGFibGVDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4sIGF2YWlsYWJsZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+KTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGZsb3dUeXBlOiBJbnZhbGlkIGZsb3cgdHlwZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRGbG93VHlwZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRmxvd1R5cGUsIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsLCBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVDdXJyZW5jaWVzLCBjdXJyZW5jeSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBjdXJyZW5jeTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMuIFN0cmluZzogXCIgKyBjdXJyZW5jeSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLk5vdEZvdW5kSW5BdmFpbGFibGVDdXJyZW5jaWVzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeSwgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIShhbW91bnQgPiAwKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGFtb3VudDogRmxvYXQgYW1vdW50IGNhbm5vdCBiZSAwIG9yIG5lZ2F0aXZlLiBWYWx1ZTogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkQW1vdW50LCBFR0FTZGtFcnJvclBhcmFtZXRlci5BbW91bnQsIGFtb3VudCArIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWl0ZW1UeXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlSXRlbVR5cGVzLCBpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGl0ZW1UeXBlcy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uTm90Rm91bmRJbkF2YWlsYWJsZUl0ZW1UeXBlcywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbVR5cGUsIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZCwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbUlkLCBpdGVtSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXM6RUdBUHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDE6c3RyaW5nLCBwcm9ncmVzc2lvbjAyOnN0cmluZywgcHJvZ3Jlc3Npb24wMzpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogSW52YWxpZCBwcm9ncmVzc2lvbiBzdGF0dXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkUHJvZ3Jlc3Npb25TdGF0dXMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uU3RhdHVzLCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBNYWtlIHN1cmUgcHJvZ3Jlc3Npb25zIGFyZSBkZWZpbmVkIGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiAwMyBmb3VuZCBidXQgMDErMDIgYXJlIGludmFsaWQuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXIsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHByb2dyZXNzaW9uMDIgJiYgIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAyIGZvdW5kIGJ1dCBub3QgMDEuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLldyb25nUHJvZ3Jlc3Npb25PcmRlciwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uV3JvbmdQcm9ncmVzc2lvbk9yZGVyLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIChwcm9ncmVzc2lvbjAxID8gcHJvZ3Jlc3Npb24wMSA6IFwiXCIpICsgXCI6XCIgKyAocHJvZ3Jlc3Npb24wMiA/IHByb2dyZXNzaW9uMDIgOiBcIlwiKSArIFwiOlwiICsgKHByb2dyZXNzaW9uMDMgPyBwcm9ncmVzc2lvbjAzIDogXCJcIikpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDEgKHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMiwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDI6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAyKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMjogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAzXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDMsIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAzOiBDYW5ub3QgYmUgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMywgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMywgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkOnN0cmluZyk6IFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRJZExlbmd0aChldmVudElkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBDYW5ub3QgYmUgKG51bGwpIG9yIGVtcHR5LiBPbmx5IDUgZXZlbnQgcGFydHMgYWxsb3dlZCBzZXBlcmF0ZWQgYnkgOi4gRWFjaCBwYXJ0IG5lZWQgdG8gYmUgNjQgY2hhcmFjdGVycyBvciBsZXNzLiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkRlc2lnbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRJZExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRXZlbnRJZCwgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBOb24gdmFsaWQgY2hhcmFjdGVycy4gT25seSBhbGxvd2VkIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuRGVzaWduRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkQ2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRXZlbnRJZCwgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbHVlOiBhbGxvdyAwLCBuZWdhdGl2ZSBhbmQgbmlsIChub3QgcmVxdWlyZWQpXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5OkVHQUVycm9yU2V2ZXJpdHksIG1lc3NhZ2U6c3RyaW5nKTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChzZXZlcml0eSA9PSBFR0FFcnJvclNldmVyaXR5LlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIHNldmVyaXR5OiBTZXZlcml0eSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU2V2ZXJpdHksIEVHQVNka0Vycm9yUGFyYW1ldGVyLlNldmVyaXR5LCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUxvbmdTdHJpbmcobWVzc2FnZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBtZXNzYWdlOiBNZXNzYWdlIGNhbm5vdCBiZSBhYm92ZSA4MTkyIGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkTG9uZ1N0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQWRFdmVudChhZEFjdGlvbjpFR0FBZEFjdGlvbiwgYWRUeXBlOkVHQUFkVHlwZSwgYWRTZGtOYW1lOnN0cmluZywgYWRQbGFjZW1lbnQ6c3RyaW5nKTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhZEFjdGlvbiA9PSBFR0FBZEFjdGlvbi5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBzZXZlcml0eTogU2V2ZXJpdHkgd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQWRFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEFkQWN0aW9uLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZEFjdGlvbiwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChhZFR5cGUgPT0gRUdBQWRUeXBlLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBhZCBldmVudCAtIGFkVHlwZTogQWQgdHlwZSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5BZEV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkQWRUeXBlLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZFR5cGUsIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoYWRTZGtOYW1lLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYWQgZXZlbnQgLSBtZXNzYWdlOiBBZCBTREsgbmFtZSBjYW5ub3QgYmUgYWJvdmUgMzIgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkFkRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTaG9ydFN0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQWRTZGtOYW1lLCBhZFNka05hbWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU3RyaW5nKGFkUGxhY2VtZW50LCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYWQgZXZlbnQgLSBtZXNzYWdlOiBBZCBwbGFjZW1lbnQgY2Fubm90IGJlIGFib3ZlIDY0IGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5BZEV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU3RyaW5nLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZFBsYWNlbWVudCwgYWRQbGFjZW1lbnQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka0Vycm9yRXZlbnQoZ2FtZUtleTpzdHJpbmcsIGdhbWVTZWNyZXQ6c3RyaW5nLCBjYXRlZ29yeTpFR0FTZGtFcnJvckNhdGVnb3J5LCBhcmVhOkVHQVNka0Vycm9yQXJlYSwgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGNhdGVnb3J5ID09PSBFR0FTZGtFcnJvckNhdGVnb3J5LlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBzZGsgZXJyb3IgZXZlbnQgLSB0eXBlOiBDYXRlZ29yeSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChhcmVhID09PSBFR0FTZGtFcnJvckFyZWEuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHNkayBlcnJvciBldmVudCAtIHR5cGU6IEFyZWEgd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoYWN0aW9uID09PSBFR0FTZGtFcnJvckFjdGlvbi5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogQWN0aW9uIHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVLZXlzKGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZUtleSwgL15bQS16MC05XXszMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZVNlY3JldCwgL15bQS16MC05XXs0MH0kLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGN1cnJlbmN5LCAvXltBLVpdezN9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydExlbmd0aChldmVudFBhcnQ6c3RyaW5nLCBhbGxvd051bGw6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOdWxsICYmICFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50UGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoZXZlbnRQYXJ0Lmxlbmd0aCA+IDY0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoZXZlbnRQYXJ0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50UGFydCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZExlbmd0aChldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXlteOl17MSw2NH0oPzo6W146XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSg6W0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9KXswLDR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShpbml0UmVzcG9uc2U6e1trZXk6c3RyaW5nXTogYW55fSwgY29uZmlnc0NyZWF0ZWQ6Ym9vbGVhbik6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBtYWtlIHN1cmUgd2UgaGF2ZSBhIHZhbGlkIGRpY3RcbiAgICAgICAgICAgICAgICBpZiAoaW5pdFJlc3BvbnNlID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIG5vIHJlc3BvbnNlIGRpY3Rpb25hcnkuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBzZXJ2ZXJfdHNcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUc051bWJlcjpudW1iZXIgPSBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl07XG4gICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJUc051bWJlciA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJzZXJ2ZXJfdHNcIl0gPSBzZXJ2ZXJUc051bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB2YWx1ZSBpbiAnc2VydmVyX3RzJyBmaWVsZC5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdzZXJ2ZXJfdHMnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihjb25maWdzQ3JlYXRlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGNvbmZpZ3MgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uczphbnlbXSA9IGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiY29uZmlnc1wiXSA9IGNvbmZpZ3VyYXRpb25zO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnY29uZmlncycgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiY29uZmlnc1wiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWdzX2hhc2g6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImNvbmZpZ3NfaGFzaFwiXSA9IGNvbmZpZ3NfaGFzaDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2NvbmZpZ3NfaGFzaCcgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX2lkIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYWJfaWQ6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiYWJfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfaWRcIl0gPSBhYl9pZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2FiX2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl9pZFwiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImFiX2lkXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX3ZhcmlhbnRfaWQgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhYl92YXJpYW50X2lkOnN0cmluZyA9IGluaXRSZXNwb25zZVtcImFiX3ZhcmlhbnRfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGFiX3ZhcmlhbnRfaWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdhYl92YXJpYW50X2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl92YXJpYW50X2lkXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiYWJfdmFyaWFudF9pZFwiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cblxuICAgICAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZWREaWN0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVpbGQoYnVpbGQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhidWlsZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHdyYXBwZXJWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHdyYXBwZXJWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZHxnb2RvdHxmbHV0dGVyKSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRW5naW5lVmVyc2lvbihlbmdpbmVWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWVuZ2luZVZlcnNpb24gfHwgIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGVuZ2luZVZlcnNpb24sIC9eKHVuaXR5fHVucmVhbHxnYW1lbWFrZXJ8Y29jb3MyZHxjb25zdHJ1Y3R8ZGVmb2xkfGdvZG90KSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlVXNlcklkKHVJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVN0cmluZyh1SWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSB1c2VyIGlkOiBpZCBjYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNob3J0U3RyaW5nKHNob3J0U3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5IG9yIG5pbFxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzaG9ydFN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghc2hvcnRTdHJpbmcgfHwgc2hvcnRTdHJpbmcubGVuZ3RoID4gMzIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU3RyaW5nKHM6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIXMgfHwgcy5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVMb25nU3RyaW5nKGxvbmdTdHJpbmc6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhbG9uZ1N0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghbG9uZ1N0cmluZyB8fCBsb25nU3RyaW5nLmxlbmd0aCA+IDgxOTIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvblR5cGU6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjb25uZWN0aW9uVHlwZSwgL14od3dhbnx3aWZpfGxhbnxvZmZsaW5lKSQvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnMoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwiY3VzdG9tIGRpbWVuc2lvbnNcIiwgY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCA2NCwgZmFsc2UsIFwicmVzb3VyY2UgY3VycmVuY2llc1wiLCByZXNvdXJjZUN1cnJlbmNpZXMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nIGZvciByZWdleFxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzb3VyY2VDdXJyZW5jaWVzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChyZXNvdXJjZUN1cnJlbmNpZXNbaV0sIC9eW0EtWmEtel0rJC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwicmVzb3VyY2UgY3VycmVuY2llcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBjdXJyZW5jeSBjYW4gb25seSBiZSBBLVosIGEtei4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUN1cnJlbmNpZXNbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJyZXNvdXJjZSBpdGVtIHR5cGVzXCIsIHJlc291cmNlSXRlbVR5cGVzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHJlc291cmNlSXRlbVR5cGUgZm9yIGV2ZW50cGFydCB2YWxpZGF0aW9uXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXNvdXJjZUl0ZW1UeXBlcy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHJlc291cmNlSXRlbVR5cGVzW2ldKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInJlc291cmNlIGl0ZW0gdHlwZXMgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgcmVzb3VyY2UgaXRlbSB0eXBlIGNhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmcgd2FzOiBcIiArIHJlc291cmNlSXRlbVR5cGVzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAxKGRpbWVuc2lvbjAxOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAxKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24wMjpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uMDM6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKG1heENvdW50Om51bWJlciwgbWF4U3RyaW5nTGVuZ3RoOm51bWJlciwgYWxsb3dOb1ZhbHVlczpib29sZWFuLCBsb2dUYWc6c3RyaW5nLCBhcnJheU9mU3RyaW5nczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhcnJheVRhZzpzdHJpbmcgPSBsb2dUYWc7XG5cbiAgICAgICAgICAgICAgICAvLyB1c2UgYXJyYXlUYWcgdG8gYW5ub3RhdGUgd2FybmluZyBsb2dcbiAgICAgICAgICAgICAgICBpZiAoIWFycmF5VGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYXJyYXlUYWcgPSBcIkFycmF5XCI7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoIWFycmF5T2ZTdHJpbmdzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgYmUgbnVsbC4gXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOb1ZhbHVlcyA9PSBmYWxzZSAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIGVtcHR5LiBcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBleGNlZWRpbmcgbWF4IGNvdW50XG4gICAgICAgICAgICAgICAgaWYgKG1heENvdW50ID4gMCAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGV4Y2VlZCBcIiArIG1heENvdW50ICsgXCIgdmFsdWVzLiBJdCBoYXMgXCIgKyBhcnJheU9mU3RyaW5ncy5sZW5ndGggKyBcIiB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmdcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5T2ZTdHJpbmdzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHN0cmluZ0xlbmd0aDpudW1iZXIgPSAhYXJyYXlPZlN0cmluZ3NbaV0gPyAwIDogYXJyYXlPZlN0cmluZ3NbaV0ubGVuZ3RoO1xuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eSAobm90IGFsbG93ZWQpXG4gICAgICAgICAgICAgICAgICAgIGlmIChzdHJpbmdMZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogY29udGFpbmVkIGFuIGVtcHR5IHN0cmluZy4gQXJyYXk9XCIgKyBKU09OLnN0cmluZ2lmeShhcnJheU9mU3RyaW5ncykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZXhjZWVkaW5nIG1heCBsZW5ndGhcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1heFN0cmluZ0xlbmd0aCA+IDAgJiYgc3RyaW5nTGVuZ3RoID4gbWF4U3RyaW5nTGVuZ3RoKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgc3RyaW5nIGV4Y2VlZGVkIG1heCBhbGxvd2VkIGxlbmd0aCAod2hpY2ggaXM6IFwiICsgbWF4U3RyaW5nTGVuZ3RoICsgXCIpLiBTdHJpbmcgd2FzOiBcIiArIGFycmF5T2ZTdHJpbmdzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoY2xpZW50VHMgPCAoMCkgfHwgY2xpZW50VHMgPiAoOTk5OTk5OTk5OTkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBkZXZpY2VcbiAgICB7XG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmFsdWVWZXJzaW9uXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBuYW1lOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyB2YWx1ZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmVyc2lvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihuYW1lOnN0cmluZywgdmFsdWU6c3RyaW5nLCB2ZXJzaW9uOnN0cmluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLm5hbWUgPSBuYW1lO1xuICAgICAgICAgICAgICAgIHRoaXMudmFsdWUgPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSB2ZXJzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIE5hbWVWZXJzaW9uXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBuYW1lOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKG5hbWU6c3RyaW5nLCB2ZXJzaW9uOnN0cmluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLm5hbWUgPSBuYW1lO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FEZXZpY2VcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgc2RrV3JhcHBlclZlcnNpb246c3RyaW5nID0gXCJqYXZhc2NyaXB0IDUuMC4wXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBvc1ZlcnNpb25QYWlyOk5hbWVWZXJzaW9uID0gR0FEZXZpY2UubWF0Y2hJdGVtKFtcbiAgICAgICAgICAgICAgICBuYXZpZ2F0b3IucGxhdGZvcm0sXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnVzZXJBZ2VudCxcbiAgICAgICAgICAgICAgICBuYXZpZ2F0b3IuYXBwVmVyc2lvbixcbiAgICAgICAgICAgICAgICBuYXZpZ2F0b3IudmVuZG9yXG4gICAgICAgICAgICBdLmpvaW4oJyAnKSwgW1xuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwid2luZG93c19waG9uZVwiLCBcIldpbmRvd3MgUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIndpbmRvd3NcIiwgXCJXaW5cIiwgXCJOVFwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQaG9uZVwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBhZFwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBvZFwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYW5kcm9pZFwiLCBcIkFuZHJvaWRcIiwgXCJBbmRyb2lkXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYmxhY2tCZXJyeVwiLCBcIkJsYWNrQmVycnlcIiwgXCIvXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwibWFjX29zeFwiLCBcIk1hY1wiLCBcIk9TIFhcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ0aXplblwiLCBcIlRpemVuXCIsIFwiVGl6ZW5cIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJsaW51eFwiLCBcIkxpbnV4XCIsIFwicnZcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJrYWlfb3NcIiwgXCJLQUlPU1wiLCBcIktBSU9TXCIpXG4gICAgICAgICAgICBdKTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBidWlsZFBsYXRmb3JtOnN0cmluZyA9IEdBRGV2aWNlLnJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1vZGVsOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1vZGVsKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1hbnVmYWN0dXJlcjpzdHJpbmcgPSBHQURldmljZS5nZXREZXZpY2VNYW51ZmFjdHVyZXIoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgb3NWZXJzaW9uOnN0cmluZyA9IEdBRGV2aWNlLmdldE9TVmVyc2lvblN0cmluZygpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBicm93c2VyVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRCcm93c2VyVmVyc2lvblN0cmluZygpO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY29ubmVjdGlvblR5cGU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB0b3VjaCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uuc2RrV3JhcHBlclZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29ubmVjdGlvblR5cGUoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihuYXZpZ2F0b3Iub25MaW5lKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSA9PT0gXCJpb3NcIiB8fCBHQURldmljZS5idWlsZFBsYXRmb3JtID09PSBcImFuZHJvaWRcIilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcInd3YW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gXCJsYW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBUT0RPOiBEZXRlY3Qgd2lmaSB1c2FnZVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwib2ZmbGluZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0T1NWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5idWlsZFBsYXRmb3JtICsgXCIgXCIgKyBHQURldmljZS5vc1ZlcnNpb25QYWlyLnZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5vc1ZlcnNpb25QYWlyLm5hbWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEJyb3dzZXJWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB1YTpzdHJpbmcgPSBuYXZpZ2F0b3IudXNlckFnZW50O1xuICAgICAgICAgICAgICAgIHZhciB0ZW06c3RyaW5nW10gfCBudWxsO1xuICAgICAgICAgICAgICAgIHZhciBNOnN0cmluZ1tdID0gdWEubWF0Y2goLyhvcGVyYXxjaHJvbWV8c2FmYXJpfGZpcmVmb3h8dWJyb3dzZXJ8bXNpZXx0cmlkZW50fGZiYXYoPz1cXC8pKVxcLz9cXHMqKFxcZCspL2kpIHx8IFtdO1xuXG4gICAgICAgICAgICAgICAgaWYoTS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiaW9zXCIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndlYmtpdF9cIiArIEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKC90cmlkZW50L2kudGVzdChNWzFdKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IC9cXGJydlsgOl0rKFxcZCspL2cuZXhlYyh1YSkgfHwgW107XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAnSUUgJyArICh0ZW1bMV0gfHwgJycpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0gPT09ICdDaHJvbWUnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGVtID0gdWEubWF0Y2goL1xcYihPUFJ8RWRnZXxVQnJvd3NlcilcXC8oXFxkKykvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYodGVtIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRlbS5zbGljZSgxKS5qb2luKCcgJykucmVwbGFjZSgnT1BSJywgJ09wZXJhJykucmVwbGFjZSgnVUJyb3dzZXInLCAnVUMnKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoTVsxXSAmJiBNWzFdLnRvTG93ZXJDYXNlKCkgPT09ICdmYmF2JylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIE1bMV0gPSBcImZhY2Vib29rXCI7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoTVsyXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZmFjZWJvb2sgXCIgKyBNWzJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIE1TdHJpbmc6c3RyaW5nW10gPSBNWzJdPyBbTVsxXSwgTVsyXV06IFtuYXZpZ2F0b3IuYXBwTmFtZSwgbmF2aWdhdG9yLmFwcFZlcnNpb24sICctPyddO1xuXG4gICAgICAgICAgICAgICAgaWYoKHRlbSA9IHVhLm1hdGNoKC92ZXJzaW9uXFwvKFxcZCspL2kpKSAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVN0cmluZy5zcGxpY2UoMSwgMSwgdGVtWzFdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gTVN0cmluZy5qb2luKCcgJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTW9kZWwoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwidW5rbm93blwiO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcInVua25vd25cIjtcblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1hdGNoSXRlbShhZ2VudDpzdHJpbmcsIGRhdGE6QXJyYXk8TmFtZVZhbHVlVmVyc2lvbj4pOk5hbWVWZXJzaW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpOYW1lVmVyc2lvbiA9IG5ldyBOYW1lVmVyc2lvbihcInVua25vd25cIiwgXCIwLjAuMFwiKTtcblxuICAgICAgICAgICAgICAgIHZhciBpOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGo6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgcmVnZXg6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciByZWdleHY6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaDpib29sZWFuO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaGVzOlJlZ0V4cE1hdGNoQXJyYXk7XG4gICAgICAgICAgICAgICAgdmFyIG1hdGhjZXNSZXN1bHQ6c3RyaW5nO1xuICAgICAgICAgICAgICAgIHZhciB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVnZXggPSBuZXcgUmVnRXhwKGRhdGFbaV0udmFsdWUsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgIG1hdGNoID0gcmVnZXgudGVzdChhZ2VudCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVnZXh2ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZlcnNpb24gKyAnWy0gLzo7XShbXFxcXGQuX10rKScsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBtYXRjaGVzID0gYWdlbnQubWF0Y2gocmVnZXh2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gPSAnJztcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzWzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWF0aGNlc1Jlc3VsdCA9IG1hdGNoZXNbMV07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGhjZXNSZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1hdGNoZXNBcnJheTpzdHJpbmdbXSA9IG1hdGhjZXNSZXN1bHQuc3BsaXQoL1suX10rLyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gMDsgaiA8IE1hdGgubWluKG1hdGNoZXNBcnJheS5sZW5ndGgsIDMpOyBqICs9IDEpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uICs9IG1hdGNoZXNBcnJheVtqXSArIChqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMykgLSAxID8gJy4nIDogJycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJzAuMC4wJztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lm5hbWUgPSBkYXRhW2ldLm5hbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQudmVyc2lvbiA9IHZlcnNpb247XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICDCoMKgwqDCoMKgwqDCoMKgfVxuICAgICAgICAgICAgwqDCoMKgwqB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0b3JlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVBcmdzT3BlcmF0b3JcbiAgICAgICAge1xuICAgICAgICAgICAgRXF1YWwsXG4gICAgICAgICAgICBMZXNzT3JFcXVhbCxcbiAgICAgICAgICAgIE5vdEVxdWFsXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTdG9yZVxuICAgICAgICB7XG4gICAgICAgICAgICBFdmVudHMgPSAwLFxuICAgICAgICAgICAgU2Vzc2lvbnMgPSAxLFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24gPSAyXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdG9yZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0b3JlID0gbmV3IEdBU3RvcmUoKTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3JhZ2VBdmFpbGFibGU6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heE51bWJlck9mRW50cmllczpudW1iZXIgPSAyMDAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzZXNzaW9uc1N0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHByb2dyZXNzaW9uU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RvcmVJdGVtczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBTdHJpbmdGb3JtYXQgPSAoc3RyOnN0cmluZywgLi4uYXJnczpzdHJpbmdbXSkgPT4gc3RyLnJlcGxhY2UoL3soXFxkKyl9L2csIChfLCBpbmRleDpudW1iZXIpID0+IGFyZ3NbaW5kZXhdIHx8ICcnKTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEtleUZvcm1hdDpzdHJpbmcgPSBcIkdBOjp7MH06OnsxfVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRXZlbnRzU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9ldmVudFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbnNTdG9yZUtleTpzdHJpbmcgPSBcImdhX3Nlc3Npb25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFByb2dyZXNzaW9uU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9wcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgSXRlbXNTdG9yZUtleTpzdHJpbmcgPSBcImdhX2l0ZW1zXCI7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBsb2NhbFN0b3JhZ2UgPT09ICdvYmplY3QnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScsICd5ZXMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdG9yYWdlIGlzIGF2YWlsYWJsZT86IFwiICsgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JhZ2VBdmFpbGFibGUoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlLmxlbmd0aCArIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZS5sZW5ndGggPiBHQVN0b3JlLk1heE51bWJlck9mRW50cmllcztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZWxlY3Qoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10sIHNvcnQ6Ym9vbGVhbiA9IGZhbHNlLCBtYXhDb3VudDpudW1iZXIgPSAwKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBhZGQ6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBhcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighYWRkKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoYWRkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQucHVzaChlbnRyeSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihzb3J0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnNvcnQoKGE6e1trZXk6c3RyaW5nXTogYW55fSwgYjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGFbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKSAtIChiW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYobWF4Q291bnQgPiAwICYmIHJlc3VsdC5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHJlc3VsdC5zbGljZSgwLCBtYXhDb3VudCArIDEpXG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGUoc3RvcmU6RUdBU3RvcmUsIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgYW55XT4sIHdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgd2hlcmVBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gd2hlcmVBcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZih1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBzZXRBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzRW50cnk6W3N0cmluZywgYW55XSA9IHNldEFyZ3Nbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc2V0QXJnc0VudHJ5WzBdXSA9IHNldEFyZ3NFbnRyeVsxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlbGV0ZShzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGRlbDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFkZWwpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihkZWwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5zcGxpY2UoaSwgMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAtLWk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5zZXJ0KHN0b3JlOkVHQVN0b3JlLCBuZXdFbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9LCByZXBsYWNlOmJvb2xlYW4gPSBmYWxzZSwgcmVwbGFjZUtleTpzdHJpbmcgPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVwbGFjZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlS2V5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgcmVwbGFjZWQ6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVtyZXBsYWNlS2V5XSA9PSBuZXdFbnRyeVtyZXBsYWNlS2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gbmV3RW50cnkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzXSA9IG5ld0VudHJ5W3NdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXBsYWNlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighcmVwbGFjZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNhdmUoZ2FtZUtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3Qgc2F2ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5FdmVudHNTdG9yZUtleSksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5KSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuUHJvZ3Jlc3Npb25TdG9yZUtleSksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSkpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpLCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBsb2FkKGdhbWVLZXk6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlN0b3JhZ2UgaXMgbm90IGF2YWlsYWJsZSwgY2Fubm90IGxvYWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5FdmVudHNTdG9yZUtleSkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdldmVudHMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnc2Vzc2lvbnMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5KSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdwcm9ncmVzc2lvbicgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0ge307XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2l0ZW1zJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SXRlbShnYW1lS2V5OnN0cmluZywga2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBrZXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoa2V5V2l0aFByZWZpeCBpbiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEl0ZW0oZ2FtZUtleTpzdHJpbmcsIGtleTpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwga2V5KTtcbiAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gYXMgc3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldFN0b3JlKHN0b3JlOkVHQVN0b3JlKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2goc3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLkV2ZW50czpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlNlc3Npb25zOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5Qcm9ncmVzc2lvbjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJHQVN0b3JlLmdldFN0b3JlKCk6IENhbm5vdCBmaW5kIHN0b3JlOiBcIiArIHN0b3JlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0YXRlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYW1lYW5hbHl0aWNzLmRldmljZS5HQURldmljZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdGF0ZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNka0Vycm9yOnN0cmluZyA9IFwic2RrX2Vycm9yXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVDpudW1iZXIgPSA1MDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEg6bnVtYmVyID0gNjQ7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIOm51bWJlciA9IDI1NjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0YXRlID0gbmV3IEdBU3RhdGUoKTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5faXNFdmVudFN1Ym1pc3Npb25FbmFibGVkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB0aGlzLmlzVW5sb2FkaW5nID0gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgdXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0VXNlcklkKHVzZXJJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQgPSB1c2VySWQ7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBpZGVudGlmaWVyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SWRlbnRpZmllcigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGV4dFVzZXJJZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV4dFVzZXJJZCh1aWQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZXh0VXNlcklkID0gdWlkOyBcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRFeHRVc2VySWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZXh0VXNlcklkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzSW5pdGlhbGl6ZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbml0aWFsaXplZCh2YWx1ZTpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25TdGFydDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25TdGFydCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGlzVW5sb2FkaW5nOmJvb2xlYW47XG5cbiAgICAgICAgICAgIHByaXZhdGUgdHJhbnNhY3Rpb25OdW06bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRUcmFuc2FjdGlvbk51bSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS50cmFuc2FjdGlvbk51bTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25JZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25JZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAxOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMzpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZ2FtZUtleTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEdhbWVLZXkoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZUtleTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lU2VjcmV0OnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZVNlY3JldCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lU2VjcmV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEodmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMih2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDM6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzOiB7IFtrZXk6IHN0cmluZ106IGFueSB9ID0ge307XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGJ1aWxkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QnVpbGQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEJ1aWxkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBidWlsZCB2ZXJzaW9uOiBcIiArIHZhbHVlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLl9pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWdDYWNoZWQ6e1trZXk6c3RyaW5nXTogYW55fTtcbiAgICAgICAgICAgIHByaXZhdGUgY29uZmlndXJhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSB0cmFja2luZ0NvbmZpZ3VyYXRpb25zOiBhbnlbXSA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSByZW1vdGVDb25maWdzSXNSZWFkeTpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSByZW1vdGVDb25maWdzTGlzdGVuZXJzOkFycmF5PHsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIGJlZm9yZVVubG9hZExpc3RlbmVyczogQXJyYXk8eyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9PiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIGluaXRBdXRob3JpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgY2xpZW50U2VydmVyVGltZU9mZnNldDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgY29uZmlnc0hhc2g6c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgYWJJZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ0lkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmFiSWQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgYWJWYXJpYW50SWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdWYXJpYW50SWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZGVmYXVsdFVzZXJJZDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHNldERlZmF1bHRJZCh2YWx1ZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWZhdWx0VXNlcklkID0gIXZhbHVlID8gXCJcIiA6IHZhbHVlO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldERlZmF1bHRJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5kZWZhdWx0VXNlcklkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnRGVmYXVsdDp7W2tleTpzdHJpbmddOiBzdHJpbmd9ID0ge307XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZGtDb25maWcoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0OnN0cmluZztcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3QgPSBqc29uO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0OnN0cmluZztcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3QgPSBqc29uO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnRGVmYXVsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblRyaWVzOntba2V5OnN0cmluZ106IG51bWJlcn0gPSB7fTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgRGVmYXVsdFVzZXJJZEtleTpzdHJpbmcgPSBcImRlZmF1bHRfdXNlcl9pZFwiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZXNzaW9uTnVtS2V5OnN0cmluZyA9IFwic2Vzc2lvbl9udW1cIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVHJhbnNhY3Rpb25OdW1LZXk6c3RyaW5nID0gXCJ0cmFuc2FjdGlvbl9udW1cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IERpbWVuc2lvbjAxS2V5OnN0cmluZyA9IFwiZGltZW5zaW9uMDFcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IERpbWVuc2lvbjAyS2V5OnN0cmluZyA9IFwiZGltZW5zaW9uMDJcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IERpbWVuc2lvbjAzS2V5OnN0cmluZyA9IFwiZGltZW5zaW9uMDNcIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2RrQ29uZmlnQ2FjaGVkS2V5OnN0cmluZyA9IFwic2RrX2NvbmZpZ19jYWNoZWRcIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgTGFzdFVzZWRJZGVudGlmaWVyS2V5OiBzdHJpbmcgPSBcImxhc3RfdXNlZF9pZGVudGlmaWVyXCI7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNFbmFibGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMShkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAyKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDMoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDNLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRTZXNzaW9uTnVtKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtID0gc2Vzc2lvbk51bUludDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRUcmFuc2FjdGlvbk51bSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRyYW5zYWN0aW9uTnVtSW50Om51bWJlciA9IEdBU3RhdGUuZ2V0VHJhbnNhY3Rpb25OdW0oKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS50cmFuc2FjdGlvbk51bSA9IHRyYW5zYWN0aW9uTnVtSW50O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0cmllczpudW1iZXIgPSBHQVN0YXRlLmdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb24pICsgMTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dID0gdHJpZXM7XG5cbiAgICAgICAgICAgICAgICAvLyBQZXJzaXN0XG4gICAgICAgICAgICAgICAgdmFyIHZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgdmFsdWVzW1wicHJvZ3Jlc3Npb25cIl0gPSBwcm9ncmVzc2lvbjtcbiAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0cmllc1wiXSA9IHRyaWVzO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLlByb2dyZXNzaW9uLCB2YWx1ZXMsIHRydWUsIFwicHJvZ3Jlc3Npb25cIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbjpzdHJpbmcpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihwcm9ncmVzc2lvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIDA7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNsZWFyUHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZGVsZXRlIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gRGVsZXRlXG4gICAgICAgICAgICAgICAgdmFyIHBhcm1zOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgIHBhcm1zLnB1c2goW1wicHJvZ3Jlc3Npb25cIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIHByb2dyZXNzaW9uXSk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuUHJvZ3Jlc3Npb24sIHBhcm1zKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRLZXlzKGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVLZXkgPSBnYW1lS2V5O1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZVNlY3JldCA9IGdhbWVTZWNyZXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0TWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWc6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnVzZU1hbnVhbFNlc3Npb25IYW5kbGluZyA9IGZsYWc7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlVzZSBtYW51YWwgc2Vzc2lvbiBoYW5kbGluZzogXCIgKyBmbGFnKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uKGZsYWc6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLl9pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQgPSBmbGFnO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEV2ZW50QW5ub3RhdGlvbnMoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyAtLS0tIFJFUVVJUkVEIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIGNvbGxlY3RvciBldmVudCBBUEkgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1widlwiXSA9IDI7XG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgVVVJRFxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZXZlbnRfdXVpZFwiXSA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcbiAgICAgICAgICAgICAgICAvLyBVc2VyIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBleHQgdXNlciBpZFxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuZXh0VXNlcklkICYmIEdBU3RhdGUuaW5zdGFuY2UuZXh0VXNlcklkLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRfZXh0XCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5leHRVc2VySWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ2xpZW50IFRpbWVzdGFtcCAodGhlIGFkanVzdGVkIHRpbWVzdGFtcClcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNsaWVudF90c1wiXSA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBCcm93c2VyIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImJyb3dzZXJfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmJyb3dzZXJWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIFBsYXRmb3JtIChvcGVyYXRpbmcgc3lzdGVtKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuICAgICAgICAgICAgICAgIC8vIFNlc3Npb24gaWRlbnRpZmllclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2Vzc2lvbl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xuICAgICAgICAgICAgICAgIC8vIFNlc3Npb24gbnVtYmVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbR0FTdGF0ZS5TZXNzaW9uTnVtS2V5XSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyByZW1vdGUgY29uZmlnc1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UudHJhY2tpbmdDb25maWd1cmF0aW9ucyAmJiBHQVN0YXRlLmluc3RhbmNlLnRyYWNraW5nQ29uZmlndXJhdGlvbnMubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29uZmlndXJhdGlvbnNfdjNcIl0gPSBHQVN0YXRlLmluc3RhbmNlLnRyYWNraW5nQ29uZmlndXJhdGlvbnM7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQS9CIHRlc3RpbmdcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmFiSWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImFiX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5hYklkO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmFiVmFyaWFudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJhYl92YXJpYW50X2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyAtLS0tIENPTkRJVElPTkFMIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIEFwcCBidWlsZCB2ZXJzaW9uICh1c2UgaWYgbm90IG5pbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5idWlsZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnVpbGRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBhbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZGtFcnJvckV2ZW50QW5ub3RhdGlvbnMoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyAtLS0tIFJFUVVJUkVEIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIGNvbGxlY3RvciBldmVudCBBUEkgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1widlwiXSA9IDI7XG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgVVVJRFxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZXZlbnRfdXVpZFwiXSA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcblxuICAgICAgICAgICAgICAgIC8vIENhdGVnb3J5XG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjYXRlZ29yeVwiXSA9IEdBU3RhdGUuQ2F0ZWdvcnlTZGtFcnJvcjtcbiAgICAgICAgICAgICAgICAvLyBTREsgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIG1ha2UgKGhhcmRjb2RlZCB0byBhcHBsZSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm1hbnVmYWN0dXJlclwiXSA9IEdBRGV2aWNlLmRldmljZU1hbnVmYWN0dXJlcjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZGV2aWNlXCJdID0gR0FEZXZpY2UuZGV2aWNlTW9kZWw7XG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG5cbiAgICAgICAgICAgICAgICAvLyB0eXBlIG9mIGNvbm5lY3Rpb24gdGhlIHVzZXIgaXMgY3VycmVudGx5IG9uIChhZGQgaWYgdmFsaWQpXG4gICAgICAgICAgICAgICAgdmFyIGNvbm5lY3Rpb25fdHlwZTpzdHJpbmcgPSBHQURldmljZS5nZXRDb25uZWN0aW9uVHlwZSgpO1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25fdHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbm5lY3Rpb25fdHlwZVwiXSA9IGNvbm5lY3Rpb25fdHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImVuZ2luZV92ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGFubm90YXRpb25zO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEluaXRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluaXRBbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5MYXN0VXNlZElkZW50aWZpZXJLZXksIEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpKTtcblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmdldElkZW50aWZpZXIoKTtcblxuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuXG4gICAgICAgICAgICAgICAgLy8gQnVpbGRcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmdldEJ1aWxkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IEdBU3RhdGUuZ2V0QnVpbGQoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wiYnVpbGRcIl0gPSBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInNlc3Npb25fbnVtXCJdID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCk7XG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicmFuZG9tX3NhbHRcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcblxuICAgICAgICAgICAgICAgIHJldHVybiBpbml0QW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q2xpZW50VHNBZGp1c3RlZCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyOm51bWJlciA9IGNsaWVudFRzICsgR0FTdGF0ZS5pbnN0YW5jZS5jbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0O1xuXG4gICAgICAgICAgICAgICAgaWYoR0FWYWxpZGF0b3IudmFsaWRhdGVDbGllbnRUcyhjbGllbnRUc0FkanVzdGVkSW50ZWdlcikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2xpZW50VHNBZGp1c3RlZEludGVnZXI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUcztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2Vzc2lvbklzU3RhcnRlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ICE9IDA7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNhY2hlSWRlbnRpZmllcigpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgPSBHQVN0YXRlLmluc3RhbmNlLnVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgPSBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImlkZW50aWZpZXIsIHtjbGVhbjpcIiArIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciArIFwifVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbnN1cmVQZXJzaXN0ZWRTdGF0ZXMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGdldCBhbmQgZXh0cmFjdCBzdG9yZWQgc3RhdGVzXG4gICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUubG9hZChHQVN0YXRlLmdldEdhbWVLZXkoKSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGludG8gR0FTdGF0ZSBpbnN0YW5jZVxuICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZTpHQVN0YXRlID0gR0FTdGF0ZS5pbnN0YW5jZTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNldERlZmF1bHRJZChHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSA6IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKSk7XG5cbiAgICAgICAgICAgICAgICBpbnN0YW5jZS5zZXNzaW9uTnVtID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNlc3Npb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNlc3Npb25OdW1LZXkpKSA6IDAuMDtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnRyYW5zYWN0aW9uTnVtID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBkaW1lbnNpb24gc2V0dGluZ3NcbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDFLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMUtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMUtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMSBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDIgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAzIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBnZXQgY2FjaGVkIGluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkU3RyaW5nOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZFN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIGRlY29kZSBKU09OXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZGtDb25maWdDYWNoZWQgPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KHNka0NvbmZpZ0NhY2hlZFN0cmluZykpO1xuICAgICAgICAgICAgICAgICAgICBpZiAoc2RrQ29uZmlnQ2FjaGVkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdFVzZWRJZGVudGlmaWVyOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5MYXN0VXNlZElkZW50aWZpZXJLZXkpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImxhc3RVc2VkSWRlbnRpZmllcj1cIiArIGxhc3RVc2VkSWRlbnRpZmllciArIFwiLCBHQVN0YXRlLmdldElkZW50aWZpZXIoKT1cIiArIEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChsYXN0VXNlZElkZW50aWZpZXIgIT0gbnVsbCAmJiBsYXN0VXNlZElkZW50aWZpZXIgIT0gR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCkpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIk5ldyBpZGVudGlmaWVyIHNwb3R0ZWQgY29tcGFyZWQgdG8gbGFzdCBvbmUgdXNlZCwgY2xlYXJpbmcgY2FjaGVkIGNvbmZpZ3MgaGFzaCEhXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWRbXCJjb25maWdzX2hhc2hcIl0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxldGUgc2RrQ29uZmlnQ2FjaGVkW1wiY29uZmlnc19oYXNoXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCA9IHNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmNvbmZpZ3NIYXNoID0gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXSA/IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5hYklkID0gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuYWJWYXJpYW50SWQgPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfdmFyaWFudF9pZFwiXSA/IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0c19nYV9wcm9ncmVzc2lvbjpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLlByb2dyZXNzaW9uKTtcblxuICAgICAgICAgICAgICAgIGlmIChyZXN1bHRzX2dhX3Byb2dyZXNzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXN1bHRzX2dhX3Byb2dyZXNzaW9uLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVzdWx0Ontba2V5OnN0cmluZ106IGFueX0gPSByZXN1bHRzX2dhX3Byb2dyZXNzaW9uW2ldO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3VsdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Jlc3VsdFtcInByb2dyZXNzaW9uXCJdIGFzIHN0cmluZ10gPSByZXN1bHRbXCJ0cmllc1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY2FsY3VsYXRlU2VydmVyVGltZU9mZnNldChzZXJ2ZXJUczpudW1iZXIpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHNlcnZlclRzIC0gY2xpZW50VHM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZvcm1hdFN0cmluZyhzOnN0cmluZywgYXJnczpBcnJheTxzdHJpbmc+KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGZvcm1hdHRlZDogc3RyaW5nID0gcztcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoOyBpKyspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcmVnZXhwID0gbmV3IFJlZ0V4cCgnXFxcXHsnICsgaSArICdcXFxcfScsICdnaScpO1xuICAgICAgICAgICAgICAgICAgICBmb3JtYXR0ZWQgPSBmb3JtYXR0ZWQucmVwbGFjZShyZWdleHAsIGFyZ3VtZW50c1tpXSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmb3JtYXR0ZWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBlcnJvckNhbGxiYWNrOihiYXNlTWVzc2FnZTpzdHJpbmcsIG1lc3NhZ2U6c3RyaW5nKSA9PiB2b2lkPW51bGwpOiB7W2lkOnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OntbaWQ6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgaWYoZmllbGRzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yKHZhciBrZXkgaW4gZmllbGRzKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWU6YW55ID0gZmllbGRzW2tleV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFrZXkgfHwgIXZhbHVlKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiYXNlTWVzc2FnZTpzdHJpbmcgPSBcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PXswfSwgdmFsdWU9ezF9IGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMga2V5IG9yIHZhbHVlIGlzIG51bGxcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBHQVN0YXRlLmZvcm1hdFN0cmluZyhiYXNlTWVzc2FnZSwgW2tleSwgdmFsdWVdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlcnJvckNhbGxiYWNrKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZihjb3VudCA8IEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlZ2V4ID0gbmV3IFJlZ0V4cChcIl5bYS16QS1aMC05X117MSxcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfS0VZX0xFTkdUSCArIFwifSRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goa2V5LCByZWdleCkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdHlwZSA9IHR5cGVvZiB2YWx1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodHlwZSA9PT0gXCJzdHJpbmdcIiB8fCB2YWx1ZSBpbnN0YW5jZW9mIFN0cmluZylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlQXNTdHJpbmc6c3RyaW5nID0gdmFsdWUgYXMgc3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZih2YWx1ZUFzU3RyaW5nLmxlbmd0aCA8PSBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX1ZBTFVFX1NUUklOR19MRU5HVEggJiYgdmFsdWVBc1N0cmluZy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFtrZXldID0gdmFsdWVBc1N0cmluZztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiYXNlTWVzc2FnZTogc3RyaW5nID0gXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT17MH0sIHZhbHVlPXsxfSBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIHZhbHVlIGlzIGFuIGVtcHR5IHN0cmluZyBvciBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGNoYXJhY3RlcnMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIICsgXCIpXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6IHN0cmluZyA9IEdBU3RhdGUuZm9ybWF0U3RyaW5nKGJhc2VNZXNzYWdlLCBba2V5LCB2YWx1ZV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVycm9yQ2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYodHlwZSA9PT0gXCJudW1iZXJcIiB8fCB2YWx1ZSBpbnN0YW5jZW9mIE51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlQXNOdW1iZXI6bnVtYmVyID0gdmFsdWUgYXMgbnVtYmVyO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRba2V5XSA9IHZhbHVlQXNOdW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJhc2VNZXNzYWdlOiBzdHJpbmcgPSBcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PXswfSwgdmFsdWU9ezF9IGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMgdmFsdWUgaXMgbm90IGEgc3RyaW5nIG9yIG51bWJlclwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6IHN0cmluZyA9IEdBU3RhdGUuZm9ybWF0U3RyaW5nKGJhc2VNZXNzYWdlLCBba2V5LCB2YWx1ZV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlcnJvckNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJhc2VNZXNzYWdlOiBzdHJpbmcgPSBcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PXswfSwgdmFsdWU9ezF9IGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMga2V5IGNvbnRhaW5zIGlsbGVnYWwgY2hhcmFjdGVyLCBpcyBlbXB0eSBvciBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGNoYXJhY3RlcnMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIICsgXCIpXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOiBzdHJpbmcgPSBHQVN0YXRlLmZvcm1hdFN0cmluZyhiYXNlTWVzc2FnZSwgW2tleSwgdmFsdWVdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVycm9yQ2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yQ2FsbGJhY2soYmFzZU1lc3NhZ2UsIG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiYXNlTWVzc2FnZTogc3RyaW5nID0gXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT17MH0sIHZhbHVlPXsxfSBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXQgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjdXN0b20gZmllbGRzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQgKyBcIilcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTogc3RyaW5nID0gR0FTdGF0ZS5mb3JtYXRTdHJpbmcoYmFzZU1lc3NhZ2UsIFtrZXksIHZhbHVlXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXJyb3JDYWxsYmFjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDEgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMSBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAyIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDIgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMyBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMyhHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAzIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDMoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25TdHJpbmdWYWx1ZShrZXk6c3RyaW5nLCBkZWZhdWx0VmFsdWU6c3RyaW5nKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldLnRvU3RyaW5nKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBkZWZhdWx0VmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25Kc29uVmFsdWUoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOmFueSk6YW55XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGRlZmF1bHRWYWx1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNSZW1vdGVDb25maWdzUmVhZHkoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0lzUmVhZHk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyOnsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMuaW5kZXhPZihsaXN0ZW5lcikgPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzLnB1c2gobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBpbmRleCA9IEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICBpZihpbmRleCA+IC0xKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmcoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9ucyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcG9wdWxhdGVDb25maWd1cmF0aW9ucyhzZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uczphbnlbXSA9IHNka0NvbmZpZ1tcImNvbmZpZ3NcIl07XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnRyYWNraW5nQ29uZmlndXJhdGlvbnMgPSBbXVxuXG4gICAgICAgICAgICAgICAgaWYoY29uZmlndXJhdGlvbnMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zID0ge307XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjb25maWd1cmF0aW9ucy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvbmZpZ3VyYXRpb246e1trZXk6c3RyaW5nXTogYW55fSA9IGNvbmZpZ3VyYXRpb25zW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb25maWd1cmF0aW9uKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBrZXk6c3RyaW5nID0gY29uZmlndXJhdGlvbltcImtleVwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWU6YW55ID0gY29uZmlndXJhdGlvbltcInZhbHVlXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzdGFydF90czpudW1iZXIgPSBjb25maWd1cmF0aW9uW1wic3RhcnRfdHNcIl0gPyBjb25maWd1cmF0aW9uW1wic3RhcnRfdHNcIl0gOiBOdW1iZXIuTUlOX1ZBTFVFO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlbmRfdHM6bnVtYmVyID0gY29uZmlndXJhdGlvbltcImVuZF90c1wiXSA/IGNvbmZpZ3VyYXRpb25bXCJlbmRfdHNcIl0gOiBOdW1iZXIuTUFYX1ZBTFVFO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNsaWVudF90c19hZGp1c3RlZDpudW1iZXIgPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGtleSAmJiB2YWx1ZSAmJiBjbGllbnRfdHNfYWRqdXN0ZWQgPiBzdGFydF90cyAmJiBjbGllbnRfdHNfYWRqdXN0ZWQgPCBlbmRfdHMpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImNvbmZpZ3VyYXRpb24gYWRkZWQ6IFwiICsgSlNPTi5zdHJpbmdpZnkoY29uZmlndXJhdGlvbikpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0cmFja0NvbmZpZzphbnkgPSB7fTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyYWNrQ29uZmlnW1wia2V5XCJdID0gY29uZmlndXJhdGlvbltcImtleVwiXVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyYWNrQ29uZmlnW1wiaWRcIl0gPSBjb25maWd1cmF0aW9uW1wiaWRcIl1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cmFja0NvbmZpZ1tcInZzblwiXSA9IGNvbmZpZ3VyYXRpb25bXCJ2c25cIl1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UudHJhY2tpbmdDb25maWd1cmF0aW9ucy5wdXNoKHRyYWNrQ29uZmlnKVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0lzUmVhZHkgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICAgdmFyIGxpc3RlbmVyczpBcnJheTx7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9PiA9IEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycztcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBsaXN0ZW5lcnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihsaXN0ZW5lcnNbaV0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxpc3RlbmVyc1tpXS5vblJlbW90ZUNvbmZpZ3NVcGRhdGVkKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcjogeyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJlZm9yZVVubG9hZExpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKSA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJlZm9yZVVubG9hZExpc3RlbmVycy5wdXNoKGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVtb3ZlT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcjogeyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBpbmRleCA9IEdBU3RhdGUuaW5zdGFuY2UuYmVmb3JlVW5sb2FkTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIGlmIChpbmRleCA+IC0xKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5iZWZvcmVVbmxvYWRMaXN0ZW5lcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgbm90aWZ5QmVmb3JlVW5sb2FkTGlzdGVuZXJzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXJzOiBBcnJheTx7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0+ID0gR0FTdGF0ZS5pbnN0YW5jZS5iZWZvcmVVbmxvYWRMaXN0ZW5lcnM7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGxpc3RlbmVycy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChsaXN0ZW5lcnNbaV0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxpc3RlbmVyc1tpXS5vbkJlZm9yZVVubG9hZCgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRhc2tzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBTZGtFcnJvclRhc2tcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4Q291bnQ6bnVtYmVyID0gMTA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBjb3VudE1hcDp7W2tleTpzdHJpbmddOiBudW1iZXJ9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSB0aW1lc3RhbXBNYXA6e1trZXk6c3RyaW5nXTogRGF0ZX0gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBleGVjdXRlKHVybDpzdHJpbmcsIHR5cGU6c3RyaW5nLCBwYXlsb2FkRGF0YTpzdHJpbmcsIHNlY3JldEtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG5vdzpEYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgICAgICAgICAgIGlmKCFTZGtFcnJvclRhc2sudGltZXN0YW1wTWFwW3R5cGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLnRpbWVzdGFtcE1hcFt0eXBlXSA9IG5vdztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYoIVNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IDA7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBkaWZmOm51bWJlciA9IG5vdy5nZXRUaW1lKCkgLSBTZGtFcnJvclRhc2sudGltZXN0YW1wTWFwW3R5cGVdLmdldFRpbWUoKTtcbiAgICAgICAgICAgICAgICB2YXIgZGlmZlNlY29uZHM6bnVtYmVyID0gZGlmZiAvIDEwMDA7XG4gICAgICAgICAgICAgICAgaWYoZGlmZlNlY29uZHMgPj0gMzYwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay50aW1lc3RhbXBNYXBbdHlwZV0gPSBub3c7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID49IFNka0Vycm9yVGFzay5NYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgaGFzaEhtYWM6c3RyaW5nID0gR0FVdGlsaXRpZXMuZ2V0SG1hYyhzZWNyZXRLZXksIHBheWxvYWREYXRhKTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZighcmVxdWVzdC5yZXNwb25zZVRleHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNkayBlcnJvciBmYWlsZWQuIE1pZ2h0IGJlIG5vIGNvbm5lY3Rpb24uIERlc2NyaXB0aW9uOiBcIiArIHJlcXVlc3Quc3RhdHVzVGV4dCArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByZXF1ZXN0LnN0YXR1cyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihyZXF1ZXN0LnN0YXR1cyAhPSAyMDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNkayBlcnJvciBmYWlsZWQuIHJlc3BvbnNlIGNvZGUgbm90IDIwMC4gc3RhdHVzIGNvZGU6IFwiICsgcmVxdWVzdC5zdGF0dXMgKyBcIiwgZGVzY3JpcHRpb246IFwiICsgcmVxdWVzdC5zdGF0dXNUZXh0ICsgXCIsIGJvZHk6IFwiICsgcmVxdWVzdC5yZXNwb25zZVRleHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gKyAxO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIHJlcXVlc3Qub3BlbihcIlBPU1RcIiwgdXJsLCB0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uXCIpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkF1dGhvcml6YXRpb25cIiwgaGFzaEhtYWMpO1xuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnNlbmQocGF5bG9hZERhdGEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IFNka0Vycm9yVGFzayA9IGdhbWVhbmFseXRpY3MudGFza3MuU2RrRXJyb3JUYXNrO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JDYXRlZ29yeSA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQ2F0ZWdvcnk7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFyZWEgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFyZWE7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFjdGlvbiA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQWN0aW9uO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JQYXJhbWV0ZXIgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvclBhcmFtZXRlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIVFRQQXBpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm90b2NvbDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGhvc3ROYW1lOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NCYXNlVXJsOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZVVybFBhdGg6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdXNlR3ppcDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0VSUk9SX01FU1NBR0VfTEVOR1RIOm51bWJlciA9IDI1NjtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYmFzZSB1cmwgc2V0dGluZ3NcbiAgICAgICAgICAgICAgICB0aGlzLnByb3RvY29sID0gXCJodHRwc1wiO1xuICAgICAgICAgICAgICAgIHRoaXMuaG9zdE5hbWUgPSBcImFwaS5nYW1lYW5hbHl0aWNzLmNvbVwiO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IFwidjJcIjtcbiAgICAgICAgICAgICAgICB0aGlzLnJlbW90ZUNvbmZpZ3NWZXJzaW9uID0gXCJ2MVwiO1xuXG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlIGJhc2UgdXJsXG4gICAgICAgICAgICAgICAgdGhpcy5iYXNlVXJsID0gdGhpcy5wcm90b2NvbCArIFwiOi8vXCIgKyB0aGlzLmhvc3ROYW1lICsgXCIvXCIgKyB0aGlzLnZlcnNpb247XG4gICAgICAgICAgICAgICAgdGhpcy5yZW1vdGVDb25maWdzQmFzZVVybCA9IHRoaXMucHJvdG9jb2wgKyBcIjovL1wiICsgdGhpcy5ob3N0TmFtZSArIFwiL3JlbW90ZV9jb25maWdzL1wiICsgdGhpcy5yZW1vdGVDb25maWdzVmVyc2lvbjtcblxuICAgICAgICAgICAgICAgIHRoaXMuaW5pdGlhbGl6ZVVybFBhdGggPSBcImluaXRcIjtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1VybFBhdGggPSBcImV2ZW50c1wiO1xuXG4gICAgICAgICAgICAgICAgdGhpcy51c2VHemlwID0gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyByZXF1ZXN0SW5pdChjb25maWdzSGFzaDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSkgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5yZW1vdGVDb25maWdzQmFzZVVybCArIFwiL1wiICsgdGhpcy5pbml0aWFsaXplVXJsUGF0aCArIFwiP2dhbWVfa2V5PVwiICsgZ2FtZUtleSArIFwiJmludGVydmFsX3NlY29uZHM9MCZjb25maWdzX2hhc2g9XCIgKyBjb25maWdzSGFzaCArIFwiJmNvbmZpZ192c25fc3VwcG9ydGVkPTNcIjtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnaW5pdCcgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldEluaXRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBKU09OIHN0cmluZyBmcm9tIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShpbml0QW5ub3RhdGlvbnMpO1xuXG4gICAgICAgICAgICAgICAgaWYoIUpTT05zdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCwgbnVsbCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGE6c3RyaW5nID0gdGhpcy5jcmVhdGVQYXlsb2FkRGF0YShKU09Oc3RyaW5nLCB0aGlzLnVzZUd6aXApO1xuICAgICAgICAgICAgICAgIHZhciBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5zZW5kUmVxdWVzdCh1cmwsIHBheWxvYWREYXRhLCBleHRyYUFyZ3MsIHRoaXMudXNlR3ppcCwgR0FIVFRQQXBpLmluaXRSZXF1ZXN0Q2FsbGJhY2ssIGNhbGxiYWNrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlbmRFdmVudHNJbkFycmF5KGV2ZW50QXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4sIHJlcXVlc3RJZDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoZXZlbnRBcnJheS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBjYWxsZWQgd2l0aCBtaXNzaW5nIGV2ZW50QXJyYXlcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmV2ZW50c1VybFBhdGg7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICAvLyBtYWtlIEpTT04gc3RyaW5nIGZyb20gZGF0YVxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2ZW50QXJyYXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIUpTT05zdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZEV2ZW50c0luQXJyYXkgSlNPTiBlbmNvZGluZyBmYWlsZWQgb2YgZXZlbnRBcnJheVwiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQsIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRBcnJheS5sZW5ndGgpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhID0gdGhpcy5jcmVhdGVQYXlsb2FkRGF0YShKU09Oc3RyaW5nLCB0aGlzLnVzZUd6aXApO1xuICAgICAgICAgICAgICAgIHZhciBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKHJlcXVlc3RJZCk7XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goZXZlbnRBcnJheS5sZW5ndGgudG9TdHJpbmcoKSk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnNlbmRSZXF1ZXN0KHVybCwgcGF5bG9hZERhdGEsIGV4dHJhQXJncywgdGhpcy51c2VHemlwLCBHQUhUVFBBcGkuc2VuZEV2ZW50SW5BcnJheVJlcXVlc3RDYWxsYmFjaywgY2FsbGJhY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZFNka0Vycm9yRXZlbnQoY2F0ZWdvcnk6RUdBU2RrRXJyb3JDYXRlZ29yeSwgYXJlYTpFR0FTZGtFcnJvckFyZWEsIGFjdGlvbjpFR0FTZGtFcnJvckFjdGlvbiwgcGFyYW1ldGVyOkVHQVNka0Vycm9yUGFyYW1ldGVyLCByZWFzb246c3RyaW5nLCBnYW1lS2V5OnN0cmluZywgc2VjcmV0S2V5OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTZGtFcnJvckV2ZW50KGdhbWVLZXksIHNlY3JldEtleSwgY2F0ZWdvcnksIGFyZWEsIGFjdGlvbikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnZXZlbnRzJyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkSlNPTlN0cmluZzpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciBlcnJvclR5cGU6c3RyaW5nID0gXCJcIlxuXG4gICAgICAgICAgICAgICAgdmFyIGpzb246e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgY2F0ZWdvcnlTdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yQ2F0ZWdvcnlTdHJpbmcoY2F0ZWdvcnkpO1xuICAgICAgICAgICAgICAgIGpzb25bXCJlcnJvcl9jYXRlZ29yeVwiXSA9IGNhdGVnb3J5U3RyaW5nO1xuICAgICAgICAgICAgICAgIGVycm9yVHlwZSArPSBjYXRlZ29yeVN0cmluZztcblxuICAgICAgICAgICAgICAgIHZhciBhcmVhU3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvckFyZWFTdHJpbmcoYXJlYSk7XG4gICAgICAgICAgICAgICAganNvbltcImVycm9yX2FyZWFcIl0gPSBhcmVhU3RyaW5nO1xuICAgICAgICAgICAgICAgIGVycm9yVHlwZSArPSBcIjpcIiArIGFyZWFTdHJpbmc7XG5cbiAgICAgICAgICAgICAgICB2YXIgYWN0aW9uU3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvckFjdGlvblN0cmluZyhhY3Rpb24pO1xuICAgICAgICAgICAgICAgIGpzb25bXCJlcnJvcl9hY3Rpb25cIl0gPSBhY3Rpb25TdHJpbmc7XG5cbiAgICAgICAgICAgICAgICB2YXIgcGFyYW1ldGVyU3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvclBhcmFtZXRlclN0cmluZyhwYXJhbWV0ZXIpO1xuICAgICAgICAgICAgICAgIGlmKHBhcmFtZXRlclN0cmluZy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAganNvbltcImVycm9yX3BhcmFtZXRlclwiXSA9IHBhcmFtZXRlclN0cmluZztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZWFzb24ubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciByZWFzb25UcmltbWVkID0gcmVhc29uO1xuICAgICAgICAgICAgICAgICAgICBpZihyZWFzb24ubGVuZ3RoID4gR0FIVFRQQXBpLk1BWF9FUlJPUl9NRVNTQUdFX0xFTkdUSClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlYXNvblRyaW1tZWQgPSByZWFzb24uc3Vic3RyaW5nKDAsIEdBSFRUUEFwaS5NQVhfRVJST1JfTUVTU0FHRV9MRU5HVEgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGpzb25bXCJyZWFzb25cIl0gPSByZWFzb25UcmltbWVkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICAgICAgZXZlbnRBcnJheS5wdXNoKGpzb24pO1xuICAgICAgICAgICAgICAgIHBheWxvYWRKU09OU3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighcGF5bG9hZEpTT05TdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwic2VuZFNka0Vycm9yRXZlbnQ6IEpTT04gZW5jb2RpbmcgZmFpbGVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kU2RrRXJyb3JFdmVudCBqc29uOiBcIiArIHBheWxvYWRKU09OU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suZXhlY3V0ZSh1cmwsIGVycm9yVHlwZSwgcGF5bG9hZEpTT05TdHJpbmcsIHNlY3JldEtleSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2socmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZDpzdHJpbmcgPSBleHRyYVsyXTtcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRDb3VudDpudW1iZXIgPSBwYXJzZUludChleHRyYVszXSk7XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZXZlbnRzIHJlcXVlc3QgY29udGVudDogXCIgKyBib2R5KTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0UmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSA9IEdBSFRUUEFwaS5pbnN0YW5jZS5wcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZSwgcmVxdWVzdC5zdGF0dXNUZXh0LCBib2R5LCBcIkV2ZW50c1wiKTtcblxuICAgICAgICAgICAgICAgIC8vIGlmIG5vdCAyMDAgcmVzdWx0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBldmVudHMgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGRlY29kZSBKU09OXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcblxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RKc29uRGljdCA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvckNhdGVnb3J5Lkh0dHAsIEVHQVNka0Vycm9yQXJlYS5FdmVudHNIdHRwLCBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGUsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgYm9keSwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByaW50IHJlYXNvbiBpZiBiYWQgcmVxdWVzdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gPT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEV2ZW50cyBDYWxsLiBCYWQgcmVxdWVzdC4gUmVzcG9uc2U6IFwiICsgSlNPTi5zdHJpbmdpZnkocmVxdWVzdEpzb25EaWN0KSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmV0dXJuIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgcmVxdWVzdEpzb25EaWN0LCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZW5kUmVxdWVzdCh1cmw6c3RyaW5nLCBwYXlsb2FkRGF0YTpzdHJpbmcsIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+LCBnemlwOmJvb2xlYW4sIGNhbGxiYWNrOihyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+KSA9PiB2b2lkLCBjYWxsYmFjazI6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdDpYTUxIdHRwUmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuXG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlIGF1dGhvcml6YXRpb24gaGFzaFxuICAgICAgICAgICAgICAgIHZhciBrZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCk7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gR0FVdGlsaXRpZXMuZ2V0SG1hYyhrZXksIHBheWxvYWREYXRhKTtcblxuICAgICAgICAgICAgICAgIHZhciBhcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBhcmdzLnB1c2goYXV0aG9yaXphdGlvbik7XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gZXh0cmFBcmdzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYXJncy5wdXNoKGV4dHJhQXJnc1tzXSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmKHJlcXVlc3QucmVhZHlTdGF0ZSA9PT0gNClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdCwgdXJsLCBjYWxsYmFjazIsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIHJlcXVlc3Qub3BlbihcIlBPU1RcIiwgdXJsLCB0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uXCIpO1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQXV0aG9yaXphdGlvblwiLCBhdXRob3JpemF0aW9uKTtcblxuICAgICAgICAgICAgICAgIGlmKGd6aXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJnemlwIG5vdCBzdXBwb3J0ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIC8vcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1FbmNvZGluZ1wiLCBcImd6aXBcIik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnNlbmQocGF5bG9hZERhdGEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGluaXRSZXF1ZXN0Q2FsbGJhY2socmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICAvLyBwcm9jZXNzIHRoZSByZXNwb25zZVxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJpbml0IHJlcXVlc3QgY29udGVudCA6IFwiICsgYm9keSArIFwiLCBKU09Oc3RyaW5nOiBcIiArIEpTT05zdHJpbmcpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJJbml0XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgSW5pdCBDYWxsLiBKc29uIGRlY29kaW5nIGZhaWxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5IdHRwLCBFR0FTZGtFcnJvckFyZWEuSW5pdEh0dHAsIEVHQVNka0Vycm9yQWN0aW9uLkZhaWxIdHRwSnNvbkRlY29kZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBib2R5LCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gQmFkIHJlcXVlc3QuIFJlc3BvbnNlOiBcIiArIEpTT04uc3RyaW5naWZ5KHJlcXVlc3RKc29uRGljdCkpO1xuICAgICAgICAgICAgICAgICAgICAvLyByZXR1cm4gYmFkIHJlcXVlc3QgcmVzdWx0XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgSW5pdCBjYWxsIHZhbHVlc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0ZWRJbml0VmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSBHQVZhbGlkYXRvci52YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShyZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RSZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkKTtcblxuICAgICAgICAgICAgICAgIGlmKCF2YWxpZGF0ZWRJbml0VmFsdWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGFsbCBva1xuICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIHZhbGlkYXRlZEluaXRWYWx1ZXMsIFwiXCIsIDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGNyZWF0ZVBheWxvYWREYXRhKHBheWxvYWQ6c3RyaW5nLCBnemlwOmJvb2xlYW4pOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGE6c3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgaWYoZ3ppcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIHBheWxvYWREYXRhID0gR0FVdGlsaXRpZXMuR3ppcENvbXByZXNzKHBheWxvYWQpO1xuICAgICAgICAgICAgICAgICAgICAvLyBHQUxvZ2dlci5EKFwiR3ppcCBzdGF0cy4gU2l6ZTogXCIgKyBFbmNvZGluZy5VVEY4LkdldEJ5dGVzKHBheWxvYWQpLkxlbmd0aCArIFwiLCBDb21wcmVzc2VkOiBcIiArIHBheWxvYWREYXRhLkxlbmd0aCArIFwiLCBDb250ZW50OiBcIiArIHBheWxvYWQpO1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJnemlwIG5vdCBzdXBwb3J0ZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHBheWxvYWREYXRhID0gcGF5bG9hZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZERhdGE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgcHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGU6bnVtYmVyLCByZXNwb25zZU1lc3NhZ2U6c3RyaW5nLCBib2R5OnN0cmluZywgcmVxdWVzdElkOnN0cmluZyk6IEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGlmIG5vIHJlc3VsdCAtIG9mdGVuIG5vIGNvbm5lY3Rpb25cbiAgICAgICAgICAgICAgICBpZighYm9keSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyByZXNwb25zZU1lc3NhZ2UgKyBcIiwgU3RhdHVzIGNvZGU6IFwiICsgcmVzcG9uc2VDb2RlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIG9rXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMjAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5PaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlZFxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDIwMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyA0MDEgY2FuIHJldHVybiAwIHN0YXR1c1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDAgfHwgcmVzcG9uc2VDb2RlID09PSA0MDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMSAtIFVuYXV0aG9yaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDQwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAwIC0gQmFkIFJlcXVlc3QuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3Q7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNTAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA1MDAgLSBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3IuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkludGVybmFsU2VydmVyRXJyb3I7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Vbmtub3duUmVzcG9uc2VDb2RlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckNhdGVnb3J5U3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQ2F0ZWdvcnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50X3ZhbGlkYXRpb25cIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkRhdGFiYXNlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkluaXQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JDYXRlZ29yeS5IdHRwOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQ2F0ZWdvcnkuSnNvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25cIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JBcmVhU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQXJlYSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5CdXNpbmVzc0V2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlc291cmNlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5EZXNpZ25FdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImRlc2lnblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuSW5pdEh0dHA6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0X2h0dHBcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuRXZlbnRzSHR0cDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50c19odHRwXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2Nlc3NFdmVudHM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9jZXNzX2V2ZW50c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5BZGRFdmVudHNUb1N0b3JlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYWRkX2V2ZW50c190b19zdG9yZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckFjdGlvblN0cmluZyh2YWx1ZTpFR0FTZGtFcnJvckFjdGlvbik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRDdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfY3VycmVuY3lcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU2hvcnRTdHJpbmc6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Nob3J0X3N0cmluZ1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGg6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfbGVuZ3RoXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfY2hhcmFjdGVyc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc3RvcmVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Zsb3dfdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic3RyaW5nX2VtcHR5X29yX251bGxcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Ob3RGb3VuZEluQXZhaWxhYmxlQ3VycmVuY2llczpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm5vdF9mb3VuZF9pbl9hdmFpbGFibGVfY3VycmVuY2llc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Ftb3VudFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLk5vdEZvdW5kSW5BdmFpbGFibGVJdGVtVHlwZXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJub3RfZm91bmRfaW5fYXZhaWxhYmxlX2l0ZW1fdHlwZXNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3cm9uZ19wcm9ncmVzc2lvbl9vcmRlclwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkTGVuZ3RoOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW52YWxpZF9ldmVudF9pZF9sZW5ndGhcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRJZENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X2lkX2NoYXJhY3RlcnNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkUHJvZ3Jlc3Npb25TdGF0dXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Byb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTZXZlcml0eTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkTG9uZ1N0cmluZzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfbG9uZ19zdHJpbmdcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5EYXRhYmFzZVRvb0xhcmdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJfdG9vX2xhcmdlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uRGF0YWJhc2VPcGVuT3JDcmVhdGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkYl9vcGVuX29yX2NyZWF0ZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkpzb25FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25fZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9kZWNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25FbmNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9lbmNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JQYXJhbWV0ZXJTdHJpbmcodmFsdWU6RUdBU2RrRXJyb3JQYXJhbWV0ZXIpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImN1cnJlbmN5XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ2FydFR5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjYXJ0X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1fdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1faWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5TdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInN0b3JlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmbG93X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5BbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJhbW91bnRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicHJvZ3Jlc3Npb24wMVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvbjAyXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uMDNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5FdmVudElkOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXZlbnRfaWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvblN0YXR1czpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlNldmVyaXR5OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5NZXNzYWdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwibWVzc2FnZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGhlYWx0aFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBIZWFsdGhTbmFwc2hvdFxuICAgICAgICB7XG4gICAgICAgICAgICBtZW1vcnlfdXNlZF9tYjogbnVtYmVyO1xuICAgICAgICAgICAgaGFyZHdhcmVfY29uY3VycmVuY3k6IG51bWJlcjtcbiAgICAgICAgICAgIHNjcmVlbl93aWR0aDogbnVtYmVyO1xuICAgICAgICAgICAgc2NyZWVuX2hlaWdodDogbnVtYmVyO1xuICAgICAgICAgICAgY3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBoYXJkd2FyZTogc3RyaW5nO1xuICAgICAgICAgICAgZ3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogc3RyaW5nO1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBSGVhbHRoXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEZQU19NQVg6IG51bWJlciA9IDEyMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1FTV9JTlRFUlZBTDogbnVtYmVyID0gNTAwMDtcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX2VuYWJsZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJhZklkOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbGFzdEZyYW1lVGltZTogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc0J1Y2tldHM6IG51bWJlcltdID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBmcmFtZUFjY3VtOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZnJhbWVDb3VudDogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc1RpbWVyOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtVGltZXI6IG51bWJlciA9IDA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBtZW1TeXNCdWNrZXRzOiBudW1iZXJbXSA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtQXBwQnVja2V0czogbnVtYmVyW10gPSBbXTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX2dwdU1vZGVsOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIF9oYXJkd2FyZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfc2NyZWVuUmVzb2x1dGlvbjogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKSB7fVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZXNldCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVBY2N1bSA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgPSAwO1xuICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyID0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2FtcGxlTWVtb3J5KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIHBlcmZvcm1hbmNlID09PSAndW5kZWZpbmVkJyB8fCAhKHBlcmZvcm1hbmNlIGFzIGFueSkubWVtb3J5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgbWVtOiBhbnkgPSAocGVyZm9ybWFuY2UgYXMgYW55KS5tZW1vcnk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZGV2aWNlQnl0ZXM6IG51bWJlciA9IEdBSGVhbHRoLmdldERldmljZU1lbW9yeUJ5dGVzKCk7XG4gICAgICAgICAgICAgICAgaWYgKGRldmljZUJ5dGVzID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzeXNQY3Q6IG51bWJlciA9IE1hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChtZW0udG90YWxKU0hlYXBTaXplIC8gZGV2aWNlQnl0ZXMgKiAxMDApKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVN5c0J1Y2tldHNbc3lzUGN0XSsrO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZW0uanNIZWFwU2l6ZUxpbWl0ID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBhcHBQY3Q6IG51bWJlciA9IE1hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChtZW0udXNlZEpTSGVhcFNpemUgLyBtZW0uanNIZWFwU2l6ZUxpbWl0ICogMTAwKSkpO1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzW2FwcFBjdF0rKztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEdwdU1vZGVsKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQUhlYWx0aC5fZ3B1TW9kZWwgIT09IG51bGwpIHsgcmV0dXJuIEdBSGVhbHRoLl9ncHVNb2RlbDsgfVxuICAgICAgICAgICAgICAgIEdBSGVhbHRoLl9ncHVNb2RlbCA9ICcnO1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCAhPT0gJ3VuZGVmaW5lZCcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjYW52YXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdjYW52YXMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBnbDogYW55ID0gY2FudmFzLmdldENvbnRleHQoJ3dlYmdsJykgfHwgY2FudmFzLmdldENvbnRleHQoJ2V4cGVyaW1lbnRhbC13ZWJnbCcpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGdsKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBleHQgPSBnbC5nZXRFeHRlbnNpb24oJ1dFQkdMX2RlYnVnX3JlbmRlcmVyX2luZm8nKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXh0KSB7IEdBSGVhbHRoLl9ncHVNb2RlbCA9IGdsLmdldFBhcmFtZXRlcihleHQuVU5NQVNLRURfUkVOREVSRVJfV0VCR0wpIHx8ICcnOyB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHt9XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBSGVhbHRoLl9ncHVNb2RlbCE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEhhcmR3YXJlKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQUhlYWx0aC5faGFyZHdhcmUgIT09IG51bGwpIHsgcmV0dXJuIEdBSGVhbHRoLl9oYXJkd2FyZTsgfVxuICAgICAgICAgICAgICAgIEdBSGVhbHRoLl9oYXJkd2FyZSA9ICd1bmtub3duJztcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FIZWFsdGguX2hhcmR3YXJlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXREZXZpY2VNZW1vcnlCeXRlcygpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKHR5cGVvZiBuYXZpZ2F0b3IgIT09ICd1bmRlZmluZWQnICYmIChuYXZpZ2F0b3IgYXMgYW55KS5kZXZpY2VNZW1vcnkpXG4gICAgICAgICAgICAgICAgICAgID8gKG5hdmlnYXRvciBhcyBhbnkpLmRldmljZU1lbW9yeSAqIDEwNzM3NDE4MjRcbiAgICAgICAgICAgICAgICAgICAgOiAwO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRTY3JlZW5SZXNvbHV0aW9uKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbiAhPT0gbnVsbCkgeyByZXR1cm4gR0FIZWFsdGguX3NjcmVlblJlc29sdXRpb247IH1cbiAgICAgICAgICAgICAgICB2YXIgdzogbnVtYmVyID0gKHR5cGVvZiBzY3JlZW4gIT09ICd1bmRlZmluZWQnKSA/IHNjcmVlbi53aWR0aCA6IDA7XG4gICAgICAgICAgICAgICAgdmFyIGg6IG51bWJlciA9ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4uaGVpZ2h0IDogMDtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbiA9IHcgKyAneCcgKyBoO1xuICAgICAgICAgICAgICAgIHJldHVybiBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmUoZW5hYmxlZDogYm9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fZW5hYmxlZCA9IGVuYWJsZWQ7XG4gICAgICAgICAgICAgICAgaWYgKGVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5zdGFydFRyYWNraW5nKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnN0b3BUcmFja2luZygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnRUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiByZXF1ZXN0QW5pbWF0aW9uRnJhbWUgPT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJlc2V0KCk7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzQnVja2V0cyA9IG5ldyBBcnJheShHQUhlYWx0aC5GUFNfTUFYICsgMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1TeXNCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcpID8gcGVyZm9ybWFuY2Uubm93KCkgOiBEYXRlLm5vdygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpY2sgPSBmdW5jdGlvbihub3c6IG51bWJlcik6IHZvaWRcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FIZWFsdGguX2VuYWJsZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB2YXIgZGVsdGE6IG51bWJlciA9IG5vdyAtIEdBSGVhbHRoLmxhc3RGcmFtZVRpbWU7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkZWx0YSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLmZyYW1lQWNjdW0gKz0gMTAwMCAvIGRlbHRhO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCsrO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgKz0gZGVsdGE7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1UaW1lciArPSBkZWx0YTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKEdBSGVhbHRoLmZwc1RpbWVyID49IDEwMDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGF2Z0ZwczogbnVtYmVyID0gTWF0aC5taW4oR0FIZWFsdGguRlBTX01BWCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChHQUhlYWx0aC5mcmFtZUFjY3VtIC8gR0FIZWFsdGguZnJhbWVDb3VudCkpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNCdWNrZXRzW2F2Z0Zwc10rKztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUFjY3VtID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUNvdW50ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNUaW1lciAtPSAxMDAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGgubWVtVGltZXIgPj0gR0FIZWFsdGguTUVNX0lOVEVSVkFMKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnNhbXBsZU1lbW9yeSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyIC09IEdBSGVhbHRoLk1FTV9JTlRFUlZBTDtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gbm93O1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5yYWZJZCA9IHJlcXVlc3RBbmltYXRpb25GcmFtZSh0aWNrKTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgR0FIZWFsdGgucmFmSWQgPSByZXF1ZXN0QW5pbWF0aW9uRnJhbWUodGljayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3BUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBjYW5jZWxBbmltYXRpb25GcmFtZSAhPT0gJ3VuZGVmaW5lZCcgJiYgR0FIZWFsdGgucmFmSWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYW5jZWxBbmltYXRpb25GcmFtZShHQUhlYWx0aC5yYWZJZCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJhZklkID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U25hcHNob3QoKTogSGVhbHRoU25hcHNob3RcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVtTWI6IG51bWJlciA9IC0xO1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgcGVyZm9ybWFuY2UgIT09ICd1bmRlZmluZWQnICYmIChwZXJmb3JtYW5jZSBhcyBhbnkpLm1lbW9yeSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIG1lbU1iID0gTWF0aC5yb3VuZCgocGVyZm9ybWFuY2UgYXMgYW55KS5tZW1vcnkudXNlZEpTSGVhcFNpemUgLyAxMDQ4NTc2KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgICAgICBtZW1vcnlfdXNlZF9tYjogbWVtTWIsXG4gICAgICAgICAgICAgICAgICAgIGhhcmR3YXJlX2NvbmN1cnJlbmN5OiAodHlwZW9mIG5hdmlnYXRvciAhPT0gJ3VuZGVmaW5lZCcgJiYgbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kpID8gbmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3kgOiAxLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fd2lkdGg6ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4ud2lkdGggOiAwLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5faGVpZ2h0OiAodHlwZW9mIHNjcmVlbiAhPT0gJ3VuZGVmaW5lZCcpID8gc2NyZWVuLmhlaWdodCA6IDAsXG4gICAgICAgICAgICAgICAgICAgIGNwdV9tb2RlbDogJ3Vua25vd24nLFxuICAgICAgICAgICAgICAgICAgICBoYXJkd2FyZTogR0FIZWFsdGguZ2V0SGFyZHdhcmUoKSxcbiAgICAgICAgICAgICAgICAgICAgZ3B1X21vZGVsOiBHQUhlYWx0aC5nZXRHcHVNb2RlbCgpLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogR0FIZWFsdGguZ2V0U2NyZWVuUmVzb2x1dGlvbigpXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRIZWFsdGhBbm5vdGF0aW9ucyhvdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG91dFsnY3B1X21vZGVsJ10gPSAndW5rbm93bic7XG5cbiAgICAgICAgICAgICAgICBvdXRbJ2hhcmR3YXJlJ10gPSBHQUhlYWx0aC5nZXRIYXJkd2FyZSgpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGdwdU1vZGVsOiBzdHJpbmcgPSBHQUhlYWx0aC5nZXRHcHVNb2RlbCgpO1xuICAgICAgICAgICAgICAgIGlmIChncHVNb2RlbCkgeyBvdXRbJ2dwdV9tb2RlbCddID0gZ3B1TW9kZWw7IH1cblxuICAgICAgICAgICAgICAgIHZhciBudW1Db3JlczogbnVtYmVyID0gKHR5cGVvZiBuYXZpZ2F0b3IgIT09ICd1bmRlZmluZWQnICYmIG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5KSA/IG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5IDogMDtcbiAgICAgICAgICAgICAgICBpZiAobnVtQ29yZXMgPiAwKSB7IG91dFsnY3B1X251bV9jb3JlcyddID0gbnVtQ29yZXM7IH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQZXJmb3JtYW5jZURhdGEob3V0OiB7W2tleTogc3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBvdXRbJ2Zwc19kYXRhX3RhYmxlJ10gPSBHQUhlYWx0aC5mcHNCdWNrZXRzLnNsaWNlKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGguZ2V0RGV2aWNlTWVtb3J5Qnl0ZXMoKSA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBvdXRbJ21lbW9yeV9zeXNfZGF0YV90YWJsZSddID0gR0FIZWFsdGgubWVtU3lzQnVja2V0cy5zbGljZSgpO1xuICAgICAgICAgICAgICAgICAgICBvdXRbJ21lbW9yeV9hcHBfZGF0YV90YWJsZSddID0gR0FIZWFsdGgubWVtQXBwQnVja2V0cy5zbGljZSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRTREtJbml0RGF0YShvdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBib290VGltZTogbnVtYmVyID0gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcpID8gTWF0aC5yb3VuZChwZXJmb3JtYW5jZS5ub3coKSkgOiAtMTtcbiAgICAgICAgICAgICAgICBpZiAoYm9vdFRpbWUgPiAwKSB7IG91dFsnYXBwX2Jvb3RfdGltZSddID0gYm9vdFRpbWU7IH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0VuYWJsZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQUhlYWx0aC5fZW5hYmxlZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FIVFRQQXBpUmVzcG9uc2U7XG4gICAgICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBWYWxpZGF0aW9uUmVzdWx0ID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLlZhbGlkYXRpb25SZXN1bHQ7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBRXZlbnRzXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2Vzc2lvblN0YXJ0OnN0cmluZyA9IFwidXNlclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uRW5kOnN0cmluZyA9IFwic2Vzc2lvbl9lbmRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RGVzaWduOnN0cmluZyA9IFwiZGVzaWduXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUJ1c2luZXNzOnN0cmluZyA9IFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5UHJvZ3Jlc3Npb246c3RyaW5nID0gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlSZXNvdXJjZTpzdHJpbmcgPSBcInJlc291cmNlXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUVycm9yOnN0cmluZyA9IFwiZXJyb3JcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QWRzOnN0cmluZyA9IFwiYWRzXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNES0luaXQ6c3RyaW5nID0gXCJzZGtfaW5pdFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlIZWFsdGg6c3RyaW5nID0gXCJoZWFsdGhcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heEV2ZW50Q291bnQ6bnVtYmVyID0gNTAwO1xuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfRVJST1JfQ09VTlQ6bnVtYmVyID0gMTA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBjb3VudE1hcDogeyBba2V5OiBzdHJpbmddOiBudW1iZXIgfSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgdGltZXN0YW1wTWFwOiB7IFtrZXk6IHN0cmluZ106IERhdGUgfSA9IHt9O1xuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyB3YXNTREtJbml0RXZlbnRTZW50OiBib29sZWFuID0gZmFsc2U7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZTpzdHJpbmcsIG1lc3NhZ2U6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG5vdzogRGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBRXZlbnRzLnRpbWVzdGFtcE1hcFtiYXNlTWVzc2FnZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudGltZXN0YW1wTWFwW2Jhc2VNZXNzYWdlXSA9IG5vdztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIGRpZmY6IG51bWJlciA9IG5vdy5nZXRUaW1lKCkgLSBHQUV2ZW50cy50aW1lc3RhbXBNYXBbYmFzZU1lc3NhZ2VdLmdldFRpbWUoKTtcbiAgICAgICAgICAgICAgICB2YXIgZGlmZlNlY29uZHM6IG51bWJlciA9IGRpZmYgLyAxMDAwO1xuICAgICAgICAgICAgICAgIGlmIChkaWZmU2Vjb25kcyA+PSAzNjAwKSB7XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLnRpbWVzdGFtcE1hcFtiYXNlTWVzc2FnZV0gPSBub3c7XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmNvdW50TWFwW2Jhc2VNZXNzYWdlXSA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRXZlbnRzLmNvdW50TWFwW2Jhc2VNZXNzYWdlXSA+PSBHQUV2ZW50cy5NQVhfRVJST1JfQ09VTlQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MudGhyZWFkaW5nLkdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEVycm9yRXZlbnQoRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nLCBtZXNzYWdlLCBudWxsLCB0cnVlKTtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID0gR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdICsgMTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRTZXNzaW9uU3RhcnRFdmVudCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgc3BlY2lmaWMgZGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ7XG5cbiAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgc2Vzc2lvbiBudW1iZXIgIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRTZXNzaW9uTnVtKCk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNlc3Npb25OdW1LZXksIEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM7XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBTRVNTSU9OIFNUQVJUIGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBldmVudCByaWdodCBhd2F5XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydCwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25FbmRFdmVudCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25fc3RhcnRfdHM6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50X3RzX2FkanVzdGVkOm51bWJlciA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uTGVuZ3RoOm51bWJlciA9IGNsaWVudF90c19hZGp1c3RlZCAtIHNlc3Npb25fc3RhcnRfdHM7XG5cbiAgICAgICAgICAgICAgICBpZihzZXNzaW9uTGVuZ3RoIDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFNob3VsZCBuZXZlciBoYXBwZW4uXG4gICAgICAgICAgICAgICAgICAgIC8vIENvdWxkIGJlIGJlY2F1c2Ugb2YgZWRnZSBjYXNlcyByZWdhcmRpbmcgdGltZSBhbHRlcmluZyBvbiBkZXZpY2UuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTZXNzaW9uIGxlbmd0aCB3YXMgY2FsY3VsYXRlZCB0byBiZSBsZXNzIHRoZW4gMC4gU2hvdWxkIG5vdCBiZSBwb3NzaWJsZS4gUmVzZXR0aW5nIHRvIDAuXCIpO1xuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uTGVuZ3RoID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wibGVuZ3RoXCJdID0gc2Vzc2lvbkxlbmd0aDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzO1xuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBFTkQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBhbGwgZXZlbnQgcmlnaHQgYXdheVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoXCJcIiwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNES0luaXRFdmVudCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIWdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihHQUV2ZW50cy53YXNTREtJbml0RXZlbnRTZW50KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBzZGsgaW5pdCBuZWVkcyB0byBiZSBzZW50IG9ubHkgb25jZSBvbiBhcHAgb3BlblxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy53YXNTREtJbml0RXZlbnRTZW50ID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNES0luaXQ7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlc3Npb25OdW06bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCk7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImlzX2ZpcnN0X3Nka19pbml0XCJdID0gc2Vzc2lvbk51bSA9PT0gMTtcblxuICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5hZGRIZWFsdGhBbm5vdGF0aW9ucyhldmVudERpY3QpO1xuICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5hZGRTREtJbml0RGF0YShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZGVkIHNkayBpbml0IGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZFNES0luaXRFdmVudCAtIEV4Y2VwdGlvbiB0aHJvd246IFwiICsgZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEhlYWx0aEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguaXNFbmFibGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5SGVhbHRoO1xuXG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZEhlYWx0aEFubm90YXRpb25zKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZFBlcmZvcm1hbmNlRGF0YShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZGVkIGhlYWx0aCBldmVudFwiKTtcblxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRIZWFsdGhFdmVudCAtIEV4Y2VwdGlvbiB0aHJvd246IFwiICsgZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGNhcnRUeXBlOnN0cmluZyA9IG51bGwsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIG1lcmdlRmllbGRzOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRpb25SZXN1bHQ6VmFsaWRhdGlvblJlc3VsdCA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlQnVzaW5lc3NFdmVudChjdXJyZW5jeSwgYW1vdW50LCBjYXJ0VHlwZSwgaXRlbVR5cGUsIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgdHJhbnNhY3Rpb24gbnVtYmVyIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRUcmFuc2FjdGlvbk51bSgpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSwgR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gUmVxdWlyZWRcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUJ1c2luZXNzO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImN1cnJlbmN5XCJdID0gY3VycmVuY3k7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5XSA9IEdBU3RhdGUuZ2V0VHJhbnNhY3Rpb25OdW0oKTtcblxuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsXG4gICAgICAgICAgICAgICAgaWYgKGNhcnRUeXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2FydF90eXBlXCJdID0gY2FydFR5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgaWYoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKG1lcmdlRmllbGRzICYmIGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBCVVNJTkVTUyBldmVudDoge2N1cnJlbmN5OlwiICsgY3VycmVuY3kgKyBcIiwgYW1vdW50OlwiICsgYW1vdW50ICsgXCIsIGl0ZW1UeXBlOlwiICsgaXRlbVR5cGUgKyBcIiwgaXRlbUlkOlwiICsgaXRlbUlkICsgXCIsIGNhcnRUeXBlOlwiICsgY2FydFR5cGUgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlLCBjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZywgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCkpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gSWYgZmxvdyB0eXBlIGlzIHNpbmsgcmV2ZXJzZSBhbW91bnRcbiAgICAgICAgICAgICAgICBpZiAoZmxvd1R5cGUgPT09IEVHQVJlc291cmNlRmxvd1R5cGUuU2luaylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFtb3VudCAqPSAtMTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgZXZlbnQgc3BlY2lmaWMgdmFsdWVzXG4gICAgICAgICAgICAgICAgdmFyIGZsb3dUeXBlU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLnJlc291cmNlRmxvd1R5cGVUb1N0cmluZyhmbG93VHlwZSk7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiZXZlbnRfaWRcIl0gPSBmbG93VHlwZVN0cmluZyArIFwiOlwiICsgY3VycmVuY3kgKyBcIjpcIiArIGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVJlc291cmNlO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImFtb3VudFwiXSA9IGFtb3VudDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZXJnZUZpZWxkcyAmJiBmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUkVTT1VSQ0UgZXZlbnQ6IHtjdXJyZW5jeTpcIiArIGN1cnJlbmN5ICsgXCIsIGFtb3VudDpcIiArIGFtb3VudCArIFwiLCBpdGVtVHlwZTpcIiArIGl0ZW1UeXBlICsgXCIsIGl0ZW1JZDpcIiArIGl0ZW1JZCArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxOnN0cmluZywgcHJvZ3Jlc3Npb24wMjpzdHJpbmcsIHByb2dyZXNzaW9uMDM6c3RyaW5nLCBzY29yZTpudW1iZXIsIHNlbmRTY29yZTpib29sZWFuLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBtZXJnZUZpZWxkczpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwcm9ncmVzc2lvblN0YXR1c1N0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5wcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHByb2dyZXNzaW9uU3RhdHVzKTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0aW9uUmVzdWx0OlZhbGlkYXRpb25SZXN1bHQgPSBHQVZhbGlkYXRvci52YWxpZGF0ZVByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDEsIHByb2dyZXNzaW9uMDIsIHByb2dyZXNzaW9uMDMpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gUHJvZ3Jlc3Npb24gaWRlbnRpZmllclxuICAgICAgICAgICAgICAgIHZhciBwcm9ncmVzc2lvbklkZW50aWZpZXI6c3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgaWYgKCFwcm9ncmVzc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiZXZlbnRfaWRcIl0gPSBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiOlwiICsgcHJvZ3Jlc3Npb25JZGVudGlmaWVyO1xuXG4gICAgICAgICAgICAgICAgLy8gQXR0ZW1wdFxuICAgICAgICAgICAgICAgIHZhciBhdHRlbXB0X251bTpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHNjb3JlIGlmIHNwZWNpZmllZCBhbmQgc3RhdHVzIGlzIG5vdCBzdGFydFxuICAgICAgICAgICAgICAgIGlmIChzZW5kU2NvcmUgJiYgcHJvZ3Jlc3Npb25TdGF0dXMgIT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuU3RhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJzY29yZVwiXSA9IE1hdGgucm91bmQoc2NvcmUpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENvdW50IGF0dGVtcHRzIG9uIGVhY2ggcHJvZ3Jlc3Npb24gZmFpbCBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuRmFpbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBhdHRlbXB0IG51bWJlclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBpbmNyZW1lbnQgYW5kIGFkZCBhdHRlbXB0X251bSBvbiBjb21wbGV0ZSBhbmQgZGVsZXRlIHBlcnNpc3RlZFxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgYXR0ZW1wdCBudW1iZXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIGV2ZW50XG4gICAgICAgICAgICAgICAgICAgIGF0dGVtcHRfbnVtID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImF0dGVtcHRfbnVtXCJdID0gYXR0ZW1wdF9udW07XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5jbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gZmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFBST0dSRVNTSU9OIGV2ZW50OiB7c3RhdHVzOlwiICsgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIiwgcHJvZ3Jlc3Npb24wMTpcIiArIHByb2dyZXNzaW9uMDEgKyBcIiwgcHJvZ3Jlc3Npb24wMjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIiwgcHJvZ3Jlc3Npb24wMzpcIiArIHByb2dyZXNzaW9uMDMgKyBcIiwgc2NvcmU6XCIgKyBzY29yZSArIFwiLCBhdHRlbXB0OlwiICsgYXR0ZW1wdF9udW0gKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlOm51bWJlciwgc2VuZFZhbHVlOmJvb2xlYW4sIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIG1lcmdlRmllbGRzOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5RGVzaWduO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImV2ZW50X2lkXCJdID0gZXZlbnRJZDtcblxuICAgICAgICAgICAgICAgIGlmKHNlbmRWYWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInZhbHVlXCJdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREYXRhKTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgaWYgKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKG1lcmdlRmllbGRzICYmIGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWZpZWxkc1RvVXNlW2tleV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBERVNJR04gZXZlbnQ6IHtldmVudElkOlwiICsgZXZlbnRJZCArIFwiLCB2YWx1ZTpcIiArIHZhbHVlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIG1lcmdlRmllbGRzOmJvb2xlYW4sIHNraXBBZGRpbmdGaWVsZHM6Ym9vbGVhbj1mYWxzZSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgc2V2ZXJpdHlTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMuZXJyb3JTZXZlcml0eVRvU3RyaW5nKHNldmVyaXR5KTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRpb25SZXN1bHQ6VmFsaWRhdGlvblJlc3VsdCA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlRXJyb3JFdmVudChzZXZlcml0eSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUVycm9yO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInNldmVyaXR5XCJdID0gc2V2ZXJpdHlTdHJpbmc7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wibWVzc2FnZVwiXSA9IG1lc3NhZ2U7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGEpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXNraXBBZGRpbmdGaWVsZHMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBpZiAoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKG1lcmdlRmllbGRzICYmIGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGF0YSwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEVSUk9SIGV2ZW50OiB7c2V2ZXJpdHk6XCIgKyBzZXZlcml0eVN0cmluZyArIFwiLCBtZXNzYWdlOlwiICsgbWVzc2FnZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50KGFkQWN0aW9uOkVHQUFkQWN0aW9uLCBhZFR5cGU6RUdBQWRUeXBlLCBhZFNka05hbWU6c3RyaW5nLCBhZFBsYWNlbWVudDpzdHJpbmcsIG5vQWRSZWFzb246RUdBQWRFcnJvciwgZHVyYXRpb246bnVtYmVyLCBzZW5kRHVyYXRpb246Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgYWRBY3Rpb25TdHJpbmc6c3RyaW5nID0gR0FFdmVudHMuYWRBY3Rpb25Ub1N0cmluZyhhZEFjdGlvbik7XG4gICAgICAgICAgICAgICAgdmFyIGFkVHlwZVN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5hZFR5cGVUb1N0cmluZyhhZFR5cGUpO1xuICAgICAgICAgICAgICAgIHZhciBub0FkUmVhc29uU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmFkRXJyb3JUb1N0cmluZyhub0FkUmVhc29uKTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRpb25SZXN1bHQ6VmFsaWRhdGlvblJlc3VsdCA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlQWRFdmVudChhZEFjdGlvbiwgYWRUeXBlLCBhZFNka05hbWUsIGFkUGxhY2VtZW50KTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QWRzO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImFkX3Nka19uYW1lXCJdID0gYWRTZGtOYW1lO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImFkX3BsYWNlbWVudFwiXSA9IGFkUGxhY2VtZW50O1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImFkX3R5cGVcIl0gPSBhZFR5cGVTdHJpbmc7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfYWN0aW9uXCJdID0gYWRBY3Rpb25TdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBpZihhZEFjdGlvbiA9PSBFR0FBZEFjdGlvbi5GYWlsZWRTaG93ICYmIG5vQWRSZWFzb25TdHJpbmcubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImFkX2ZhaWxfc2hvd19yZWFzb25cIl0gPSBub0FkUmVhc29uU3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHNlbmREdXJhdGlvbiAmJiAoYWRUeXBlID09IEVHQUFkVHlwZS5SZXdhcmRlZFZpZGVvIHx8IGFkVHlwZSA9PSBFR0FBZFR5cGUuVmlkZW8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfZHVyYXRpb25cIl0gPSBkdXJhdGlvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gZmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERhdGEsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEFEIGV2ZW50OiB7YWRfc2RrX25hbWU6XCIgKyBhZFNka05hbWUgKyBcIiwgYWRfcGxhY2VtZW50OlwiICsgYWRQbGFjZW1lbnQgKyBcIiwgYWRfdHlwZTpcIiArIGFkVHlwZVN0cmluZyArIFwiLCBhZF9hY3Rpb246XCIgKyBhZEFjdGlvblN0cmluZyArICgoYWRBY3Rpb24gPT0gRUdBQWRBY3Rpb24uRmFpbGVkU2hvdyAmJiBub0FkUmVhc29uU3RyaW5nLmxlbmd0aCA+IDApID8gKFwiLCBhZF9mYWlsX3Nob3dfcmVhc29uOlwiICsgbm9BZFJlYXNvblN0cmluZykgOiBcIlwiKSArICgoc2VuZER1cmF0aW9uICYmIChhZFR5cGUgPT0gRUdBQWRUeXBlLlJld2FyZGVkVmlkZW8gfHwgYWRUeXBlID09IEVHQUFkVHlwZS5WaWRlbykpID8gKFwiLCBhZF9kdXJhdGlvbjpcIiArIGR1cmF0aW9uKSA6IFwiXCIpICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHByb2Nlc3NFdmVudHMoY2F0ZWdvcnk6c3RyaW5nLCBwZXJmb3JtQ2xlYW5VcDpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHRocm93IG5ldyBFcnJvcihcInByb2Nlc3NFdmVudHMgbm90IGltcGxlbWVudGVkXCIpO1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZGVudGlmaWVyOnN0cmluZyA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDbGVhbnVwXG4gICAgICAgICAgICAgICAgICAgIGlmKHBlcmZvcm1DbGVhblVwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jbGVhbnVwRXZlbnRzKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5maXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cygpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gUHJlcGFyZSBTUUxcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlbGVjdEFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIFwibmV3XCJdKTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlV2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIFwibmV3XCJdKTtcbiAgICAgICAgICAgICAgICAgICAgaWYoY2F0ZWdvcnkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJjYXRlZ29yeVwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgY2F0ZWdvcnldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZVNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlU2V0QXJncy5wdXNoKFtcInN0YXR1c1wiLCByZXF1ZXN0SWRlbnRpZmllcl0pO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBldmVudHMgdG8gcHJvY2Vzc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnRzOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBmb3IgZXJyb3JzIG9yIGVtcHR5XG4gICAgICAgICAgICAgICAgICAgIGlmKCFldmVudHMgfHwgZXZlbnRzLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IE5vIGV2ZW50cyB0byBzZW5kXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudXBkYXRlU2Vzc2lvblN0b3JlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBudW1iZXIgb2YgZXZlbnRzIGFuZCB0YWtlIHNvbWUgYWN0aW9uIGlmIHRoZXJlIGFyZSB0b28gbWFueT9cbiAgICAgICAgICAgICAgICAgICAgaWYoZXZlbnRzLmxlbmd0aCA+IEdBRXZlbnRzLk1heEV2ZW50Q291bnQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIE1ha2UgYSBsaW1pdCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgICAgICAgICBldmVudHMgPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MsIHRydWUsIEdBRXZlbnRzLk1heEV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIEdldCBsYXN0IHRpbWVzdGFtcFxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RJdGVtOntba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbZXZlbnRzLmxlbmd0aCAtIDFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RUaW1lc3RhbXA6c3RyaW5nID0gbGFzdEl0ZW1bXCJjbGllbnRfdHNcIl0gYXMgc3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFNlbGVjdCBhZ2FpblxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZXZlbnRzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBTZW5kaW5nIFwiICsgZXZlbnRzLmxlbmd0aCArIFwiIGV2ZW50cy5cIik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gU2V0IHN0YXR1cyBvZiBldmVudHMgdG8gJ3NlbmRpbmcnIChhbHNvIGNoZWNrIGZvciBlcnJvcilcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHVwZGF0ZVNldEFyZ3MsIHVwZGF0ZVdoZXJlQXJncykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBwYXlsb2FkIGRhdGEgZnJvbSBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgdmFyIHBheWxvYWRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGk6bnVtYmVyID0gMDsgaSA8IGV2ZW50cy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2Ontba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbaV07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0ID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChldltcImV2ZW50XCJdKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXZlbnREaWN0Lmxlbmd0aCAhPSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczogbnVtYmVyID0gZXZlbnREaWN0W1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoY2xpZW50VHMgJiYgIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ2xpZW50VHMoY2xpZW50VHMpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIGV2ZW50RGljdFtcImNsaWVudF90c1wiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGF5bG9hZEFycmF5LnB1c2goZXZlbnREaWN0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kRXZlbnRzSW5BcnJheShwYXlsb2FkQXJyYXksIHJlcXVlc3RJZGVudGlmaWVyLCBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzQ2FsbGJhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJFcnJvciBkdXJpbmcgUHJvY2Vzc0V2ZW50cygpOiBcIiArIGUuc3RhY2spO1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5Kc29uLCBFR0FTZGtFcnJvckFyZWEuUHJvY2Vzc0V2ZW50cywgRUdBU2RrRXJyb3JBY3Rpb24uSnNvbkVycm9yLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIGUuc3RhY2ssIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRzQ2FsbGJhY2socmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSwgZGF0YURpY3Q6e1trZXk6c3RyaW5nXTogYW55fSwgIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgcmVxdWVzdElkV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCByZXF1ZXN0SWRdKTtcblxuICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gRGVsZXRlIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogXCIgKyBldmVudENvdW50ICsgXCIgZXZlbnRzIHNlbnQuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBQdXQgZXZlbnRzIGJhY2sgKE9ubHkgaW4gY2FzZSBvZiBubyByZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cyB0byBjb2xsZWN0b3IgLSBSZXRyeWluZyBuZXh0IHRpbWVcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHNldEFyZ3MsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBEZWxldGUgZXZlbnRzIChXaGVuIGdldHRpbmcgc29tZSBhbndzZXIgYmFjayBhbHdheXMgYXNzdW1lIGV2ZW50cyBhcmUgcHJvY2Vzc2VkKVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZGF0YURpY3QpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGpzb246YW55O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiBpbiBkYXRhRGljdClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGpzb24gPSBkYXRhRGljdFtqXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgJiYganNvbi5jb25zdHJ1Y3RvciA9PT0gQXJyYXkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IFwiICsgZXZlbnRDb3VudCArIFwiIGV2ZW50cyBzZW50LiBcIiArIGNvdW50ICsgXCIgZXZlbnRzIGZhaWxlZCBHQSBzZXJ2ZXIgdmFsaWRhdGlvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNsZWFudXBFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgW1tcInN0YXR1c1wiICwgXCJuZXdcIl1dKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEdldCBhbGwgc2Vzc2lvbnMgdGhhdCBhcmUgbm90IGN1cnJlbnRcbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBhcmdzLnB1c2goW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbCwgR0FTdGF0ZS5nZXRTZXNzaW9uSWQoKV0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25zOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuU2Vzc2lvbnMsIGFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgaWYgKCFzZXNzaW9ucyB8fCBzZXNzaW9ucy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKHNlc3Npb25zLmxlbmd0aCArIFwiIHNlc3Npb24ocykgbG9jYXRlZCB3aXRoIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnRzXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBzZXNzaW9ucy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uRW5kRXZlbnQ6e1trZXk6c3RyaW5nXTogYW55fSA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2Vzc2lvbnNbaV1bXCJldmVudFwiXSBhcyBzdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50X3RzOm51bWJlciA9IHNlc3Npb25FbmRFdmVudFtcImNsaWVudF90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdGFydF90czpudW1iZXIgPSBzZXNzaW9uc1tpXVtcInRpbWVzdGFtcFwiXSBhcyBudW1iZXI7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGxlbmd0aDpudW1iZXIgPSBldmVudF90cyAtIHN0YXJ0X3RzO1xuICAgICAgICAgICAgICAgICAgICBsZW5ndGggPSBNYXRoLm1heCgwLCBsZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKGxlbmd0aCA9PT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAgICAgIGxlbmd0aCA9IDA7XG4gICAgICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMgbGVuZ3RoIGNhbGN1bGF0ZWQ6IFwiICsgbGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uRW5kRXZlbnRbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvbkVuZDtcbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkVuZEV2ZW50W1wibGVuZ3RoXCJdID0gbGVuZ3RoO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoc2Vzc2lvbkVuZEV2ZW50KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZEV2ZW50VG9TdG9yZShldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDaGVjayBpZiB3ZSBhcmUgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBhZGQgZXZlbnQ6IFNESyBpcyBub3QgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGRiIHNpemUgbGltaXRzICgxMG1iKVxuICAgICAgICAgICAgICAgICAgICAvLyBJZiBkYXRhYmFzZSBpcyB0b28gbGFyZ2UgYmxvY2sgYWxsIGV4Y2VwdCB1c2VyLCBzZXNzaW9uIGFuZCBidXNpbmVzc1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdG9yZS5pc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKSAmJiAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gYXMgc3RyaW5nLCAvXih1c2VyfHNlc3Npb25fZW5kfGJ1c2luZXNzKSQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkRhdGFiYXNlIHRvbyBsYXJnZS4gRXZlbnQgaGFzIGJlZW4gYmxvY2tlZC5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5EYXRhYmFzZSwgRUdBU2RrRXJyb3JBcmVhLkFkZEV2ZW50c1RvU3RvcmUsIEVHQVNka0Vycm9yQWN0aW9uLkRhdGFiYXNlVG9vTGFyZ2UsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgXCJcIiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBkZWZhdWx0IGFubm90YXRpb25zXG4gICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gTWVyZ2Ugd2l0aCBldmVudERhdGFcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBlIGluIGV2ZW50RGF0YSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZXZbZV0gPSBldmVudERhdGFbZV07XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDcmVhdGUganNvbiBzdHJpbmcgcmVwcmVzZW50YXRpb25cbiAgICAgICAgICAgICAgICAgICAgdmFyIGpzb246c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXYpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIG91dHB1dCBpZiBWRVJCT1NFIExPRyBlbmFibGVkXG5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaWkoXCJFdmVudCBhZGRlZCB0byBxdWV1ZTogXCIgKyBqc29uKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInN0YXR1c1wiXSA9IFwibmV3XCI7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNhdGVnb3J5XCJdID0gZXZbXCJjYXRlZ29yeVwiXTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IGV2W1wic2Vzc2lvbl9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiY2xpZW50X3RzXCJdID0gZXZbXCJjbGllbnRfdHNcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcblxuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5FdmVudHMsIHZhbHVlcyk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHNlc3Npb24gc3RvcmUgaWYgbm90IGxhc3RcbiAgICAgICAgICAgICAgICAgICAgaWYgKGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID09IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvbkVuZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuU2Vzc2lvbnMsIFtbXCJzZXNzaW9uX2lkXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBldltcInNlc3Npb25faWRcIl0gYXMgc3RyaW5nXV0pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudXBkYXRlU2Vzc2lvblN0b3JlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNhdmUoR0FTdGF0ZS5nZXRHYW1lS2V5KCkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZEV2ZW50VG9TdG9yZTogZXJyb3JcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvckNhdGVnb3J5LkRhdGFiYXNlLCBFR0FTZGtFcnJvckFyZWEuQWRkRXZlbnRzVG9TdG9yZSwgRUdBU2RrRXJyb3JBY3Rpb24uRGF0YWJhc2VUb29MYXJnZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBlLnN0YWNrLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgdXBkYXRlU2Vzc2lvblN0b3JlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInRpbWVzdGFtcFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2OiB7IFtrZXk6IHN0cmluZ106IGFueSB9ID0gR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2KTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXYsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShldikpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5TZXNzaW9ucywgdmFsdWVzLCB0cnVlLCBcInNlc3Npb25faWRcIik7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zYXZlKEdBU3RhdGUuZ2V0R2FtZUtleSgpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudERhdGEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIGFkZCB0byBkaWN0IChpZiBub3QgbmlsKVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAxXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDJcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wM1wiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9LCBmaWVsZHM6e1trZXk6c3RyaW5nXTogYW55fSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFldmVudERhdGEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV9maWVsZHNcIl0gPSBmaWVsZHM7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZXNvdXJjZUZsb3dUeXBlVG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5Tb3VyY2UgfHwgdmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZVtFR0FSZXNvdXJjZUZsb3dUeXBlLlNvdXJjZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTb3VyY2VcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlNpbmsgfHwgdmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZVtFR0FSZXNvdXJjZUZsb3dUeXBlLlNpbmtdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU2lua1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2dyZXNzaW9uU3RhdHVzVG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuU3RhcnQgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuU3RhcnRdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU3RhcnRcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5Db21wbGV0ZSB8fCB2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1c1tFR0FQcm9ncmVzc2lvblN0YXR1cy5Db21wbGV0ZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJDb21wbGV0ZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWwgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuRmFpbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJGYWlsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZXJyb3JTZXZlcml0eVRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuRGVidWcgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkRlYnVnXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImRlYnVnXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5JbmZvIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5JbmZvXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImluZm9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5Lldhcm5pbmcgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5Lldhcm5pbmddKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwid2FybmluZ1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuRXJyb3IgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkVycm9yXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImVycm9yXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5Dcml0aWNhbCB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuQ3JpdGljYWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiY3JpdGljYWxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZEFjdGlvblRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQUFkQWN0aW9uLkNsaWNrZWQgfHwgdmFsdWUgPT0gRUdBQWRBY3Rpb25bRUdBQWRBY3Rpb24uQ2xpY2tlZF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjbGlja2VkXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRBY3Rpb24uU2hvdyB8fCB2YWx1ZSA9PSBFR0FBZEFjdGlvbltFR0FBZEFjdGlvbi5TaG93XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcInNob3dcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEFjdGlvbi5GYWlsZWRTaG93IHx8IHZhbHVlID09IEVHQUFkQWN0aW9uW0VHQUFkQWN0aW9uLkZhaWxlZFNob3ddKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZmFpbGVkX3Nob3dcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEFjdGlvbi5SZXdhcmRSZWNlaXZlZCB8fCB2YWx1ZSA9PSBFR0FBZEFjdGlvbltFR0FBZEFjdGlvbi5SZXdhcmRSZWNlaXZlZF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJyZXdhcmRfcmVjZWl2ZWRcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZEVycm9yVG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBQWRFcnJvci5Vbmtub3duIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5Vbmtub3duXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcInVua25vd25cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLk9mZmxpbmUgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLk9mZmxpbmVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwib2ZmbGluZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuTm9GaWxsIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5Ob0ZpbGxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwibm9fZmlsbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuSW50ZXJuYWxFcnJvciB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuSW50ZXJuYWxFcnJvcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnRlcm5hbF9lcnJvclwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuSW52YWxpZFJlcXVlc3QgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLkludmFsaWRSZXF1ZXN0XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfcmVxdWVzdFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuVW5hYmxlVG9QcmVjYWNoZSB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuVW5hYmxlVG9QcmVjYWNoZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ1bmFibGVfdG9fcHJlY2FjaGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZFR5cGVUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuVmlkZW8gfHwgdmFsdWUgPT0gRUdBQWRUeXBlW0VHQUFkVHlwZS5WaWRlb10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ2aWRlb1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkVHlwZS5SZXdhcmRlZFZpZGVvIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRUeXBlLlJld2FyZGVkVmlkZW9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmV3YXJkZWRfdmlkZW9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuUGxheWFibGUgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZFR5cGUuUGxheWFibGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicGxheWFibGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuSW50ZXJzdGl0aWFsIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRUeXBlLkludGVyc3RpdGlhbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnRlcnN0aXRpYWxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuT2ZmZXJXYWxsIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRUeXBlLk9mZmVyV2FsbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJvZmZlcl93YWxsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRUeXBlLkJhbm5lciB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkVHlwZS5CYW5uZXJdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYmFubmVyXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0aHJlYWRpbmdcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUV2ZW50cyA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkdBRXZlbnRzO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVRocmVhZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVRocmVhZGluZyA9IG5ldyBHQVRocmVhZGluZygpO1xuICAgICAgICAgICAgcHJpdmF0ZSByZWFkb25seSB0YXNrUXVldWU6QXJyYXk8KCkgPT4gdm9pZD4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGV2ZW50SW50ZXJ2YWxJZDpSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBQcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyID0gOC4wO1xuICAgICAgICAgICAgcHJpdmF0ZSBpc1J1bm5pbmc6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzZXRJbnRlcnZhbChHQVRocmVhZGluZy5ydW4sIDEwMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRhc2tPbkdBVGhyZWFkKHRhc2tCbG9jazooKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLnRhc2tRdWV1ZS5wdXNoKHRhc2tCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5ldmVudEludGVydmFsSWQgPSBzZXRJbnRlcnZhbChcbiAgICAgICAgICAgICAgICAgICAgICAgICgpID0+IEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZChHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSksXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMgKiAxMDAwXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFbmRpbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0b3BFdmVudFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRIZWFsdGhFdmVudCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvbkVuZEV2ZW50KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IDA7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RvcEV2ZW50UXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGNsZWFySW50ZXJ2YWwoR0FUaHJlYWRpbmcuZXZlbnRJbnRlcnZhbElkKTtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGludGVydmFsID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcyA9IGludGVydmFsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB3aGlsZSAoR0FUaHJlYWRpbmcuaW5zdGFuY2UudGFza1F1ZXVlLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCB0YXNrID0gR0FUaHJlYWRpbmcuaW5zdGFuY2UudGFza1F1ZXVlLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0YXNrKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyB0YXNrKCk7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGNhdGNoIChlOiBhbnkpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIG9uIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlByb2Nlc3NpbmcgZXZlbnQgcXVldWUuLi5cIik7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCB0cnVlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgaW1wb3J0IEdBVGhyZWFkaW5nID0gZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmc7XG4gICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgIGltcG9ydCBHQURldmljZSA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLkdBRGV2aWNlO1xuICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICBpbXBvcnQgRUdBSFRUUEFwaVJlc3BvbnNlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcbiAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICBpbXBvcnQgR0FFdmVudHMgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5HQUV2ZW50cztcbiAgICBpbXBvcnQgR0FIZWFsdGggPSBnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aDtcblxuICAgIGV4cG9ydCBjbGFzcyBHYW1lQW5hbHl0aWNzXG4gICAge1xucHVibGljIHN0YXRpYyBtZXRob2RNYXA6e1tpZDpzdHJpbmddOiAoLi4uYXJnczogYW55W10pID0+IHZvaWR9ID0ge307XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0R2xvYmFsT2JqZWN0KCk6IGFueVxuICAgICAgICB7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGdsb2JhbFRoaXMgIT09ICd1bmRlZmluZWQnKSB7IHJldHVybiBnbG9iYWxUaGlzOyB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIHNlbGYgIT09ICd1bmRlZmluZWQnKSB7IHJldHVybiBzZWxmOyB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIHdpbmRvdzsgfVxuICAgICAgICAgICAgaWYgKHR5cGVvZiBnbG9iYWwgIT09ICd1bmRlZmluZWQnKSB7IHJldHVybiBnbG9iYWw7IH1cbiAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGluaXQoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS50b3VjaCgpO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQnVpbGQnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQnVpbGQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlVXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZVVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRVc2VySWQnXSA9IEdhbWVBbmFseXRpY3MuZ2V0VXNlcklkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEV4dFVzZXJJZCddID0gR2FtZUFuYWx5dGljcy5zZXRFeHRVc2VySWQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0RXh0VXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLmdldEV4dFVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpbml0aWFsaXplJ10gPSBHYW1lQW5hbHl0aWNzLmluaXRpYWxpemU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkQnVzaW5lc3NFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRCdXNpbmVzc0V2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFJlc291cmNlRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkUmVzb3VyY2VFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRQcm9ncmVzc2lvbkV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZFByb2dyZXNzaW9uRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRGVzaWduRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRGVzaWduRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRXJyb3JFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRFcnJvckV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEFkRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkQWRFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkSW5mb0xvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkSW5mb0xvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkVmVyYm9zZUxvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkVmVyYm9zZUxvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbiddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2VuYWJsZUhlYWx0aEV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmVuYWJsZUhlYWx0aEV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAxJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAyJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAzJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzJ10gPSBHYW1lQW5hbHl0aWNzLnNldEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEV2ZW50UHJvY2Vzc0ludGVydmFsJ10gPSBHYW1lQW5hbHl0aWNzLnNldEV2ZW50UHJvY2Vzc0ludGVydmFsO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3N0YXJ0U2Vzc2lvbiddID0gR2FtZUFuYWx5dGljcy5zdGFydFNlc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZW5kU2Vzc2lvbiddID0gR2FtZUFuYWx5dGljcy5lbmRTZXNzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ29uU3RvcCddID0gR2FtZUFuYWx5dGljcy5vblN0b3A7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnb25SZXN1bWUnXSA9IEdhbWVBbmFseXRpY3Mub25SZXN1bWU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyJ10gPSBHYW1lQW5hbHl0aWNzLmFkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydyZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MucmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2dldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzU3RyaW5nJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzU3RyaW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2dldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzSlNPTiddID0gR2FtZUFuYWx5dGljcy5nZXRSZW1vdGVDb25maWdzVmFsdWVBc0pTT047XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnaXNSZW1vdGVDb25maWdzUmVhZHknXSA9IEdhbWVBbmFseXRpY3MuaXNSZW1vdGVDb25maWdzUmVhZHk7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZyddID0gR2FtZUFuYWx5dGljcy5nZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZE9uQmVmb3JlVW5sb2FkTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MuYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydyZW1vdmVPbkJlZm9yZVVubG9hZExpc3RlbmVyJ10gPSBHYW1lQW5hbHl0aWNzLnJlbW92ZU9uQmVmb3JlVW5sb2FkTGlzdGVuZXI7XG4gICAgICAgICAgICBcblxuICAgICAgICAgICAgaWYgKHR5cGVvZiBHYW1lQW5hbHl0aWNzLmdldEdsb2JhbE9iamVjdCgpICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddWydxJ10gIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBxOiBhbnlbXSA9IEdhbWVBbmFseXRpY3MuZ2V0R2xvYmFsT2JqZWN0KClbJ0dhbWVBbmFseXRpY3MnXVsncSddO1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgaW4gcSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuZ2FDb21tYW5kLmFwcGx5KG51bGwsIHFbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuXG4gICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcImJlZm9yZXVubG9hZFwiLCAoZSkgPT4ge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKCdhZGRFdmVudExpc3RlbmVyIHVubG9hZCcpO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUubm90aWZ5QmVmb3JlVW5sb2FkTGlzdGVuZXJzKCk7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnYUNvbW1hbmQoLi4uYXJnczogYW55W10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKGFyZ3MubGVuZ3RoID4gMClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihhcmdzWzBdIGluIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihhcmdzLmxlbmd0aCA+IDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbYXJnc1swXV0uYXBwbHkobnVsbCwgQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJncywgMSkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFthcmdzWzBdXSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGl0ZW0gdHlwZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVCdWlsZChidWlsZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJCdWlsZCB2ZXJzaW9uIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdWlsZChidWlsZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGJ1aWxkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgMzIgbGVuZ3RoLiBTdHJpbmc6IFwiICsgYnVpbGQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QnVpbGQoYnVpbGQpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2RrV3JhcHBlclZlcnNpb24oc2RrR2FtZUVuZ2luZVZlcnNpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBzZGsgdmVyc2lvbjogU2RrIHZlcnNpb24gbm90IHN1cHBvcnRlZC4gU3RyaW5nOiBcIiArIHNka0dhbWVFbmdpbmVWZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbiA9IHNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uKGdhbWVFbmdpbmVWZXJzaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGdhbWUgZW5naW5lIHZlcnNpb246IEdhbWUgZW5naW5lIHZlcnNpb24gbm90IHN1cHBvcnRlZC4gU3RyaW5nOiBcIiArIGdhbWVFbmdpbmVWZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbiA9IGdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVVzZXJJZCh1SWQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQSBjdXN0b20gdXNlciBpZCBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlVXNlcklkKHVJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHVzZXJfaWQ6IENhbm5vdCBiZSBudWxsLCBlbXB0eSBvciBhYm92ZSA2NCBsZW5ndGguIFdpbGwgdXNlIGRlZmF1bHQgdXNlcl9pZCBtZXRob2QuIFVzZWQgc3RyaW5nOiBcIiArIHVJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldFVzZXJJZCh1SWQpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV4dFVzZXJJZCh1SWQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRFeHRVc2VySWQodUlkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRFeHRVc2VySWQoKTogc3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldEV4dFVzZXJJZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRVc2VySWQoKSA6IHN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGluaXRpYWxpemUoZ2FtZUtleTpzdHJpbmcgPSBcIlwiLCBnYW1lU2VjcmV0OnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNESyBhbHJlYWR5IGluaXRpYWxpemVkLiBDYW4gb25seSBiZSBjYWxsZWQgb25jZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGZhaWxlZCBpbml0aWFsaXplLiBHYW1lIGtleSBvciBzZWNyZXQga2V5IGlzIGludmFsaWQuIENhbiBvbmx5IGNvbnRhaW4gY2hhcmFjdGVycyBBLXogMC05LCBnYW1lS2V5IGlzIDMyIGxlbmd0aCwgZ2FtZVNlY3JldCBpcyA0MCBsZW5ndGguIEZhaWxlZCBrZXlzIC0gZ2FtZUtleTogXCIgKyBnYW1lS2V5ICsgXCIsIHNlY3JldEtleTogXCIgKyBnYW1lU2VjcmV0KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0S2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KTtcblxuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW50ZXJuYWxJbml0aWFsaXplKCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIsIGNhcnRUeXBlOnN0cmluZyA9IFwiXCIsIGN1c3RvbUZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZighR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgY2FydFR5cGUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUgPSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZCwgY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiLCBjdXN0b21GaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30sIG1lcmdlRmllbGRzOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHJlc291cmNlIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czogRUdBUHJvZ3Jlc3Npb25TdGF0dXMgPSBFR0FQcm9ncmVzc2lvblN0YXR1cy5VbmRlZmluZWQsIHByb2dyZXNzaW9uMDE6IHN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDI6IHN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDM6IHN0cmluZyA9IFwiXCIsIHNjb3JlPzogbnVtYmVyLCBjdXN0b21GaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9LCBtZXJnZUZpZWxkczogYm9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHByb2dyZXNzaW9uIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOiBib29sZWFuID0gdHlwZW9mIHNjb3JlID09PSBcIm51bWJlclwiO1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzLCBzZW5kU2NvcmUgPyBzY29yZSA6IDAsIHNlbmRTY29yZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHByb2dyZXNzaW9uIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgIHZhciBzZW5kU2NvcmU6IGJvb2xlYW4gPSB0eXBlb2Ygc2NvcmUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMywgc2VuZFNjb3JlID8gc2NvcmUgOiAwLCBzZW5kU2NvcmUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOiBzdHJpbmcsIHZhbHVlPzogbnVtYmVyLCBjdXN0b21GaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9LCBtZXJnZUZpZWxkczogYm9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZW5kVmFsdWU6IGJvb2xlYW4gPSB0eXBlb2YgdmFsdWUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERlc2lnbkV2ZW50KGV2ZW50SWQsIHNlbmRWYWx1ZSA/IHZhbHVlIDogMCwgc2VuZFZhbHVlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgZGVzaWduIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIHNlbmRWYWx1ZTogYm9vbGVhbiA9IHR5cGVvZiB2YWx1ZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREZXNpZ25FdmVudChldmVudElkLCBzZW5kVmFsdWUgPyB2YWx1ZSA6IDAsIHNlbmRWYWx1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6IEVHQUVycm9yU2V2ZXJpdHkgPSBFR0FFcnJvclNldmVyaXR5LlVuZGVmaW5lZCwgbWVzc2FnZTogc3RyaW5nID0gXCJcIiwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEVycm9yRXZlbnQoc2V2ZXJpdHksIG1lc3NhZ2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEVycm9yRXZlbnQoc2V2ZXJpdHksIG1lc3NhZ2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50V2l0aE5vQWRSZWFzb24oYWRBY3Rpb246IEVHQUFkQWN0aW9uID0gRUdBQWRBY3Rpb24uVW5kZWZpbmVkLCBhZFR5cGU6IEVHQUFkVHlwZSA9IEVHQUFkVHlwZS5VbmRlZmluZWQsIGFkU2RrTmFtZTogc3RyaW5nID0gXCJcIiwgYWRQbGFjZW1lbnQ6IHN0cmluZyA9IFwiXCIsIG5vQWRSZWFzb246IEVHQUFkRXJyb3IgPSBFR0FBZEVycm9yLlVuZGVmaW5lZCwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgbm9BZFJlYXNvbiwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgbm9BZFJlYXNvbiwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50V2l0aER1cmF0aW9uKGFkQWN0aW9uOiBFR0FBZEFjdGlvbiA9IEVHQUFkQWN0aW9uLlVuZGVmaW5lZCwgYWRUeXBlOiBFR0FBZFR5cGUgPSBFR0FBZFR5cGUuVW5kZWZpbmVkLCBhZFNka05hbWU6IHN0cmluZyA9IFwiXCIsIGFkUGxhY2VtZW50OiBzdHJpbmcgPSBcIlwiLCBkdXJhdGlvbjogbnVtYmVyID0gMCwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgRUdBQWRFcnJvci5VbmRlZmluZWQsIGR1cmF0aW9uLCB0cnVlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIEVHQUFkRXJyb3IuVW5kZWZpbmVkLCBkdXJhdGlvbiwgdHJ1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEFkRXZlbnQoYWRBY3Rpb246IEVHQUFkQWN0aW9uID0gRUdBQWRBY3Rpb24uVW5kZWZpbmVkLCBhZFR5cGU6IEVHQUFkVHlwZSA9IEVHQUFkVHlwZS5VbmRlZmluZWQsIGFkU2RrTmFtZTogc3RyaW5nID0gXCJcIiwgYWRQbGFjZW1lbnQ6IHN0cmluZyA9IFwiXCIsIGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30sIG1lcmdlRmllbGRzOiBib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIEVHQUFkRXJyb3IuVW5kZWZpbmVkLCAwLCBmYWxzZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGFkIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQWRFdmVudChhZEFjdGlvbiwgYWRUeXBlLCBhZFNka05hbWUsIGFkUGxhY2VtZW50LCBFR0FBZEVycm9yLlVuZGVmaW5lZCwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkSW5mb0xvZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRJbmZvTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5mbyBsb2dnaW5nIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbmZvIGxvZ2dpbmcgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldEluZm9Mb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRWZXJib3NlTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZlcmJvc2UgbG9nZ2luZyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0VmVyYm9zZUxvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBzdWJtaXNzaW9uIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBzdWJtaXNzaW9uIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGVuYWJsZUhlYWx0aEV2ZW50KGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5jb25maWd1cmUoZmxhZyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMoY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBnbG9iYWwgY3VzdG9tIGV2ZW50IGZpZWxkczogXCIgKyBKU09OLnN0cmluZ2lmeShjdXN0b21GaWVsZHMpKTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcyA9IGN1c3RvbUZpZWxkcztcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbEluU2Vjb25kczpudW1iZXIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNldEV2ZW50UHJvY2Vzc0ludGVydmFsKGludGVydmFsSW5TZWNvbmRzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzdGFydFNlc3Npb24oKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvL2lmKEdBU3RhdGUuZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5yZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy9pZihHQVN0YXRlLmdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3Mub25TdG9wKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uU3RvcCgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoRXhjZXB0aW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgb25SZXN1bWUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLnJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmcoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyA9IG51bGwpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5LCBkZWZhdWx0VmFsdWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRSZW1vdGVDb25maWdzVmFsdWVBc0pTT04oa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOmFueSA9IG51bGwpOmFueVxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRDb25maWd1cmF0aW9uSnNvblZhbHVlKGtleSwgZGVmYXVsdFZhbHVlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgaXNSZW1vdGVDb25maWdzUmVhZHkoKTpib29sZWFuXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmlzUmVtb3RlQ29uZmlnc1JlYWR5KCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUuYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgcmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyOnsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5yZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmcoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QUJUZXN0aW5nSWQoKTpzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0QUJUZXN0aW5nSWQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QUJUZXN0aW5nVmFyaWFudElkKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldEFCVGVzdGluZ1ZhcmlhbnRJZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyOiB7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUuYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZU9uQmVmb3JlVW5sb2FkTGlzdGVuZXIobGlzdGVuZXI6IHsgb25CZWZvcmVVbmxvYWQ6ICgpID0+IHZvaWQgfSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5yZW1vdmVPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIGludGVybmFsSW5pdGlhbGl6ZSgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUuZW5zdXJlUGVyc2lzdGVkU3RhdGVzKCk7XG4gICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSwgR0FTdGF0ZS5nZXREZWZhdWx0SWQoKSk7XG5cbiAgICAgICAgICAgIEdBU3RhdGUuc2V0SW5pdGlhbGl6ZWQodHJ1ZSk7XG5cbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xuXG4gICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBuZXdTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FMb2dnZXIuaShcIlN0YXJ0aW5nIGEgbmV3IHNlc3Npb24uXCIpO1xuXG4gICAgICAgICAgICAvLyBtYWtlIHN1cmUgdGhlIGN1cnJlbnQgY3VzdG9tIGRpbWVuc2lvbnMgYXJlIHZhbGlkXG4gICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnJlcXVlc3RJbml0KEdBU3RhdGUuaW5zdGFuY2UuY29uZmlnc0hhc2gsIEdhbWVBbmFseXRpY3Muc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2spO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2soaW5pdFJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwgaW5pdFJlc3BvbnNlRGljdDp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBpbml0IGlzIG9rXG4gICAgICAgICAgICBpZigoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCkgJiYgaW5pdFJlc3BvbnNlRGljdClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBzZXQgdGhlIHRpbWUgb2Zmc2V0IC0gaG93IG1hbnkgc2Vjb25kcyB0aGUgbG9jYWwgdGltZSBpcyBkaWZmZXJlbnQgZnJvbSBzZXJ2ZXJ0aW1lXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVPZmZzZXRTZWNvbmRzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlRGljdFtcInNlcnZlcl90c1wiXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUczpudW1iZXIgPSBpbml0UmVzcG9uc2VEaWN0W1wic2VydmVyX3RzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgdGltZU9mZnNldFNlY29uZHMgPSBHQVN0YXRlLmNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1widGltZV9vZmZzZXRcIl0gPSB0aW1lT2Zmc2V0U2Vjb25kcztcblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0NvbmZpZygpO1xuICAgICAgICAgICAgICAgICAgICAvLyB1c2UgY2FjaGVkIGlmIG5vdCBDcmVhdGVkXG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc1wiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzX2hhc2hcIl0gPSBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImFiX2lkXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWdzSGFzaCA9IGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzX2hhc2hcIl0gPyBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc19oYXNoXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmFiSWQgPSBpbml0UmVzcG9uc2VEaWN0W1wiYWJfaWRcIl0gPyBpbml0UmVzcG9uc2VEaWN0W1wiYWJfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQgPSBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA/IGluaXRSZXNwb25zZURpY3RbXCJhYl92YXJpYW50X2lkXCJdIDogXCJcIjtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBuZXcgY29uZmlnIGluIHNxbCBsaXRlIGNyb3NzIHNlc3Npb24gc3RvcmFnZVxuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXksIEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGluaXRSZXNwb25zZURpY3QpKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBzZXQgbmV3IGNvbmZpZyBhbmQgY2FjaGUgaW4gbWVtb3J5XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgPSBpbml0UmVzcG9uc2VEaWN0O1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gaW5pdFJlc3BvbnNlRGljdDtcblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT0gRUdBSFRUUEFwaVJlc3BvbnNlLlVuYXV0aG9yaXplZClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiSW5pdGlhbGl6ZSBTREsgZmFpbGVkIC0gVW5hdXRob3JpemVkXCIpO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBsb2cgdGhlIHN0YXR1cyBpZiBubyBjb25uZWN0aW9uXG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5SZXF1ZXN0VGltZW91dClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIG5vIHJlc3BvbnNlLiBDb3VsZCBiZSBvZmZsaW5lIG9yIHRpbWVvdXQuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkRlY29kZUZhaWxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXNwb25zZS4gQ291bGQgYmUgYmFkIHJlc3BvbnNlIGZyb20gcHJveHkgb3IgR0Egc2VydmVycy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdCB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Vbmtub3duUmVzcG9uc2VDb2RlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gYmFkIHJlcXVlc3Qgb3IgdW5rbm93biByZXNwb25zZS5cIik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5pdCBjYWxsIGZhaWxlZCAocGVyaGFwcyBvZmZsaW5lKVxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCAhPSBudWxsKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGxhc3QgY3Jvc3Mgc2Vzc2lvbiBzdG9yZWQgY29uZmlnIGluaXQgdmFsdWVzXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgZGVmYXVsdCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBpbml0IHZhbHVlc1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0RlZmF1bHQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgY2FjaGVkIGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIHNldCBvZmZzZXQgaW4gc3RhdGUgKG1lbW9yeSkgZnJvbSBjdXJyZW50IGNvbmZpZyAoY29uZmlnIGNvdWxkIGJlIGZyb20gY2FjaGUgZXRjLilcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY2xpZW50U2VydmVyVGltZU9mZnNldCA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKClbXCJ0aW1lX29mZnNldFwiXSA/IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKClbXCJ0aW1lX29mZnNldFwiXSBhcyBudW1iZXIgOiAwO1xuXG4gICAgICAgICAgICAvLyBwb3B1bGF0ZSBjb25maWd1cmF0aW9uc1xuICAgICAgICAgICAgR0FTdGF0ZS5wb3B1bGF0ZUNvbmZpZ3VyYXRpb25zKEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCkpO1xuXG4gICAgICAgICAgICAvLyBpZiBTREsgaXMgZGlzYWJsZWQgaW4gY29uZmlnXG4gICAgICAgICAgICBpZighR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHN0YXJ0IHNlc3Npb246IFNESyBpcyBkaXNhYmxlZC5cIik7XG4gICAgICAgICAgICAgICAgLy8gc3RvcCBldmVudCBxdWV1ZVxuICAgICAgICAgICAgICAgIC8vICsgbWFrZSBzdXJlIGl0J3MgYWJsZSB0byByZXN0YXJ0IGlmIGFub3RoZXIgc2Vzc2lvbiBkZXRlY3RzIGl0J3MgZW5hYmxlZCBhZ2FpblxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0b3BFdmVudFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gZ2VuZXJhdGUgdGhlIG5ldyBzZXNzaW9uXG4gICAgICAgICAgICB2YXIgbmV3U2Vzc2lvbklkOnN0cmluZyA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcblxuICAgICAgICAgICAgLy8gU2V0IHNlc3Npb24gaWRcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkID0gbmV3U2Vzc2lvbklkO1xuXG4gICAgICAgICAgICAvLyBTZXQgc2Vzc2lvbiBzdGFydFxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQgPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcblxuICAgICAgICAgICAgLy8gQWRkIHNlc3Npb24gc3RhcnQgZXZlbnRcbiAgICAgICAgICAgIEdBRXZlbnRzLmFkZFNlc3Npb25TdGFydEV2ZW50KCk7XG5cbiAgICAgICAgICAgIC8vIEFkZCBzZGsgaW5pdCBldmVudCBpZiBlbmFibGVkXG4gICAgICAgICAgICBHQUV2ZW50cy5hZGRTREtJbml0RXZlbnQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJSZXN1bWluZyBzZXNzaW9uLlwiKTtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm5ld1Nlc3Npb24oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIGlzU2RrUmVhZHkobmVlZHNJbml0aWFsaXplZDpib29sZWFuLCB3YXJuOmJvb2xlYW4gPSB0cnVlLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIpOiBib29sZWFuXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKG1lc3NhZ2UpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbWVzc2FnZSA9IG1lc3NhZ2UgKyBcIjogXCI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIElzIFNESyBpbml0aWFsaXplZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBJcyBTREsgZW5hYmxlZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNESyBpcyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgc2Vzc2lvbiBzdGFydGVkXG4gICAgICAgICAgICBpZiAobmVlZHNJbml0aWFsaXplZCAmJiAhR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNlc3Npb24gaGFzIG5vdCBzdGFydGVkIHlldFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9XG59XG5nYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuaW5pdCgpO1xudmFyIEdhbWVBbmFseXRpY3MgPSBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuZ2FDb21tYW5kO1xuIl19

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
