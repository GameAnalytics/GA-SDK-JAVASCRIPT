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

var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
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
    var http;
    (function (http) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAHttpClientBrowser = (function () {
            function GAHttpClientBrowser() {
            }
            GAHttpClientBrowser.prototype.initialize = function () { };
            GAHttpClientBrowser.prototype.cleanup = function () { };
            GAHttpClientBrowser.prototype.sendRequest = function (url, auth, payload, useGzip) {
                return new Promise(function (resolve) {
                    if (useGzip) {
                        GALogger.w("gzip is not supported by the browser HTTP client");
                        resolve({ code: -1, packet: new Uint8Array(0), statusText: "gzip unsupported" });
                        return;
                    }
                    var request = new XMLHttpRequest();
                    request.onreadystatechange = function () {
                        if (request.readyState === 4) {
                            var text = request.responseText || "";
                            resolve({ code: request.status || -1, packet: new TextEncoder().encode(text), statusText: request.statusText || "" });
                        }
                    };
                    request.open("POST", url, true);
                    request.setRequestHeader("Content-Type", "application/json");
                    request.setRequestHeader("Authorization", auth);
                    try {
                        request.send(payload);
                    }
                    catch (e) {
                        GALogger.e(e && e.stack ? e.stack : String(e));
                        resolve({ code: -1, packet: new Uint8Array(0), statusText: "send failed" });
                    }
                });
            };
            return GAHttpClientBrowser;
        }());
        http.GAHttpClientBrowser = GAHttpClientBrowser;
    })(http = gameanalytics.http || (gameanalytics.http = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var http;
    (function (http) {
        function makeHttpClient() {
            return new http.GAHttpClientBrowser();
        }
        http.makeHttpClient = makeHttpClient;
    })(http = gameanalytics.http || (gameanalytics.http = {}));
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
    var platform;
    (function (platform) {
        var GAPlatform = (function () {
            function GAPlatform() {
            }
            GAPlatform.prototype.getAdvertisingId = function () { return ""; };
            GAPlatform.prototype.getDeviceId = function () { return ""; };
            GAPlatform.prototype.getCpuModel = function () { return ""; };
            GAPlatform.prototype.getGpuModel = function () { return ""; };
            GAPlatform.prototype.getNumCpuCores = function () { return -1; };
            GAPlatform.prototype.getTotalDeviceMemory = function () { return -1; };
            GAPlatform.prototype.getAppMemoryUsage = function () { return -1; };
            GAPlatform.prototype.getSysMemoryUsage = function () { return -1; };
            GAPlatform.prototype.getBootTime = function () { return -1; };
            GAPlatform.prototype.getBrowserVersion = function () { return ""; };
            GAPlatform.prototype.onInit = function () { };
            GAPlatform.prototype.setupUncaughtExceptionHandler = function () { };
            return GAPlatform;
        }());
        platform.GAPlatform = GAPlatform;
    })(platform = gameanalytics.platform || (gameanalytics.platform = {}));
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
            GADevice.setPlatform = function (p) {
                GADevice.platform = p;
            };
            GADevice.getPlatform = function () {
                return GADevice.platform;
            };
            GADevice.getWritablePath = function () {
                return GADevice.platform ? GADevice.platform.getPersistentPath() : "";
            };
            Object.defineProperty(GADevice, "buildPlatform", {
                get: function () { return GADevice.platform ? GADevice.platform.getBuildPlatform() : "unknown"; },
                enumerable: false,
                configurable: true
            });
            Object.defineProperty(GADevice, "deviceModel", {
                get: function () { return GADevice.platform ? GADevice.platform.getDeviceModel() : "unknown"; },
                enumerable: false,
                configurable: true
            });
            Object.defineProperty(GADevice, "deviceManufacturer", {
                get: function () { return GADevice.platform ? GADevice.platform.getDeviceManufacturer() : "unknown"; },
                enumerable: false,
                configurable: true
            });
            Object.defineProperty(GADevice, "osVersion", {
                get: function () { return GADevice.platform ? GADevice.platform.getOSVersion() : "unknown 0.0.0"; },
                enumerable: false,
                configurable: true
            });
            Object.defineProperty(GADevice, "browserVersion", {
                get: function () { return GADevice.platform ? GADevice.platform.getBrowserVersion() : ""; },
                enumerable: false,
                configurable: true
            });
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
                GADevice.connectionType = GADevice.platform ? GADevice.platform.getConnectionType() : "offline";
            };
            GADevice.sdkWrapperVersion = "javascript 5.0.0";
            GADevice.platform = null;
            return GADevice;
        }());
        device.GADevice = GADevice;
    })(device = gameanalytics.device || (gameanalytics.device = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var platform;
    (function (platform) {
        var GALogger = gameanalytics.logging.GALogger;
        var NameValueVersion = gameanalytics.device.NameValueVersion;
        var NameVersion = gameanalytics.device.NameVersion;
        var GAPlatformBrowser = (function (_super) {
            __extends(GAPlatformBrowser, _super);
            function GAPlatformBrowser() {
                var _this = _super !== null && _super.apply(this, arguments) || this;
                _this.osVersionPair = null;
                return _this;
            }
            GAPlatformBrowser.prototype.getOsVersionPair = function () {
                if (this.osVersionPair === null) {
                    var agent = (typeof navigator !== 'undefined')
                        ? [navigator.platform, navigator.userAgent, navigator.appVersion, navigator.vendor].join(' ')
                        : '';
                    this.osVersionPair = GAPlatformBrowser.matchItem(agent, [
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
                }
                return this.osVersionPair;
            };
            GAPlatformBrowser.prototype.getOSVersion = function () { return this.getBuildPlatform() + " " + this.getOsVersionPair().version; };
            GAPlatformBrowser.prototype.getBuildPlatform = function () { return this.getOsVersionPair().name; };
            GAPlatformBrowser.prototype.getDeviceManufacturer = function () { return "unknown"; };
            GAPlatformBrowser.prototype.getDeviceModel = function () { return "unknown"; };
            GAPlatformBrowser.prototype.getPersistentPath = function () { return ""; };
            GAPlatformBrowser.prototype.getConnectionType = function () {
                if (typeof navigator === 'undefined' || navigator.onLine) {
                    var p = this.getBuildPlatform();
                    return (p === "ios" || p === "android") ? "wwan" : "lan";
                }
                return "offline";
            };
            GAPlatformBrowser.prototype.getNumCpuCores = function () {
                return (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : -1;
            };
            GAPlatformBrowser.prototype.getTotalDeviceMemory = function () {
                return (typeof navigator !== 'undefined' && navigator.deviceMemory) ? navigator.deviceMemory * 1073741824 : -1;
            };
            GAPlatformBrowser.prototype.getAppMemoryUsage = function () {
                return (typeof performance !== 'undefined' && performance.memory) ? performance.memory.usedJSHeapSize : -1;
            };
            GAPlatformBrowser.prototype.getBootTime = function () {
                return (typeof performance !== 'undefined') ? Math.round(performance.now()) : -1;
            };
            GAPlatformBrowser.prototype.getGpuModel = function () {
                try {
                    if (typeof document !== 'undefined') {
                        var canvas = document.createElement('canvas');
                        var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                        if (gl) {
                            var ext = gl.getExtension('WEBGL_debug_renderer_info');
                            if (ext) {
                                return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                            }
                        }
                    }
                }
                catch (e) { }
                return "";
            };
            GAPlatformBrowser.prototype.getBrowserVersion = function () {
                if (typeof navigator === 'undefined') {
                    return "";
                }
                var ua = navigator.userAgent;
                var tem;
                var M = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident|fbav(?=\/))\/?\s*(\d+)/i) || [];
                if (M.length == 0) {
                    if (this.getBuildPlatform() === "ios") {
                        return "webkit_" + this.getOSVersion();
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
            GAPlatformBrowser.prototype.onInit = function () {
                if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') {
                    return;
                }
                window.addEventListener("beforeunload", function () {
                    GALogger.d('addEventListener unload');
                    gameanalytics.state.GAState.instance.isUnloading = true;
                    gameanalytics.state.GAState.notifyBeforeUnloadListeners();
                    gameanalytics.threading.GAThreading.endSessionAndStopQueue();
                    gameanalytics.state.GAState.instance.isUnloading = false;
                });
            };
            GAPlatformBrowser.matchItem = function (agent, data) {
                var result = new NameVersion("unknown", "0.0.0");
                var mathcesResult;
                for (var i = 0; i < data.length; i += 1) {
                    if (new RegExp(data[i].value, 'i').test(agent)) {
                        var matches = agent.match(new RegExp(data[i].version + '[- /:;]([\\d._]+)', 'i'));
                        var version = '';
                        if (matches && matches[1]) {
                            mathcesResult = matches[1];
                        }
                        if (mathcesResult) {
                            var parts = mathcesResult.split(/[._]+/);
                            for (var j = 0; j < Math.min(parts.length, 3); j += 1) {
                                version += parts[j] + (j < Math.min(parts.length, 3) - 1 ? '.' : '');
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
            return GAPlatformBrowser;
        }(platform.GAPlatform));
        platform.GAPlatformBrowser = GAPlatformBrowser;
    })(platform = gameanalytics.platform || (gameanalytics.platform = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var platform;
    (function (platform) {
        function makePlatform() {
            return new platform.GAPlatformBrowser();
        }
        platform.makePlatform = makePlatform;
    })(platform = gameanalytics.platform || (gameanalytics.platform = {}));
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
            }
            GAStore.setStorage = function (s) {
                GAStore.storage = s;
                GALogger.d("Storage is available?: " + GAStore.isStorageAvailable());
            };
            GAStore.isStorageAvailable = function () {
                return GAStore.storage !== null && GAStore.storage.isAvailable();
            };
            GAStore.isStoreTooLargeForEvents = function () {
                var bytes = GAStore.storage ? GAStore.storage.getSizeBytes() : -1;
                if (bytes >= 0) {
                    return bytes > GAStore.MaxDbSizeBytes;
                }
                return GAStore.instance.eventsStore.length + GAStore.instance.sessionsStore.length > GAStore.MaxNumberOfEntries;
            };
            GAStore.deleteSessionCache = function () {
                if (GAStore.storage) {
                    GAStore.storage.deleteSessionCache();
                }
            };
            GAStore.put = function (key, value) {
                try {
                    GAStore.storage.setItem(key, value);
                }
                catch (e) {
                    GALogger.w("Store write failed for " + key + ": " + (e && e.name ? e.name : e));
                }
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
            GAStore.delete = function (store, args) {
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
                GAStore.put(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.EventsStoreKey), JSON.stringify(GAStore.instance.eventsStore));
                GAStore.put(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.SessionsStoreKey), JSON.stringify(GAStore.instance.sessionsStore));
                GAStore.put(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ProgressionStoreKey), JSON.stringify(GAStore.instance.progressionStore));
                GAStore.put(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ItemsStoreKey), JSON.stringify(GAStore.instance.storeItems));
            };
            GAStore.load = function (gameKey) {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot load.");
                    return;
                }
                try {
                    GAStore.instance.eventsStore = JSON.parse(GAStore.storage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.EventsStoreKey)));
                    if (!GAStore.instance.eventsStore) {
                        GAStore.instance.eventsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'events' store. Using empty store.");
                    GAStore.instance.eventsStore = [];
                }
                try {
                    GAStore.instance.sessionsStore = JSON.parse(GAStore.storage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.SessionsStoreKey)));
                    if (!GAStore.instance.sessionsStore) {
                        GAStore.instance.sessionsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'sessions' store. Using empty store.");
                    GAStore.instance.sessionsStore = [];
                }
                try {
                    GAStore.instance.progressionStore = JSON.parse(GAStore.storage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ProgressionStoreKey)));
                    if (!GAStore.instance.progressionStore) {
                        GAStore.instance.progressionStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'progression' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
                try {
                    GAStore.instance.storeItems = JSON.parse(GAStore.storage.getItem(GAStore.StringFormat(GAStore.KeyFormat, gameKey, GAStore.ItemsStoreKey)));
                    if (!GAStore.instance.storeItems) {
                        GAStore.instance.storeItems = {};
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'items' store. Using empty store.");
                    GAStore.instance.storeItems = {};
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
            GAStore.storage = null;
            GAStore.MaxNumberOfEntries = 2000;
            GAStore.MaxDbSizeBytes = 6291456;
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
    var storage;
    (function (storage) {
        var GAStorageBrowser = (function () {
            function GAStorageBrowser() {
                this.available = false;
                try {
                    if (typeof localStorage === 'object') {
                        localStorage.setItem('testingLocalStorage', 'yes');
                        localStorage.removeItem('testingLocalStorage');
                        this.available = true;
                    }
                }
                catch (e) { }
            }
            GAStorageBrowser.prototype.getItem = function (key) { return localStorage.getItem(key); };
            GAStorageBrowser.prototype.setItem = function (key, value) { localStorage.setItem(key, value); };
            GAStorageBrowser.prototype.removeItem = function (key) { localStorage.removeItem(key); };
            GAStorageBrowser.prototype.isAvailable = function () { return this.available; };
            GAStorageBrowser.prototype.getSizeBytes = function () { return -1; };
            GAStorageBrowser.prototype.deleteSessionCache = function () { };
            return GAStorageBrowser;
        }());
        storage.GAStorageBrowser = GAStorageBrowser;
    })(storage = gameanalytics.storage || (gameanalytics.storage = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var storage;
    (function (storage) {
        function makeStorage() {
            return new storage.GAStorageBrowser();
        }
        storage.makeStorage = makeStorage;
    })(storage = gameanalytics.storage || (gameanalytics.storage = {}));
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
                this._enableErrorReporting = false;
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
                GAStore.delete(EGAStore.Progression, parms);
            };
            GAState.setKeys = function (gameKey, gameSecret) {
                GAState.instance.gameKey = gameKey;
                GAState.instance.gameSecret = gameSecret;
            };
            GAState.setManualSessionHandling = function (flag) {
                GAState.instance.useManualSessionHandling = flag;
                GALogger.i("Use manual session handling: " + flag);
            };
            GAState.setEnableErrorReporting = function (flag) {
                GAState.instance._enableErrorReporting = flag;
                GALogger.i("Use error reporting: " + flag);
            };
            GAState.useErrorReporting = function () {
                return GAState.instance._enableErrorReporting;
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
                var client = gameanalytics.http.GAHTTPApi.getClient();
                if (!client) {
                    return;
                }
                client.sendRequest(url, hashHmac, new TextEncoder().encode(payloadData), false).then(function (r) {
                    var text = r.packet && r.packet.length ? new TextDecoder().decode(r.packet) : "";
                    if (!text) {
                        GALogger.d("sdk error failed. Might be no connection. Description: " + (r.statusText || "") + ", Status code: " + r.code);
                        return;
                    }
                    if (r.code != 200) {
                        GALogger.w("sdk error failed. response code not 200. status code: " + r.code + ", description: " + (r.statusText || "") + ", body: " + text);
                        return;
                    }
                    SdkErrorTask.countMap[type] = SdkErrorTask.countMap[type] + 1;
                }).catch(function (e) { GALogger.e("sdk error request failed: " + e); });
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
            GAHTTPApi.setClient = function (c) { GAHTTPApi.client = c; };
            GAHTTPApi.getClient = function () { return GAHTTPApi.client; };
            GAHTTPApi.inFlightCount = function () { return GAHTTPApi.inFlight.length; };
            GAHTTPApi.whenIdle = function () {
                if (GAHTTPApi.inFlight.length === 0) {
                    return Promise.resolve();
                }
                return Promise.all(GAHTTPApi.inFlight.slice()).then(function () { return GAHTTPApi.whenIdle(); });
            };
            GAHTTPApi.track = function (p) {
                GAHTTPApi.inFlight.push(p);
                var done = function () { var i = GAHTTPApi.inFlight.indexOf(p); if (i >= 0) {
                    GAHTTPApi.inFlight.splice(i, 1);
                } };
                p.then(done, done);
            };
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
                if (!GAHTTPApi.client) {
                    GALogger.w("No HTTP client configured");
                    return;
                }
                var key = GAState.getGameSecret();
                var authorization = GAUtilities.getHmac(key, payloadData);
                var args = [];
                args.push(authorization);
                for (var s in extraArgs) {
                    args.push(extraArgs[s]);
                }
                var p = GAHTTPApi.client.sendRequest(url, authorization, new TextEncoder().encode(payloadData), gzip)
                    .then(function (r) {
                    var like = {
                        status: r.code < 0 ? 0 : r.code,
                        statusText: r.statusText || "",
                        responseText: r.packet && r.packet.length ? new TextDecoder().decode(r.packet) : ""
                    };
                    callback(like, url, callback2, args);
                })
                    .catch(function (e) { GALogger.e("HTTP callback failed: " + (e && e.stack ? e.stack : e)); });
                GAHTTPApi.track(p);
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
            GAHTTPApi.client = null;
            GAHTTPApi.inFlight = [];
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
            GAHealth.setPlatform = function (p) {
                GAHealth.platform = p;
                if (p) {
                    GAHealth._cpuModel = p.getCpuModel();
                    GAHealth._numCores = p.getNumCpuCores();
                    GAHealth._hardware = p.getDeviceModel();
                    GAHealth._gpuModel = p.getGpuModel();
                    GAHealth._totalMemory = p.getTotalDeviceMemory();
                }
            };
            GAHealth.reset = function () {
                GAHealth.frameAccum = 0;
                GAHealth.frameCount = 0;
                GAHealth.fpsTimer = 0;
                GAHealth.memTimer = 0;
            };
            GAHealth.sampleMemory = function () {
                if (!GAHealth.platform) {
                    return;
                }
                var total = GAHealth._totalMemory;
                var app = GAHealth.platform.getAppMemoryUsage();
                var sys = GAHealth.platform.getSysMemoryUsage();
                if (total > 0 && sys >= 0) {
                    GAHealth.memSysBuckets[Math.min(100, Math.max(0, Math.round(sys / total * 100)))]++;
                }
                if (total > 0 && app >= 0) {
                    GAHealth.memAppBuckets[Math.min(100, Math.max(0, Math.round(app / total * 100)))]++;
                }
            };
            GAHealth.getGpuModel = function () { return GAHealth._gpuModel; };
            GAHealth.getHardware = function () { return GAHealth._hardware; };
            GAHealth.getDeviceMemoryBytes = function () { return GAHealth._totalMemory; };
            GAHealth.getScreenResolution = function () {
                if (GAHealth._screenResolution !== null) {
                    return GAHealth._screenResolution;
                }
                var w = (typeof screen !== 'undefined') ? screen.width : -1;
                var h = (typeof screen !== 'undefined') ? screen.height : -1;
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
                var appBytes = GAHealth.platform ? GAHealth.platform.getAppMemoryUsage() : -1;
                var memMb = appBytes >= 0 ? Math.round(appBytes / 1048576) : -1;
                return {
                    memory_used_mb: memMb,
                    hardware_concurrency: GAHealth._numCores,
                    screen_width: (typeof screen !== 'undefined') ? screen.width : -1,
                    screen_height: (typeof screen !== 'undefined') ? screen.height : -1,
                    cpu_model: GAHealth._cpuModel || 'unknown',
                    hardware: GAHealth.getHardware(),
                    gpu_model: GAHealth.getGpuModel(),
                    screen_resolution: GAHealth.getScreenResolution()
                };
            };
            GAHealth.addHealthAnnotations = function (out) {
                out['cpu_model'] = GAHealth._cpuModel || 'unknown';
                out['hardware'] = GAHealth.getHardware() || 'unknown';
                var gpuModel = GAHealth.getGpuModel();
                if (gpuModel) {
                    out['gpu_model'] = gpuModel;
                }
                var numCores = GAHealth._numCores;
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
                var bootTime = GAHealth.platform ? GAHealth.platform.getBootTime() : -1;
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
            GAHealth.platform = null;
            GAHealth._cpuModel = "";
            GAHealth._numCores = -1;
            GAHealth._hardware = "";
            GAHealth._gpuModel = "";
            GAHealth._totalMemory = -1;
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
                        if (eventDict && typeof eventDict === "object") {
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
                    GAStore.delete(EGAStore.Events, requestIdWhereArgs);
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
                        GAStore.delete(EGAStore.Events, requestIdWhereArgs);
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
                        GAStore.delete(EGAStore.Sessions, [["session_id", EGAStoreArgsOperator.Equal, ev["session_id"]]]);
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
                else if (value == gameanalytics.EGAAdType.RewardedVideo || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.RewardedVideo]) {
                    return "rewarded_video";
                }
                else if (value == gameanalytics.EGAAdType.Playable || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.Playable]) {
                    return "playable";
                }
                else if (value == gameanalytics.EGAAdType.Interstitial || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.Interstitial]) {
                    return "interstitial";
                }
                else if (value == gameanalytics.EGAAdType.OfferWall || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.OfferWall]) {
                    return "offer_wall";
                }
                else if (value == gameanalytics.EGAAdType.Banner || value == gameanalytics.EGAAdType[gameanalytics.EGAAdType.Banner]) {
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
                GAThreading.pumpId = setInterval(GAThreading.run, 100);
                GAThreading.unref(GAThreading.pumpId);
            }
            GAThreading.unref = function (t) { if (t && typeof t.unref === 'function') {
                t.unref();
            } };
            GAThreading.flush = function () { GAThreading.run(); };
            GAThreading.pendingTaskCount = function () { return GAThreading.instance.taskQueue.length; };
            GAThreading.stopPump = function () { clearInterval(GAThreading.pumpId); };
            GAThreading.performTaskOnGAThread = function (taskBlock) {
                GAThreading.instance.taskQueue.push(taskBlock);
            };
            GAThreading.ensureEventQueueIsRunning = function () {
                if (!GAThreading.instance.isRunning) {
                    GAThreading.instance.isRunning = true;
                    GAThreading.eventIntervalId = setInterval(function () { return GAThreading.performTaskOnGAThread(GAThreading.processEventQueue); }, GAThreading.ProcessEventsIntervalInSeconds * 1000);
                    GAThreading.unref(GAThreading.eventIntervalId);
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
    var GAHealth = gameanalytics.health.GAHealth;
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
            var platform = gameanalytics.platform.makePlatform();
            GADevice.setPlatform(platform);
            GAHealth.setPlatform(platform);
            GAStore.setStorage(gameanalytics.storage.makeStorage());
            GAHTTPApi.setClient(gameanalytics.http.makeHttpClient());
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
            GameAnalytics.methodMap['setEnabledErrorReporting'] = GameAnalytics.setEnabledErrorReporting;
            GameAnalytics.methodMap['onQuit'] = GameAnalytics.onQuit;
            if (typeof GameAnalytics.getGlobalObject() !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics'] !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics']['q'] !== 'undefined') {
                var q = GameAnalytics.getGlobalObject()['GameAnalytics']['q'];
                for (var i in q) {
                    GameAnalytics.gaCommand.apply(null, q[i]);
                }
            }
            platform.onInit();
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
        GameAnalytics.setEnabledErrorReporting = function (flag) {
            if (flag === void 0) { flag = false; }
            GAState.setEnableErrorReporting(flag);
        };
        GameAnalytics.onQuit = function () {
            if (GameAnalytics.quitPromise) {
                return GameAnalytics.quitPromise;
            }
            return GameAnalytics.quitPromise = GameAnalytics.settle(10)
                .then(function () {
                GAThreading.performTaskOnGAThread(function () { GAEvents.processEvents("", true); });
                GAThreading.performTaskOnGAThread(function () { GAThreading.endSessionAndStopQueue(); });
                return GameAnalytics.settle(10);
            })
                .then(function () {
                var left = GAStore.select(gameanalytics.store.EGAStore.Events);
                if (!left || left.length === 0) {
                    GAStore.deleteSessionCache();
                }
                else {
                    GALogger.w("onQuit: " + left.length + " event(s) could not be delivered; session cache kept for the next run");
                }
                GAThreading.stopPump();
            });
        };
        GameAnalytics.settle = function (maxRounds) {
            GAThreading.flush();
            if (maxRounds <= 0 || (GAHTTPApi.inFlightCount() === 0 && GAThreading.pendingTaskCount() === 0)) {
                return Promise.resolve();
            }
            return GAHTTPApi.whenIdle().then(function () { return GameAnalytics.settle(maxRounds - 1); });
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
        GameAnalytics.quitPromise = null;
        return GameAnalytics;
    }());
    gameanalytics.GameAnalytics = GameAnalytics;
})(gameanalytics || (gameanalytics = {}));
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9QdWJsaWNFbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy9odHRwL0dBSHR0cENsaWVudEJyb3dzZXIudHMiLCJzcmMvaHR0cC9tYWtlSHR0cENsaWVudC5icm93c2VyLnRzIiwic3JjL3ZhbGlkYXRvcnMvR0FWYWxpZGF0b3IudHMiLCJzcmMvcGxhdGZvcm0vR0FQbGF0Zm9ybS50cyIsInNyYy9kZXZpY2UvR0FEZXZpY2UudHMiLCJzcmMvcGxhdGZvcm0vR0FQbGF0Zm9ybUJyb3dzZXIudHMiLCJzcmMvcGxhdGZvcm0vbWFrZVBsYXRmb3JtLmJyb3dzZXIudHMiLCJzcmMvc3RvcmUvR0FTdG9yZS50cyIsInNyYy9zdG9yYWdlL0dBU3RvcmFnZUJyb3dzZXIudHMiLCJzcmMvc3RvcmFnZS9tYWtlU3RvcmFnZS5icm93c2VyLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2hlYWx0aC9HQUhlYWx0aC50cyIsInNyYy9ldmVudHMvR0FFdmVudHMudHMiLCJzcmMvdGhyZWFkaW5nL0dBVGhyZWFkaW5nLnRzIiwic3JjL0dhbWVBbmFseXRpY3MudHMiLCJzcmMvc3RvcmFnZS9JR0FTdG9yYWdlLnRzIiwic3JjL2h0dHAvSUdBSHR0cENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7QUFBQSxJQUFPLGFBQWEsQ0F1Sm5CO0FBdkpELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQU9YO0lBUEQsV0FBWSxnQkFBZ0I7UUFDeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFQ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bWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgZW51bSBFR0FFcnJvclNldmVyaXR5IHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgRGVidWcgPSAxLFxuICAgICAgICBJbmZvID0gMixcbiAgICAgICAgV2FybmluZyA9IDMsXG4gICAgICAgIEVycm9yID0gNCxcbiAgICAgICAgQ3JpdGljYWwgPSA1XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTdGFydCA9IDEsXG4gICAgICAgIENvbXBsZXRlID0gMixcbiAgICAgICAgRmFpbCA9IDNcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgU291cmNlID0gMSxcbiAgICAgICAgU2luayA9IDJcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZEFjdGlvbiB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIENsaWNrZWQgPSAxLFxuICAgICAgICBTaG93ID0gMixcbiAgICAgICAgRmFpbGVkU2hvdyA9IDMsXG4gICAgICAgIFJld2FyZFJlY2VpdmVkID0gNFxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkRXJyb3Ige1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBVbmtub3duID0gMSxcbiAgICAgICAgT2ZmbGluZSA9IDIsXG4gICAgICAgIE5vRmlsbCA9IDMsXG4gICAgICAgIEludGVybmFsRXJyb3IgPSA0LFxuICAgICAgICBJbnZhbGlkUmVxdWVzdCA9IDUsXG4gICAgICAgIFVuYWJsZVRvUHJlY2FjaGUgPSA2XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRUeXBlIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgVmlkZW8gPSAxLFxuICAgICAgICBSZXdhcmRlZFZpZGVvID0gMixcbiAgICAgICAgUGxheWFibGUgPSAzLFxuICAgICAgICBJbnRlcnN0aXRpYWwgPSA0LFxuICAgICAgICBPZmZlcldhbGwgPSA1LFxuICAgICAgICBCYW5uZXIgPSA2XG4gICAgfVxuXG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXG4gICAge1xuICAgICAgICBleHBvcnQgZW51bSBFR0FIVFRQQXBpUmVzcG9uc2VcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gY2xpZW50XG4gICAgICAgICAgICBOb1Jlc3BvbnNlLFxuICAgICAgICAgICAgQmFkUmVzcG9uc2UsXG4gICAgICAgICAgICBSZXF1ZXN0VGltZW91dCwgLy8gNDA4XG4gICAgICAgICAgICBKc29uRW5jb2RlRmFpbGVkLFxuICAgICAgICAgICAgSnNvbkRlY29kZUZhaWxlZCxcbiAgICAgICAgICAgIC8vIHNlcnZlclxuICAgICAgICAgICAgSW50ZXJuYWxTZXJ2ZXJFcnJvcixcbiAgICAgICAgICAgIEJhZFJlcXVlc3QsIC8vIDQwMFxuICAgICAgICAgICAgVW5hdXRob3JpemVkLCAvLyA0MDFcbiAgICAgICAgICAgIFVua25vd25SZXNwb25zZUNvZGUsXG4gICAgICAgICAgICBPayxcbiAgICAgICAgICAgIENyZWF0ZWRcbiAgICAgICAgfVxuICAgIH1cblxuICAgIGV4cG9ydCBtb2R1bGUgZXZlbnRzXG4gICAge1xuICAgICAgICBleHBvcnQgZW51bSBFR0FTZGtFcnJvckNhdGVnb3J5XG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBFdmVudFZhbGlkYXRpb24gPSAxLFxuICAgICAgICAgICAgRGF0YWJhc2UgPSAyLFxuICAgICAgICAgICAgSW5pdCA9IDMsXG4gICAgICAgICAgICBIdHRwID0gNCxcbiAgICAgICAgICAgIEpzb24gPSA1XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTZGtFcnJvckFyZWFcbiAgICAgICAge1xuICAgICAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgICAgIEJ1c2luZXNzRXZlbnQgPSAxLFxuICAgICAgICAgICAgUmVzb3VyY2VFdmVudCA9IDIsXG4gICAgICAgICAgICBQcm9ncmVzc2lvbkV2ZW50ID0gMyxcbiAgICAgICAgICAgIERlc2lnbkV2ZW50ID0gNCxcbiAgICAgICAgICAgIEVycm9yRXZlbnQgPSA1LFxuICAgICAgICAgICAgSW5pdEh0dHAgPSA5LFxuICAgICAgICAgICAgRXZlbnRzSHR0cCA9IDEwLFxuICAgICAgICAgICAgUHJvY2Vzc0V2ZW50cyA9IDExLFxuICAgICAgICAgICAgQWRkRXZlbnRzVG9TdG9yZSA9IDEyLFxuICAgICAgICAgICAgQWRFdmVudCA9IDIwXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTZGtFcnJvckFjdGlvblxuICAgICAgICB7XG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICAgICAgSW52YWxpZEN1cnJlbmN5ID0gMSxcbiAgICAgICAgICAgIEludmFsaWRTaG9ydFN0cmluZyA9IDIsXG4gICAgICAgICAgICBJbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoID0gMyxcbiAgICAgICAgICAgIEludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzID0gNCxcbiAgICAgICAgICAgIEludmFsaWRTdG9yZSA9IDUsXG4gICAgICAgICAgICBJbnZhbGlkRmxvd1R5cGUgPSA2LFxuICAgICAgICAgICAgU3RyaW5nRW1wdHlPck51bGwgPSA3LFxuICAgICAgICAgICAgTm90Rm91bmRJbkF2YWlsYWJsZUN1cnJlbmNpZXMgPSA4LFxuICAgICAgICAgICAgSW52YWxpZEFtb3VudCA9IDksXG4gICAgICAgICAgICBOb3RGb3VuZEluQXZhaWxhYmxlSXRlbVR5cGVzID0gMTAsXG4gICAgICAgICAgICBXcm9uZ1Byb2dyZXNzaW9uT3JkZXIgPSAxMSxcbiAgICAgICAgICAgIEludmFsaWRFdmVudElkTGVuZ3RoID0gMTIsXG4gICAgICAgICAgICBJbnZhbGlkRXZlbnRJZENoYXJhY3RlcnMgPSAxMyxcbiAgICAgICAgICAgIEludmFsaWRQcm9ncmVzc2lvblN0YXR1cyA9IDE1LFxuICAgICAgICAgICAgSW52YWxpZFNldmVyaXR5ID0gMTYsXG4gICAgICAgICAgICBJbnZhbGlkTG9uZ1N0cmluZyA9IDE3LFxuICAgICAgICAgICAgRGF0YWJhc2VUb29MYXJnZSA9IDE4LFxuICAgICAgICAgICAgRGF0YWJhc2VPcGVuT3JDcmVhdGUgPSAxOSxcbiAgICAgICAgICAgIEpzb25FcnJvciA9IDI1LFxuICAgICAgICAgICAgRmFpbEh0dHBKc29uRGVjb2RlID0gMjksXG4gICAgICAgICAgICBGYWlsSHR0cEpzb25FbmNvZGUgPSAzMCxcbiAgICAgICAgICAgIEludmFsaWRBZEFjdGlvbiA9IDMxLFxuICAgICAgICAgICAgSW52YWxpZEFkVHlwZSA9IDMyLFxuICAgICAgICAgICAgSW52YWxpZFN0cmluZyA9IDMzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTZGtFcnJvclBhcmFtZXRlclxuICAgICAgICB7XG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICAgICAgQ3VycmVuY3kgPSAxLFxuICAgICAgICAgICAgQ2FydFR5cGUgPSAyLFxuICAgICAgICAgICAgSXRlbVR5cGUgPSAzLFxuICAgICAgICAgICAgSXRlbUlkID0gNCxcbiAgICAgICAgICAgIFN0b3JlID0gNSxcbiAgICAgICAgICAgIEZsb3dUeXBlID0gNixcbiAgICAgICAgICAgIEFtb3VudCA9IDcsXG4gICAgICAgICAgICBQcm9ncmVzc2lvbjAxID0gOCxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uMDIgPSA5LFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24wMyA9IDEwLFxuICAgICAgICAgICAgRXZlbnRJZCA9IDExLFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb25TdGF0dXMgPSAxMixcbiAgICAgICAgICAgIFNldmVyaXR5ID0gMTMsXG4gICAgICAgICAgICBNZXNzYWdlID0gMTQsXG4gICAgICAgICAgICBBZEFjdGlvbiA9IDE1LFxuICAgICAgICAgICAgQWRUeXBlID0gMTYsXG4gICAgICAgICAgICBBZFNka05hbWUgPSAxNyxcbiAgICAgICAgICAgIEFkUGxhY2VtZW50ID0gMThcbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBwdWJsaWNfZW51bXNcbntcbiAgICBleHBvcnQgZW51bSBFR0FFcnJvclNldmVyaXR5XG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBEZWJ1ZyA9IDEsXG4gICAgICAgIEluZm8gPSAyLFxuICAgICAgICBXYXJuaW5nID0gMyxcbiAgICAgICAgRXJyb3IgPSA0LFxuICAgICAgICBDcml0aWNhbCA9IDVcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FQcm9ncmVzc2lvblN0YXR1c1xuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgU3RhcnQgPSAxLFxuICAgICAgICBDb21wbGV0ZSA9IDIsXG4gICAgICAgIEZhaWwgPSAzXG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBUmVzb3VyY2VGbG93VHlwZVxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgU291cmNlID0gMSxcbiAgICAgICAgU2luayA9IDJcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZEFjdGlvblxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgQ2xpY2tlZCA9IDEsXG4gICAgICAgIFNob3cgPSAyLFxuICAgICAgICBGYWlsZWRTaG93ID0gMyxcbiAgICAgICAgUmV3YXJkUmVjZWl2ZWQgPSA0XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRFcnJvclxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgVW5rbm93biA9IDEsXG4gICAgICAgIE9mZmxpbmUgPSAyLFxuICAgICAgICBOb0ZpbGwgPSAzLFxuICAgICAgICBJbnRlcm5hbEVycm9yID0gNCxcbiAgICAgICAgSW52YWxpZFJlcXVlc3QgPSA1LFxuICAgICAgICBVbmFibGVUb1ByZWNhY2hlID0gNlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkVHlwZVxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgVmlkZW8gPSAxLFxuICAgICAgICBSZXdhcmRlZFZpZGVvID0gMixcbiAgICAgICAgUGxheWFibGUgPSAzLFxuICAgICAgICBJbnRlcnN0aXRpYWwgPSA0LFxuICAgICAgICBPZmZlcldhbGwgPSA1LFxuICAgICAgICBCYW5uZXIgPSA2XG4gICAgfVxufVxuIiwiLy9HQUxPR0dFUl9TVEFSVFxubW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGxvZ2dpbmdcbiAgICB7XG4gICAgICAgIGVudW0gRUdBTG9nZ2VyTWVzc2FnZVR5cGVcbiAgICAgICAge1xuICAgICAgICAgICAgRXJyb3IgPSAwLFxuICAgICAgICAgICAgV2FybmluZyA9IDEsXG4gICAgICAgICAgICBJbmZvID0gMixcbiAgICAgICAgICAgIERlYnVnID0gM1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBTG9nZ2VyXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIEZpZWxkcyBhbmQgcHJvcGVydGllczogU1RBUlRcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FMb2dnZXIgPSBuZXcgR0FMb2dnZXIoKTtcbiAgICAgICAgICAgIHByaXZhdGUgaW5mb0xvZ0VuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgaW5mb0xvZ1ZlcmJvc2VFbmFibGVkOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBkZWJ1Z0VuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFRhZzpzdHJpbmcgPSBcIkdhbWVBbmFseXRpY3NcIjtcblxuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBFTkRcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZGVidWdFbmFibGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTWV0aG9kczogU1RBUlRcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbmZvTG9nKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ0VuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRWZXJib3NlTG9nKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ1ZlcmJvc2VFbmFibGVkID0gdmFsdWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkluZm8vXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdyhmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiV2FybmluZy9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJFcnJvci9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaWkoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ1ZlcmJvc2VFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiVmVyYm9zZS9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmRlYnVnRW5hYmxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkRlYnVnL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlOnN0cmluZywgdHlwZTpFR0FMb2dnZXJNZXNzYWdlVHlwZSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2godHlwZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRXJyb3I6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4obWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5EZWJ1ZzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYodHlwZW9mIGNvbnNvbGUuZGVidWcgPT09IFwiZnVuY3Rpb25cIilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBFTkRcbiAgICAgICAgfVxuICAgIH1cbn1cbi8vR0FMT0dHRVJfRU5EXG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdXRpbGl0aWVzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVXRpbGl0aWVzXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SG1hYyhrZXk6c3RyaW5nLCBkYXRhOnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBlbmNyeXB0ZWRNZXNzYWdlID0gQ3J5cHRvSlMuSG1hY1NIQTI1NihkYXRhLCBrZXkpO1xuICAgICAgICAgICAgICAgIHJldHVybiBDcnlwdG9KUy5lbmMuQmFzZTY0LnN0cmluZ2lmeShlbmNyeXB0ZWRNZXNzYWdlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdHJpbmdNYXRjaChzOnN0cmluZywgcGF0dGVybjpSZWdFeHApOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIXMgfHwgIXBhdHRlcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBhdHRlcm4udGVzdChzKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBqb2luU3RyaW5nQXJyYXkodjpBcnJheTxzdHJpbmc+LCBkZWxpbWl0ZXI6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcIlwiO1xuXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDAsIGlsID0gdi5sZW5ndGg7IGkgPCBpbDsgaSsrKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGkgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQgKz0gZGVsaW1pdGVyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSB2W2ldO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXJyYXk6QXJyYXk8c3RyaW5nPiwgc2VhcmNoOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYXJyYXkubGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBhcnJheSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGFycmF5W3NdID09PSBzZWFyY2gpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkga2V5U3RyOnN0cmluZyA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz1cIjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpbnB1dCA9IGVuY29kZVVSSShpbnB1dCk7XG4gICAgICAgICAgICAgICAgdmFyIG91dHB1dDpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciBjaHIxOm51bWJlciwgY2hyMjpudW1iZXIsIGNocjM6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgZW5jMTpudW1iZXIsIGVuYzI6bnVtYmVyLCBlbmMzOm51bWJlciwgZW5jNDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBpID0gMDtcblxuICAgICAgICAgICAgICAgIGRvXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgIGNocjEgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuXG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGNocjEgPj4gMjtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gKChjaHIxICYgMykgPDwgNCkgfCAoY2hyMiA+PiA0KTtcbiAgICAgICAgICAgICAgICAgICBlbmMzID0gKChjaHIyICYgMTUpIDw8IDIpIHwgKGNocjMgPj4gNik7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IGNocjMgJiA2MztcblxuICAgICAgICAgICAgICAgICAgIGlmIChpc05hTihjaHIyKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jMyA9IGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoaXNOYU4oY2hyMykpXG4gICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMSkgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMikgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMykgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkZWNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVtb3ZlIGFsbCBjaGFyYWN0ZXJzIHRoYXQgYXJlIG5vdCBBLVosIGEteiwgMC05LCArLCAvLCBvciA9XG4gICAgICAgICAgICAgICAgdmFyIGJhc2U2NHRlc3QgPSAvW15BLVphLXowLTlcXCtcXC9cXD1dL2c7XG4gICAgICAgICAgICAgICAgaWYgKGJhc2U2NHRlc3QuZXhlYyhpbnB1dCkpIHtcbiAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVGhlcmUgd2VyZSBpbnZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGluIHRoZSBpbnB1dCB0ZXh0LiBWYWxpZCBiYXNlNjQgY2hhcmFjdGVycyBhcmUgQS1aLCBhLXosIDAtOSwgJysnLCAnLycsYW5kICc9Jy4gRXhwZWN0IGVycm9ycyBpbiBkZWNvZGluZy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlucHV0ID0gaW5wdXQucmVwbGFjZSgvW15BLVphLXowLTlcXCtcXC9cXD1dL2csIFwiXCIpO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSAoZW5jMSA8PCAyKSB8IChlbmMyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGNocjIgPSAoKGVuYzIgJiAxNSkgPDwgNCkgfCAoZW5jMyA+PiAyKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gKChlbmMzICYgMykgPDwgNikgfCBlbmM0O1xuXG4gICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIxKTtcblxuICAgICAgICAgICAgICAgICAgIGlmIChlbmMzICE9IDY0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIyKTtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzQgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjMpO1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSBjaHIyID0gY2hyMyA9IDA7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGVuYzIgPSBlbmMzID0gZW5jNCA9IDA7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGRlY29kZVVSSShvdXRwdXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZGF0ZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gTWF0aC5yb3VuZChkYXRlLmdldFRpbWUoKSAvIDEwMDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZUd1aWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIChcIjEwMDAwMDAwLTEwMDAtNDAwMC04MDAwLTEwMDAwMDAwMDAwMFwiKS5yZXBsYWNlKC9bMDE4XS9nLCBjID0+ICgrYyBeIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMSkpWzBdICYgMTUgPj4gK2MgLyA0KS50b1N0cmluZygxNikpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIdHRwQ2xpZW50QnJvd3NlciBpbXBsZW1lbnRzIElHQUh0dHBDbGllbnRcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIGluaXRpYWxpemUoKTogdm9pZCB7fVxuICAgICAgICAgICAgcHVibGljIGNsZWFudXAoKTogdm9pZCB7fVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZFJlcXVlc3QodXJsOnN0cmluZywgYXV0aDpzdHJpbmcsIHBheWxvYWQ6VWludDhBcnJheSwgdXNlR3ppcDpib29sZWFuKTogUHJvbWlzZTxHQUh0dHBSZXNwb25zZT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFByb21pc2U8R0FIdHRwUmVzcG9uc2U+KChyZXNvbHZlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh1c2VHemlwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiZ3ppcCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoZSBicm93c2VyIEhUVFAgY2xpZW50XCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh7Y29kZTogLTEsIHBhY2tldDogbmV3IFVpbnQ4QXJyYXkoMCksIHN0YXR1c1RleHQ6IFwiZ3ppcCB1bnN1cHBvcnRlZFwifSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0ZXh0OnN0cmluZyA9IHJlcXVlc3QucmVzcG9uc2VUZXh0IHx8IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh7Y29kZTogcmVxdWVzdC5zdGF0dXMgfHwgLTEsIHBhY2tldDogbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpLCBzdGF0dXNUZXh0OiByZXF1ZXN0LnN0YXR1c1RleHQgfHwgXCJcIn0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtVHlwZVwiLCBcImFwcGxpY2F0aW9uL2pzb25cIik7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkF1dGhvcml6YXRpb25cIiwgYXV0aCk7XG4gICAgICAgICAgICAgICAgICAgIHRyeSB7IHJlcXVlc3Quc2VuZChwYXlsb2FkKTsgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSkgeyBHQUxvZ2dlci5lKGUgJiYgZS5zdGFjayA/IGUuc3RhY2sgOiBTdHJpbmcoZSkpOyByZXNvbHZlKHtjb2RlOiAtMSwgcGFja2V0OiBuZXcgVWludDhBcnJheSgwKSwgc3RhdHVzVGV4dDogXCJzZW5kIGZhaWxlZFwifSk7IH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXG4gICAge1xuICAgICAgICBleHBvcnQgZnVuY3Rpb24gbWFrZUh0dHBDbGllbnQoKTogSUdBSHR0cENsaWVudFxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IEdBSHR0cENsaWVudEJyb3dzZXIoKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB2YWxpZGF0b3JzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JDYXRlZ29yeSA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQ2F0ZWdvcnk7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFyZWEgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFyZWE7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFjdGlvbiA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQWN0aW9uO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JQYXJhbWV0ZXIgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvclBhcmFtZXRlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgY2F0ZWdvcnk6RUdBU2RrRXJyb3JDYXRlZ29yeTtcbiAgICAgICAgICAgIHB1YmxpYyBhcmVhOkVHQVNka0Vycm9yQXJlYTtcbiAgICAgICAgICAgIHB1YmxpYyBhY3Rpb246RUdBU2RrRXJyb3JBY3Rpb247XG4gICAgICAgICAgICBwdWJsaWMgcGFyYW1ldGVyOkVHQVNka0Vycm9yUGFyYW1ldGVyO1xuICAgICAgICAgICAgcHVibGljIHJlYXNvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihjYXRlZ29yeTpFR0FTZGtFcnJvckNhdGVnb3J5LCBhcmVhOkVHQVNka0Vycm9yQXJlYSwgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uLCBwYXJhbWV0ZXI6RUdBU2RrRXJyb3JQYXJhbWV0ZXIsIHJlYXNvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5jYXRlZ29yeSA9IGNhdGVnb3J5O1xuICAgICAgICAgICAgICAgIHRoaXMuYXJlYSA9IGFyZWE7XG4gICAgICAgICAgICAgICAgdGhpcy5hY3Rpb24gPSBhY3Rpb247XG4gICAgICAgICAgICAgICAgdGhpcy5wYXJhbWV0ZXIgPSBwYXJhbWV0ZXI7XG4gICAgICAgICAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FWYWxpZGF0b3JcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBjYXJ0VHlwZTpzdHJpbmcsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZyk6IFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW5jeVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBjdXJyZW5jeTogQ2Fubm90IGJlIChudWxsKSBhbmQgbmVlZCB0byBiZSBBLVosIDMgY2hhcmFjdGVycyBhbmQgaW4gdGhlIHN0YW5kYXJkIGF0IG9wZW5leGNoYW5nZXJhdGVzLm9yZy4gRmFpbGVkIGN1cnJlbmN5OiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEN1cnJlbmN5LCBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeSwgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChhbW91bnQgPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gYW1vdW50LiBDYW5ub3QgYmUgbGVzcyB0aGFuIDAuIEZhaWxlZCBhbW91bnQ6IFwiICsgYW1vdW50KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEFtb3VudCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQW1vdW50LCBhbW91bnQgKyBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjYXJ0VHlwZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhjYXJ0VHlwZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBjYXJ0VHlwZS4gQ2Fubm90IGJlIGFib3ZlIDMyIGxlbmd0aC4gU3RyaW5nOiBcIiArIGNhcnRUeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZFNob3J0U3RyaW5nLCBFR0FTZGtFcnJvclBhcmFtZXRlci5DYXJ0VHlwZSwgY2FydFR5cGUpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGxlbmd0aFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5CdXNpbmVzc0V2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGNoYXJzXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5CdXNpbmVzc0V2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbVR5cGUsIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtSWRcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1JZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkLiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbUlkLCBpdGVtSWQpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1JZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtSWQ6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZCwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGF2YWlsYWJsZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiwgYXZhaWxhYmxlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsb3dUeXBlID09IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gZmxvd1R5cGU6IEludmFsaWQgZmxvdyB0eXBlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEZsb3dUeXBlLCBFR0FTZGtFcnJvclBhcmFtZXRlci5GbG93VHlwZSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghY3VycmVuY3kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBjdXJyZW5jeTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uU3RyaW5nRW1wdHlPck51bGwsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkN1cnJlbmN5LCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUN1cnJlbmNpZXMsIGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGN1cnJlbmN5OiBOb3QgZm91bmQgaW4gbGlzdCBvZiBwcmUtZGVmaW5lZCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcy4gU3RyaW5nOiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uTm90Rm91bmRJbkF2YWlsYWJsZUN1cnJlbmNpZXMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkN1cnJlbmN5LCBjdXJyZW5jeSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghKGFtb3VudCA+IDApKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gYW1vdW50OiBGbG9hdCBhbW91bnQgY2Fubm90IGJlIDAgb3IgbmVnYXRpdmUuIFZhbHVlOiBcIiArIGFtb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFtb3VudCwgYW1vdW50ICsgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghaXRlbVR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uU3RyaW5nRW1wdHlPck51bGwsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1UeXBlLCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtVHlwZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1UeXBlLCBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1UeXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1UeXBlLCBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVJdGVtVHlwZXMsIGl0ZW1UeXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBOb3QgZm91bmQgaW4gbGlzdCBvZiBwcmUtZGVmaW5lZCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbVR5cGVzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5Ob3RGb3VuZEluQXZhaWxhYmxlSXRlbVR5cGVzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1JZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbUlkLCBpdGVtSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtSWQsIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZyk6IFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiBJbnZhbGlkIHByb2dyZXNzaW9uIHN0YXR1cy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRQcm9ncmVzc2lvblN0YXR1cywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb25TdGF0dXMsIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIE1ha2Ugc3VyZSBwcm9ncmVzc2lvbnMgYXJlIGRlZmluZWQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1xuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvbjAzICYmICEocHJvZ3Jlc3Npb24wMiB8fCAhcHJvZ3Jlc3Npb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAzIGZvdW5kIGJ1dCAwMSswMiBhcmUgaW52YWxpZC4gUHJvZ3Jlc3Npb24gbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswMy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLldyb25nUHJvZ3Jlc3Npb25PcmRlciwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAocHJvZ3Jlc3Npb24wMiAmJiAhcHJvZ3Jlc3Npb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogMDIgZm91bmQgYnV0IG5vdCAwMS4gUHJvZ3Jlc3Npb24gbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uV3JvbmdQcm9ncmVzc2lvbk9yZGVyLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIHByb2dyZXNzaW9uMDEgKyBcIjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIjpcIiArIHByb2dyZXNzaW9uMDMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghcHJvZ3Jlc3Npb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogcHJvZ3Jlc3Npb24wMSBub3QgdmFsaWQuIFByb2dyZXNzaW9ucyBtdXN0IGJlIHNldCBhcyBlaXRoZXIgMDEsIDAxKzAyIG9yIDAxKzAyKzAzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXIsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgKHByb2dyZXNzaW9uMDEgPyBwcm9ncmVzc2lvbjAxIDogXCJcIikgKyBcIjpcIiArIChwcm9ncmVzc2lvbjAyID8gcHJvZ3Jlc3Npb24wMiA6IFwiXCIpICsgXCI6XCIgKyAocHJvZ3Jlc3Npb24wMyA/IHByb2dyZXNzaW9uMDMgOiBcIlwiKSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJvZ3Jlc3Npb24wMSAocmVxdWlyZWQpXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChwcm9ncmVzc2lvbjAxLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDEsIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAxKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDE6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gcHJvZ3Jlc3Npb24wMlxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChwcm9ncmVzc2lvbjAyLCB0cnVlKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMjogQ2Fubm90IGJlIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDIsIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDIpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDIsIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMywgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAzLCBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAzKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMzogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAzLCBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURlc2lnbkV2ZW50KGV2ZW50SWQ6c3RyaW5nKTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGRlc2lnbiBldmVudCAtIGV2ZW50SWQ6IENhbm5vdCBiZSAobnVsbCkgb3IgZW1wdHkuIE9ubHkgNSBldmVudCBwYXJ0cyBhbGxvd2VkIHNlcGVyYXRlZCBieSA6LiBFYWNoIHBhcnQgbmVlZCB0byBiZSA2NCBjaGFyYWN0ZXJzIG9yIGxlc3MuIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuRGVzaWduRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkTGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5FdmVudElkLCBldmVudElkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50SWRDaGFyYWN0ZXJzKGV2ZW50SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGRlc2lnbiBldmVudCAtIGV2ZW50SWQ6IE5vbiB2YWxpZCBjaGFyYWN0ZXJzLiBPbmx5IGFsbG93ZWQgQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGV2ZW50SWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5EZXNpZ25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50SWRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5FdmVudElkLCBldmVudElkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsdWU6IGFsbG93IDAsIG5lZ2F0aXZlIGFuZCBuaWwgKG5vdCByZXF1aXJlZClcbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHNldmVyaXR5ID09IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGVycm9yIGV2ZW50IC0gc2V2ZXJpdHk6IFNldmVyaXR5IHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkVycm9yRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTZXZlcml0eSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuU2V2ZXJpdHksIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlTG9uZ1N0cmluZyhtZXNzYWdlLCB0cnVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIG1lc3NhZ2U6IE1lc3NhZ2UgY2Fubm90IGJlIGFib3ZlIDgxOTIgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkVycm9yRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRMb25nU3RyaW5nLCBFR0FTZGtFcnJvclBhcmFtZXRlci5NZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBZEV2ZW50KGFkQWN0aW9uOkVHQUFkQWN0aW9uLCBhZFR5cGU6RUdBQWRUeXBlLCBhZFNka05hbWU6c3RyaW5nLCBhZFBsYWNlbWVudDpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGFkQWN0aW9uID09IEVHQUFkQWN0aW9uLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIHNldmVyaXR5OiBTZXZlcml0eSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5BZEV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkQWRBY3Rpb24sIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFkQWN0aW9uLCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKGFkVHlwZSA9PSBFR0FBZFR5cGUuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGFkIGV2ZW50IC0gYWRUeXBlOiBBZCB0eXBlIHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkFkRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBZFR5cGUsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFkVHlwZSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhhZFNka05hbWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBhZCBldmVudCAtIG1lc3NhZ2U6IEFkIFNESyBuYW1lIGNhbm5vdCBiZSBhYm92ZSAzMiBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQWRFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZFNob3J0U3RyaW5nLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZFNka05hbWUsIGFkU2RrTmFtZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcoYWRQbGFjZW1lbnQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBhZCBldmVudCAtIG1lc3NhZ2U6IEFkIHBsYWNlbWVudCBjYW5ub3QgYmUgYWJvdmUgNjQgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkFkRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTdHJpbmcsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFkUGxhY2VtZW50LCBhZFBsYWNlbWVudCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcsIGNhdGVnb3J5OkVHQVNka0Vycm9yQ2F0ZWdvcnksIGFyZWE6RUdBU2RrRXJyb3JBcmVhLCBhY3Rpb246RUdBU2RrRXJyb3JBY3Rpb24pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlS2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoY2F0ZWdvcnkgPT09IEVHQVNka0Vycm9yQ2F0ZWdvcnkuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHNkayBlcnJvciBldmVudCAtIHR5cGU6IENhdGVnb3J5IHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKGFyZWEgPT09IEVHQVNka0Vycm9yQXJlYS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogQXJlYSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChhY3Rpb24gPT09IEVHQVNka0Vycm9yQWN0aW9uLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBzZGsgZXJyb3IgZXZlbnQgLSB0eXBlOiBBY3Rpb24gd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUtleXMoZ2FtZUtleTpzdHJpbmcsIGdhbWVTZWNyZXQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChnYW1lS2V5LCAvXltBLXowLTldezMyfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChnYW1lU2VjcmV0LCAvXltBLXowLTldezQwfSQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ3VycmVuY3koY3VycmVuY3k6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghY3VycmVuY3kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goY3VycmVuY3ksIC9eW0EtWl17M30kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGV2ZW50UGFydDpzdHJpbmcsIGFsbG93TnVsbDpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhbGxvd051bGwgJiYgIWV2ZW50UGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghZXZlbnRQYXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChldmVudFBhcnQubGVuZ3RoID4gNjQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhldmVudFBhcnQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRQYXJ0LCAvXltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnRJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50SWQsIC9eW146XXsxLDY0fSg/OjpbXjpdezEsNjR9KXswLDR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRDaGFyYWN0ZXJzKGV2ZW50SWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnRJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50SWQsIC9eW0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9KDpbQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0pezAsNH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kQ2xlYW5Jbml0UmVxdWVzdFJlc3BvbnNlKGluaXRSZXNwb25zZTp7W2tleTpzdHJpbmddOiBhbnl9LCBjb25maWdzQ3JlYXRlZDpib29sZWFuKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIG1ha2Ugc3VyZSB3ZSBoYXZlIGEgdmFsaWQgZGljdFxuICAgICAgICAgICAgICAgIGlmIChpbml0UmVzcG9uc2UgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gbm8gcmVzcG9uc2UgZGljdGlvbmFyeS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0ZWREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHNlcnZlcl90c1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlcnZlclRzTnVtYmVyOm51bWJlciA9IGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlclRzTnVtYmVyID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcInNlcnZlcl90c1wiXSA9IHNlcnZlclRzTnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHZhbHVlIGluICdzZXJ2ZXJfdHMnIGZpZWxkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ3NlcnZlcl90cycgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3NDcmVhdGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY29uZmlncyBmaWVsZFxuICAgICAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvbmZpZ3VyYXRpb25zOmFueVtdID0gaW5pdFJlc3BvbnNlW1wiY29uZmlnc1wiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJjb25maWdzXCJdID0gY29uZmlndXJhdGlvbnM7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdjb25maWdzJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJjb25maWdzXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiY29uZmlnc1wiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvbmZpZ3NfaGFzaDpzdHJpbmcgPSBpbml0UmVzcG9uc2VbXCJjb25maWdzX2hhc2hcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiY29uZmlnc19oYXNoXCJdID0gY29uZmlnc19oYXNoO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnY29uZmlnc19oYXNoJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJjb25maWdzX2hhc2hcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJjb25maWdzX2hhc2hcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgYWJfaWQgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhYl9pZDpzdHJpbmcgPSBpbml0UmVzcG9uc2VbXCJhYl9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJhYl9pZFwiXSA9IGFiX2lkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnYWJfaWQnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImFiX2lkXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiYWJfaWRcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgYWJfdmFyaWFudF9pZCBmaWVsZFxuICAgICAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFiX3ZhcmlhbnRfaWQ6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiYWJfdmFyaWFudF9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJhYl92YXJpYW50X2lkXCJdID0gYWJfdmFyaWFudF9pZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2FiX3ZhcmlhbnRfaWQnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImFiX3ZhcmlhbnRfaWRcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJhYl92YXJpYW50X2lkXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHZhbGlkYXRlZERpY3Q7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCdWlsZChidWlsZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNob3J0U3RyaW5nKGJ1aWxkLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrV3JhcHBlclZlcnNpb24od3JhcHBlclZlcnNpb246c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2god3JhcHBlclZlcnNpb24sIC9eKHVuaXR5fHVucmVhbHxnYW1lbWFrZXJ8Y29jb3MyZHxjb25zdHJ1Y3R8ZGVmb2xkfGdvZG90fGZsdXR0ZXIpIFswLTldezAsNX0oXFwuWzAtOV17MCw1fSl7MCwyfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFbmdpbmVWZXJzaW9uKGVuZ2luZVZlcnNpb246c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZW5naW5lVmVyc2lvbiB8fCAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZW5naW5lVmVyc2lvbiwgL14odW5pdHl8dW5yZWFsfGdhbWVtYWtlcnxjb2NvczJkfGNvbnN0cnVjdHxkZWZvbGR8Z29kb3QpIFswLTldezAsNX0oXFwuWzAtOV17MCw1fSl7MCwyfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVVc2VySWQodUlkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU3RyaW5nKHVJZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHVzZXIgaWQ6IGlkIGNhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2hvcnRTdHJpbmcoc2hvcnRTdHJpbmc6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIXNob3J0U3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFzaG9ydFN0cmluZyB8fCBzaG9ydFN0cmluZy5sZW5ndGggPiAzMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTdHJpbmcoczpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eSBvciBuaWxcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghcyB8fCBzLmxlbmd0aCA+IDY0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUxvbmdTdHJpbmcobG9uZ1N0cmluZzpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eVxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFsb25nU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFsb25nU3RyaW5nIHx8IGxvbmdTdHJpbmcubGVuZ3RoID4gODE5MilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uVHlwZTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGNvbm5lY3Rpb25UeXBlLCAvXih3d2FufHdpZml8bGFufG9mZmxpbmUpJC8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJjdXN0b20gZGltZW5zaW9uc1wiLCBjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDY0LCBmYWxzZSwgXCJyZXNvdXJjZSBjdXJyZW5jaWVzXCIsIHJlc291cmNlQ3VycmVuY2llcykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmcgZm9yIHJlZ2V4XG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXNvdXJjZUN1cnJlbmNpZXMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHJlc291cmNlQ3VycmVuY2llc1tpXSwgL15bQS1aYS16XSskLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJyZXNvdXJjZSBjdXJyZW5jaWVzIHZhbGlkYXRpb24gZmFpbGVkOiBhIHJlc291cmNlIGN1cnJlbmN5IGNhbiBvbmx5IGJlIEEtWiwgYS16LiBTdHJpbmcgd2FzOiBcIiArIHJlc291cmNlQ3VycmVuY2llc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgMzIsIGZhbHNlLCBcInJlc291cmNlIGl0ZW0gdHlwZXNcIiwgcmVzb3VyY2VJdGVtVHlwZXMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggcmVzb3VyY2VJdGVtVHlwZSBmb3IgZXZlbnRwYXJ0IHZhbGlkYXRpb25cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc291cmNlSXRlbVR5cGVzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocmVzb3VyY2VJdGVtVHlwZXNbaV0pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwicmVzb3VyY2UgaXRlbSB0eXBlcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBpdGVtIHR5cGUgY2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZyB3YXM6IFwiICsgcmVzb3VyY2VJdGVtVHlwZXNbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uMDE6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbjAyOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMyhkaW1lbnNpb24wMzpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQXJyYXlPZlN0cmluZ3MobWF4Q291bnQ6bnVtYmVyLCBtYXhTdHJpbmdMZW5ndGg6bnVtYmVyLCBhbGxvd05vVmFsdWVzOmJvb2xlYW4sIGxvZ1RhZzpzdHJpbmcsIGFycmF5T2ZTdHJpbmdzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFycmF5VGFnOnN0cmluZyA9IGxvZ1RhZztcblxuICAgICAgICAgICAgICAgIC8vIHVzZSBhcnJheVRhZyB0byBhbm5vdGF0ZSB3YXJuaW5nIGxvZ1xuICAgICAgICAgICAgICAgIGlmICghYXJyYXlUYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhcnJheVRhZyA9IFwiQXJyYXlcIjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZighYXJyYXlPZlN0cmluZ3MpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBiZSBudWxsLiBcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eVxuICAgICAgICAgICAgICAgIGlmIChhbGxvd05vVmFsdWVzID09IGZhbHNlICYmIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgYmUgZW1wdHkuIFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggY291bnRcbiAgICAgICAgICAgICAgICBpZiAobWF4Q291bnQgPiAwICYmIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCA+IG1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgZXhjZWVkIFwiICsgbWF4Q291bnQgKyBcIiB2YWx1ZXMuIEl0IGhhcyBcIiArIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCArIFwiIHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHN0cmluZ1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYXJyYXlPZlN0cmluZ3MubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc3RyaW5nTGVuZ3RoOm51bWJlciA9ICFhcnJheU9mU3RyaW5nc1tpXSA/IDAgOiBhcnJheU9mU3RyaW5nc1tpXS5sZW5ndGg7XG4gICAgICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGVtcHR5IChub3QgYWxsb3dlZClcbiAgICAgICAgICAgICAgICAgICAgaWYgKHN0cmluZ0xlbmd0aCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBjb250YWluZWQgYW4gZW1wdHkgc3RyaW5nLiBBcnJheT1cIiArIEpTT04uc3RyaW5naWZ5KGFycmF5T2ZTdHJpbmdzKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBleGNlZWRpbmcgbWF4IGxlbmd0aFxuICAgICAgICAgICAgICAgICAgICBpZiAobWF4U3RyaW5nTGVuZ3RoID4gMCAmJiBzdHJpbmdMZW5ndGggPiBtYXhTdHJpbmdMZW5ndGgpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYSBzdHJpbmcgZXhjZWVkZWQgbWF4IGFsbG93ZWQgbGVuZ3RoICh3aGljaCBpczogXCIgKyBtYXhTdHJpbmdMZW5ndGggKyBcIikuIFN0cmluZyB3YXM6IFwiICsgYXJyYXlPZlN0cmluZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ2xpZW50VHMoY2xpZW50VHM6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChjbGllbnRUcyA8ICgwKSB8fCBjbGllbnRUcyA+ICg5OTk5OTk5OTk5OSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHBsYXRmb3JtXG4gICAge1xuICAgICAgICAvLyBQb3J0IG9mIHRoZSBDKysgU0RLJ3MgUGxhdGZvcm0vR0FQbGF0Zm9ybS5oLiBBYnN0cmFjdCBtZW1iZXJzIGFyZSB0aGVcbiAgICAgICAgLy8gQysrIHB1cmUgdmlydHVhbHM7IHRoZSByZXN0IGRlZmF1bHQgdG8gdGhlIHNhbWUgc2VudGluZWxzIEdBUGxhdGZvcm0uY3BwXG4gICAgICAgIC8vIHJldHVybnM6IFwiXCIgZm9yIHN0cmluZ3MsIC0xIGZvciBudW1iZXJzLiAtMSBtZWFucyBcIm5vdCBtZWFzdXJhYmxlIG9uXG4gICAgICAgIC8vIHRoaXMgcGxhdGZvcm1cIiwgd2hpY2ggZG93bnN0cmVhbSBjYW4gdGVsbCBhcGFydCBmcm9tIGEgcmVhbCAwLlxuICAgICAgICBleHBvcnQgYWJzdHJhY3QgY2xhc3MgR0FQbGF0Zm9ybVxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgYWJzdHJhY3QgZ2V0T1NWZXJzaW9uKCk6IHN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBhYnN0cmFjdCBnZXREZXZpY2VNYW51ZmFjdHVyZXIoKTogc3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIGFic3RyYWN0IGdldEJ1aWxkUGxhdGZvcm0oKTogc3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIGFic3RyYWN0IGdldFBlcnNpc3RlbnRQYXRoKCk6IHN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBhYnN0cmFjdCBnZXREZXZpY2VNb2RlbCgpOiBzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgYWJzdHJhY3QgZ2V0Q29ubmVjdGlvblR5cGUoKTogc3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0QWR2ZXJ0aXNpbmdJZCgpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuICAgICAgICAgICAgcHVibGljIGdldERldmljZUlkKCk6IHN0cmluZyB7IHJldHVybiBcIlwiOyB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRDcHVNb2RlbCgpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuICAgICAgICAgICAgcHVibGljIGdldEdwdU1vZGVsKCk6IHN0cmluZyB7IHJldHVybiBcIlwiOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0TnVtQ3B1Q29yZXMoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0VG90YWxEZXZpY2VNZW1vcnkoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0QXBwTWVtb3J5VXNhZ2UoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0U3lzTWVtb3J5VXNhZ2UoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0Qm9vdFRpbWUoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG5cbiAgICAgICAgICAgIC8vIEpTLW9ubHksIGxpa2UgdGhlIGl0ZW1zIHN0b3JlOiBicm93c2VyX3ZlcnNpb24gaXMgb24gdGhlIHdpcmUgYW5kXG4gICAgICAgICAgICAvLyBDKysgaGFzIG5vIGJyb3dzZXIuIERlZmF1bHRlZCBzbyBOb2RlIGluaGVyaXRzIHRoZSBzZW50aW5lbC5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRCcm93c2VyVmVyc2lvbigpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuXG4gICAgICAgICAgICAvLyBDKysgaW5zdGFsbHMgaXRzIHRlcm1pbmF0ZSBoYW5kbGVyIGhlcmUsIGdhdGVkIG9uIHVzZUVycm9yUmVwb3J0aW5nKCkuXG4gICAgICAgICAgICBwdWJsaWMgb25Jbml0KCk6IHZvaWQge31cbiAgICAgICAgICAgIHB1YmxpYyBzZXR1cFVuY2F1Z2h0RXhjZXB0aW9uSGFuZGxlcigpOiB2b2lkIHt9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgZGV2aWNlXG4gICAge1xuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZhbHVlVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmFsdWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZhbHVlOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZhbHVlID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmVyc2lvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihuYW1lOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSB2ZXJzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBRGV2aWNlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IHNka1dyYXBwZXJWZXJzaW9uOnN0cmluZyA9IFwiamF2YXNjcmlwdCA1LjAuMFwiO1xuXG4gICAgICAgICAgICAvLyBPd25lZCBoZXJlLCBtaXJyb3JpbmcgR0FEZXZpY2U6Ol9wbGF0Zm9ybSBpbiB0aGUgQysrIFNESy4gU2V0IGJ5XG4gICAgICAgICAgICAvLyBHYW1lQW5hbHl0aWNzLmluaXQoKSBiZWZvcmUgYW55dGhpbmcgcmVhZHMgZGV2aWNlIGluZm9ybWF0aW9uLCBzb1xuICAgICAgICAgICAgLy8gbm90aGluZyBiZWxvdyB0b3VjaGVzIGEgYnJvd3NlciBnbG9iYWwgYXQgY2xhc3MtZGVmaW5pdGlvbiB0aW1lLlxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcGxhdGZvcm06Z2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtID0gbnVsbDtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdhbWVFbmdpbmVWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNvbm5lY3Rpb25UeXBlOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRQbGF0Zm9ybShwOmdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQURldmljZS5wbGF0Zm9ybSA9IHA7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UGxhdGZvcm0oKTogZ2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnBsYXRmb3JtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBXcmFwcyBnZXRQZXJzaXN0ZW50UGF0aCgpLCBhcyBHQURldmljZTo6Z2V0V3JpdGFibGVQYXRoKCkgZG9lcyBpbiBDKysuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFdyaXRhYmxlUGF0aCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRQZXJzaXN0ZW50UGF0aCgpIDogXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXQgYnVpbGRQbGF0Zm9ybSgpOiBzdHJpbmcgeyByZXR1cm4gR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRCdWlsZFBsYXRmb3JtKCkgOiBcInVua25vd25cIjsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXQgZGV2aWNlTW9kZWwoKTogc3RyaW5nIHsgcmV0dXJuIEdBRGV2aWNlLnBsYXRmb3JtID8gR0FEZXZpY2UucGxhdGZvcm0uZ2V0RGV2aWNlTW9kZWwoKSA6IFwidW5rbm93blwiOyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldCBkZXZpY2VNYW51ZmFjdHVyZXIoKTogc3RyaW5nIHsgcmV0dXJuIEdBRGV2aWNlLnBsYXRmb3JtID8gR0FEZXZpY2UucGxhdGZvcm0uZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCkgOiBcInVua25vd25cIjsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXQgb3NWZXJzaW9uKCk6IHN0cmluZyB7IHJldHVybiBHQURldmljZS5wbGF0Zm9ybSA/IEdBRGV2aWNlLnBsYXRmb3JtLmdldE9TVmVyc2lvbigpIDogXCJ1bmtub3duIDAuMC4wXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0IGJyb3dzZXJWZXJzaW9uKCk6IHN0cmluZyB7IHJldHVybiBHQURldmljZS5wbGF0Zm9ybSA/IEdBRGV2aWNlLnBsYXRmb3JtLmdldEJyb3dzZXJWZXJzaW9uKCkgOiBcIlwiOyB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdG91Y2goKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbGV2YW50U2RrVmVyc2lvbigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka1dyYXBwZXJWZXJzaW9uO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbm5lY3Rpb25UeXBlKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5jb25uZWN0aW9uVHlwZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGVDb25uZWN0aW9uVHlwZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBHQURldmljZS5wbGF0Zm9ybSA/IEdBRGV2aWNlLnBsYXRmb3JtLmdldENvbm5lY3Rpb25UeXBlKCkgOiBcIm9mZmxpbmVcIjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBwbGF0Zm9ybVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgTmFtZVZhbHVlVmVyc2lvbiA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLk5hbWVWYWx1ZVZlcnNpb247XG4gICAgICAgIGltcG9ydCBOYW1lVmVyc2lvbiA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLk5hbWVWZXJzaW9uO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVBsYXRmb3JtQnJvd3NlciBleHRlbmRzIEdBUGxhdGZvcm1cbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBvc1ZlcnNpb25QYWlyOk5hbWVWZXJzaW9uID0gbnVsbDtcblxuICAgICAgICAgICAgcHJpdmF0ZSBnZXRPc1ZlcnNpb25QYWlyKCk6IE5hbWVWZXJzaW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHRoaXMub3NWZXJzaW9uUGFpciA9PT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBhZ2VudDpzdHJpbmcgPSAodHlwZW9mIG5hdmlnYXRvciAhPT0gJ3VuZGVmaW5lZCcpXG4gICAgICAgICAgICAgICAgICAgICAgICA/IFtuYXZpZ2F0b3IucGxhdGZvcm0sIG5hdmlnYXRvci51c2VyQWdlbnQsIG5hdmlnYXRvci5hcHBWZXJzaW9uLCBuYXZpZ2F0b3IudmVuZG9yXS5qb2luKCcgJylcbiAgICAgICAgICAgICAgICAgICAgICAgIDogJyc7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMub3NWZXJzaW9uUGFpciA9IEdBUGxhdGZvcm1Ccm93c2VyLm1hdGNoSXRlbShhZ2VudCwgW1xuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzX3Bob25lXCIsIFwiV2luZG93cyBQaG9uZVwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzXCIsIFwiV2luXCIsIFwiTlRcIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQaG9uZVwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGFkXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQb2RcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYW5kcm9pZFwiLCBcIkFuZHJvaWRcIiwgXCJBbmRyb2lkXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJibGFja0JlcnJ5XCIsIFwiQmxhY2tCZXJyeVwiLCBcIi9cIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIm1hY19vc3hcIiwgXCJNYWNcIiwgXCJPUyBYXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ0aXplblwiLCBcIlRpemVuXCIsIFwiVGl6ZW5cIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImxpbnV4XCIsIFwiTGludXhcIiwgXCJydlwiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwia2FpX29zXCIsIFwiS0FJT1NcIiwgXCJLQUlPU1wiKVxuICAgICAgICAgICAgICAgICAgICBdKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMub3NWZXJzaW9uUGFpcjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGdldE9TVmVyc2lvbigpOiBzdHJpbmcgeyByZXR1cm4gdGhpcy5nZXRCdWlsZFBsYXRmb3JtKCkgKyBcIiBcIiArIHRoaXMuZ2V0T3NWZXJzaW9uUGFpcigpLnZlcnNpb247IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXRCdWlsZFBsYXRmb3JtKCk6IHN0cmluZyB7IHJldHVybiB0aGlzLmdldE9zVmVyc2lvblBhaXIoKS5uYW1lOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6IHN0cmluZyB7IHJldHVybiBcInVua25vd25cIjsgfVxuICAgICAgICAgICAgcHVibGljIGdldERldmljZU1vZGVsKCk6IHN0cmluZyB7IHJldHVybiBcInVua25vd25cIjsgfVxuICAgICAgICAgICAgcHVibGljIGdldFBlcnNpc3RlbnRQYXRoKCk6IHN0cmluZyB7IHJldHVybiBcIlwiOyB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRDb25uZWN0aW9uVHlwZSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIG5hdmlnYXRvciA9PT0gJ3VuZGVmaW5lZCcgfHwgbmF2aWdhdG9yLm9uTGluZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBwOnN0cmluZyA9IHRoaXMuZ2V0QnVpbGRQbGF0Zm9ybSgpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gKHAgPT09IFwiaW9zXCIgfHwgcCA9PT0gXCJhbmRyb2lkXCIpID8gXCJ3d2FuXCIgOiBcImxhblwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJvZmZsaW5lXCI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXROdW1DcHVDb3JlcygpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKHR5cGVvZiBuYXZpZ2F0b3IgIT09ICd1bmRlZmluZWQnICYmIG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5KSA/IG5hdmlnYXRvci5oYXJkd2FyZUNvbmN1cnJlbmN5IDogLTE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRUb3RhbERldmljZU1lbW9yeSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKHR5cGVvZiBuYXZpZ2F0b3IgIT09ICd1bmRlZmluZWQnICYmIChuYXZpZ2F0b3IgYXMgYW55KS5kZXZpY2VNZW1vcnkpID8gKG5hdmlnYXRvciBhcyBhbnkpLmRldmljZU1lbW9yeSAqIDEwNzM3NDE4MjQgOiAtMTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGdldEFwcE1lbW9yeVVzYWdlKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiAodHlwZW9mIHBlcmZvcm1hbmNlICE9PSAndW5kZWZpbmVkJyAmJiAocGVyZm9ybWFuY2UgYXMgYW55KS5tZW1vcnkpID8gKHBlcmZvcm1hbmNlIGFzIGFueSkubWVtb3J5LnVzZWRKU0hlYXBTaXplIDogLTE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRCb290VGltZSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcpID8gTWF0aC5yb3VuZChwZXJmb3JtYW5jZS5ub3coKSkgOiAtMTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGdldEdwdU1vZGVsKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBkb2N1bWVudCAhPT0gJ3VuZGVmaW5lZCcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjYW52YXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdjYW52YXMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBnbDogYW55ID0gY2FudmFzLmdldENvbnRleHQoJ3dlYmdsJykgfHwgY2FudmFzLmdldENvbnRleHQoJ2V4cGVyaW1lbnRhbC13ZWJnbCcpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGdsKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBleHQgPSBnbC5nZXRFeHRlbnNpb24oJ1dFQkdMX2RlYnVnX3JlbmRlcmVyX2luZm8nKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXh0KSB7IHJldHVybiBnbC5nZXRQYXJhbWV0ZXIoZXh0LlVOTUFTS0VEX1JFTkRFUkVSX1dFQkdMKSB8fCAnJzsgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7fVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0QnJvd3NlclZlcnNpb24oKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBuYXZpZ2F0b3IgPT09ICd1bmRlZmluZWQnKSB7IHJldHVybiBcIlwiOyB9XG4gICAgICAgICAgICAgICAgdmFyIHVhOnN0cmluZyA9IG5hdmlnYXRvci51c2VyQWdlbnQ7XG4gICAgICAgICAgICAgICAgdmFyIHRlbTpzdHJpbmdbXSB8IG51bGw7XG4gICAgICAgICAgICAgICAgdmFyIE06c3RyaW5nW10gPSB1YS5tYXRjaCgvKG9wZXJhfGNocm9tZXxzYWZhcml8ZmlyZWZveHx1YnJvd3Nlcnxtc2llfHRyaWRlbnR8ZmJhdig/PVxcLykpXFwvP1xccyooXFxkKykvaSkgfHwgW107XG5cbiAgICAgICAgICAgICAgICBpZihNLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYodGhpcy5nZXRCdWlsZFBsYXRmb3JtKCkgPT09IFwiaW9zXCIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndlYmtpdF9cIiArIHRoaXMuZ2V0T1NWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZigvdHJpZGVudC9pLnRlc3QoTVsxXSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0ZW0gPSAvXFxicnZbIDpdKyhcXGQrKS9nLmV4ZWModWEpIHx8IFtdO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gJ0lFICcgKyAodGVtWzFdIHx8ICcnKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihNWzFdID09PSAnQ2hyb21lJylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IHVhLm1hdGNoKC9cXGIoT1BSfEVkZ2V8VUJyb3dzZXIpXFwvKFxcZCspLyk7XG4gICAgICAgICAgICAgICAgICAgIGlmKHRlbSE9IG51bGwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0ZW0uc2xpY2UoMSkuam9pbignICcpLnJlcGxhY2UoJ09QUicsICdPcGVyYScpLnJlcGxhY2UoJ1VCcm93c2VyJywgJ1VDJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0gJiYgTVsxXS50b0xvd2VyQ2FzZSgpID09PSAnZmJhdicpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBNWzFdID0gXCJmYWNlYm9va1wiO1xuICAgICAgICAgICAgICAgICAgICBpZihNWzJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWNlYm9vayBcIiArIE1bMl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgTVN0cmluZzpzdHJpbmdbXSA9IE1bMl0/IFtNWzFdLCBNWzJdXTogW25hdmlnYXRvci5hcHBOYW1lLCBuYXZpZ2F0b3IuYXBwVmVyc2lvbiwgJy0/J107XG5cbiAgICAgICAgICAgICAgICBpZigodGVtID0gdWEubWF0Y2goL3ZlcnNpb25cXC8oXFxkKykvaSkpICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBNU3RyaW5nLnNwbGljZSgxLCAxLCB0ZW1bMV0pO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBNU3RyaW5nLmpvaW4oJyAnKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBiZWZvcmV1bmxvYWQgaXMgYSBicm93c2VyIGRldGFpbCwgcmVnaXN0ZXJlZCBoZXJlIHJhdGhlciB0aGFuIGluXG4gICAgICAgICAgICAvLyBHYW1lQW5hbHl0aWNzLmluaXQoKSB3aGVyZSBpdCB1c2VkIHRvIHRocm93IG9uIGltcG9ydCBpbiBOb2RlLlxuICAgICAgICAgICAgcHVibGljIG9uSW5pdCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lciAhPT0gJ2Z1bmN0aW9uJykgeyByZXR1cm47IH1cbiAgICAgICAgICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcImJlZm9yZXVubG9hZFwiLCAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoJ2FkZEV2ZW50TGlzdGVuZXIgdW5sb2FkJyk7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZS5ub3RpZnlCZWZvcmVVbmxvYWRMaXN0ZW5lcnMoKTtcbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWF0Y2hJdGVtKGFnZW50OnN0cmluZywgZGF0YTpBcnJheTxOYW1lVmFsdWVWZXJzaW9uPik6TmFtZVZlcnNpb25cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0Ok5hbWVWZXJzaW9uID0gbmV3IE5hbWVWZXJzaW9uKFwidW5rbm93blwiLCBcIjAuMC4wXCIpO1xuICAgICAgICAgICAgICAgIHZhciBtYXRoY2VzUmVzdWx0OnN0cmluZztcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGRhdGEubGVuZ3RoOyBpICs9IDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAobmV3IFJlZ0V4cChkYXRhW2ldLnZhbHVlLCAnaScpLnRlc3QoYWdlbnQpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWF0Y2hlczpSZWdFeHBNYXRjaEFycmF5ID0gYWdlbnQubWF0Y2gobmV3IFJlZ0V4cChkYXRhW2ldLnZlcnNpb24gKyAnWy0gLzo7XShbXFxcXGQuX10rKScsICdpJykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZlcnNpb246c3RyaW5nID0gJyc7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0Y2hlcyAmJiBtYXRjaGVzWzFdKSB7IG1hdGhjZXNSZXN1bHQgPSBtYXRjaGVzWzFdOyB9XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0aGNlc1Jlc3VsdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcGFydHM6c3RyaW5nW10gPSBtYXRoY2VzUmVzdWx0LnNwbGl0KC9bLl9dKy8pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgTWF0aC5taW4ocGFydHMubGVuZ3RoLCAzKTsgaiArPSAxKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyc2lvbiArPSBwYXJ0c1tqXSArIChqIDwgTWF0aC5taW4ocGFydHMubGVuZ3RoLCAzKSAtIDEgPyAnLicgOiAnJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gPSAnMC4wLjAnO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lm5hbWUgPSBkYXRhW2ldLm5hbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQudmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgcGxhdGZvcm1cbiAgICB7XG4gICAgICAgIC8vIEJyb3dzZXIgYnVpbGQgdGFyZ2V0LiBUaGUgTm9kZSBidW5kbGUgY29tcGlsZXMgbWFrZVBsYXRmb3JtLm5vZGUudHNcbiAgICAgICAgLy8gaW5zdGVhZDsgdGhpcyBpcyB0aGUgSlMgYW5hbG9ndWUgb2YgQysrJ3MgR0FEZXZpY2VQbGF0Zm9ybS5oIHNlbGVjdGlvbi5cbiAgICAgICAgZXhwb3J0IGZ1bmN0aW9uIG1ha2VQbGF0Zm9ybSgpOiBHQVBsYXRmb3JtXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgR0FQbGF0Zm9ybUJyb3dzZXIoKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdG9yZVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgSUdBU3RvcmFnZSA9IGdhbWVhbmFseXRpY3Muc3RvcmFnZS5JR0FTdG9yYWdlO1xuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVN0b3JlQXJnc09wZXJhdG9yXG4gICAgICAgIHtcbiAgICAgICAgICAgIEVxdWFsLFxuICAgICAgICAgICAgTGVzc09yRXF1YWwsXG4gICAgICAgICAgICBOb3RFcXVhbFxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgRXZlbnRzID0gMCxcbiAgICAgICAgICAgIFNlc3Npb25zID0gMSxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uID0gMlxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdG9yZSA9IG5ldyBHQVN0b3JlKCk7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzdG9yYWdlOklHQVN0b3JhZ2UgPSBudWxsO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4TnVtYmVyT2ZFbnRyaWVzOm51bWJlciA9IDIwMDA7ICAgLy8gYnJvd3NlcjogZW50cnkgY291bnRcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heERiU2l6ZUJ5dGVzOm51bWJlciA9IDYyOTE0NTY7ICAgICAvLyBOb2RlOiBieXRlcywgR0FTdG9yZS5jcHA6MTlcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbnNTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0b3JlSXRlbXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgU3RyaW5nRm9ybWF0ID0gKHN0cjpzdHJpbmcsIC4uLmFyZ3M6c3RyaW5nW10pID0+IHN0ci5yZXBsYWNlKC97KFxcZCspfS9nLCAoXywgaW5kZXg6bnVtYmVyKSA9PiBhcmdzW2luZGV4XSB8fCAnJyk7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBLZXlGb3JtYXQ6c3RyaW5nID0gXCJHQTo6ezB9Ojp7MX1cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEV2ZW50c1N0b3JlS2V5OnN0cmluZyA9IFwiZ2FfZXZlbnRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFNlc3Npb25zU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9zZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBQcm9ncmVzc2lvblN0b3JlS2V5OnN0cmluZyA9IFwiZ2FfcHJvZ3Jlc3Npb25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEl0ZW1zU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9pdGVtc1wiO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKCkge31cblxuICAgICAgICAgICAgLy8gSW5qZWN0ZWQgYnkgR2FtZUFuYWx5dGljcy5pbml0KCk6IGxvY2FsU3RvcmFnZSBpbiB0aGUgYnJvd3NlciwgdGhlXG4gICAgICAgICAgICAvLyB0d28tdGllciBmaWxlIHN0b3JlIGluIE5vZGUgKHNwZWMsIFwiU3RvcmFnZVwiKS5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0U3RvcmFnZShzOklHQVN0b3JhZ2UpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zdG9yYWdlID0gcztcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU3RvcmFnZSBpcyBhdmFpbGFibGU/OiBcIiArIEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzU3RvcmFnZUF2YWlsYWJsZSgpOmJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5zdG9yYWdlICE9PSBudWxsICYmIEdBU3RvcmUuc3RvcmFnZS5pc0F2YWlsYWJsZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGJ5dGVzOm51bWJlciA9IEdBU3RvcmUuc3RvcmFnZSA/IEdBU3RvcmUuc3RvcmFnZS5nZXRTaXplQnl0ZXMoKSA6IC0xO1xuICAgICAgICAgICAgICAgIGlmIChieXRlcyA+PSAwKSB7IHJldHVybiBieXRlcyA+IEdBU3RvcmUuTWF4RGJTaXplQnl0ZXM7IH1cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZS5sZW5ndGggKyBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUubGVuZ3RoID4gR0FTdG9yZS5NYXhOdW1iZXJPZkVudHJpZXM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZGVsZXRlU2Vzc2lvbkNhY2hlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FTdG9yZS5zdG9yYWdlKSB7IEdBU3RvcmUuc3RvcmFnZS5kZWxldGVTZXNzaW9uQ2FjaGUoKTsgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwdXQoa2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIEEgZmFpbGVkIHdyaXRlIHVzZWQgdG8gYmUgc3dhbGxvd2VkIGJ5IGFkZEV2ZW50VG9TdG9yZSdzIGNhdGNoOyBsb2cgaXQuXG4gICAgICAgICAgICAgICAgdHJ5IHsgR0FTdG9yZS5zdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7IH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSkgeyBHQUxvZ2dlci53KFwiU3RvcmUgd3JpdGUgZmFpbGVkIGZvciBcIiArIGtleSArIFwiOiBcIiArIChlICYmIGUubmFtZSA/IGUubmFtZSA6IGUpKTsgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNlbGVjdChzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSwgc29ydDpib29sZWFuID0gZmFsc2UsIG1heENvdW50Om51bWJlciA9IDApOiBBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGFkZDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFhZGQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihhZGQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5wdXNoKGVudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHNvcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXN1bHQuc29ydCgoYTp7W2tleTpzdHJpbmddOiBhbnl9LCBiOntba2V5OnN0cmluZ106IGFueX0pID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoYVtcImNsaWVudF90c1wiXSBhcyBudW1iZXIpIC0gKGJbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKVxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihtYXhDb3VudCA+IDAgJiYgcmVzdWx0Lmxlbmd0aCA+IG1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gcmVzdWx0LnNsaWNlKDAsIG1heENvdW50ICsgMSlcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVwZGF0ZShzdG9yZTpFR0FTdG9yZSwgc2V0QXJnczpBcnJheTxbc3RyaW5nLCBhbnldPiwgd2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldPiA9IFtdKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGU6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCB3aGVyZUFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSB3aGVyZUFyZ3Nbal07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXVwZGF0ZSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKHVwZGF0ZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IHNldEFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNldEFyZ3NFbnRyeTpbc3RyaW5nLCBhbnldID0gc2V0QXJnc1tqXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzZXRBcmdzRW50cnlbMF1dID0gc2V0QXJnc0VudHJ5WzFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZGVsZXRlKHN0b3JlOkVHQVN0b3JlLCBhcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgZGVsOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgYXJncy5sZW5ndGg7ICsrailcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3NFbnRyeTpbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XSA9IGFyZ3Nbal07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWRlbClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGRlbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnNwbGljZShpLCAxKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC0taTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbnNlcnQoc3RvcmU6RUdBU3RvcmUsIG5ld0VudHJ5Ontba2V5OnN0cmluZ106IGFueX0sIHJlcGxhY2U6Ym9vbGVhbiA9IGZhbHNlLCByZXBsYWNlS2V5OnN0cmluZyA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZXBsYWNlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoIXJlcGxhY2VLZXkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHZhciByZXBsYWNlZDpib29sZWFuID0gZmFsc2U7XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W3JlcGxhY2VLZXldID09IG5ld0VudHJ5W3JlcGxhY2VLZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBuZXdFbnRyeSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudHJ5W3NdID0gbmV3RW50cnlbc107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcGxhY2VkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnB1c2gobmV3RW50cnkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2F2ZShnYW1lS2V5OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTdG9yYWdlIGlzIG5vdCBhdmFpbGFibGUsIGNhbm5vdCBzYXZlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RvcmUucHV0KEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5KSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSkpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUucHV0KEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLlNlc3Npb25zU3RvcmVLZXkpLCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnB1dChHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5KSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlKSk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5wdXQoR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuSXRlbXNTdG9yZUtleSksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcykpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGxvYWQoZ2FtZUtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3QgbG9hZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBKU09OLnBhcnNlKEdBU3RvcmUuc3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5KSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2V2ZW50cycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gSlNPTi5wYXJzZShHQVN0b3JlLnN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5KSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdzZXNzaW9ucycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBKU09OLnBhcnNlKEdBU3RvcmUuc3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLlByb2dyZXNzaW9uU3RvcmVLZXkpKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ3Byb2dyZXNzaW9uJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcyA9IEpTT04ucGFyc2UoR0FTdG9yZS5zdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuSXRlbXNTdG9yZUtleSkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnaXRlbXMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcyA9IHt9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJdGVtKGdhbWVLZXk6c3RyaW5nLCBrZXk6c3RyaW5nLCB2YWx1ZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGtleVdpdGhQcmVmaXg6c3RyaW5nID0gR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIGtleSk7XG5cbiAgICAgICAgICAgICAgICBpZighdmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SXRlbShnYW1lS2V5OnN0cmluZywga2V5OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBrZXkpO1xuICAgICAgICAgICAgICAgIGlmKGtleVdpdGhQcmVmaXggaW4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XSBhcyBzdHJpbmc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0U3RvcmUoc3RvcmU6RUdBU3RvcmUpOiBBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaChzdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuRXZlbnRzOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuU2Vzc2lvbnM6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlByb2dyZXNzaW9uOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkdBU3RvcmUuZ2V0U3RvcmUoKTogQ2Fubm90IGZpbmQgc3RvcmU6IFwiICsgc3RvcmUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmFnZVxuICAgIHtcbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RvcmFnZUJyb3dzZXIgaW1wbGVtZW50cyBJR0FTdG9yYWdlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlOmJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgbG9jYWxTdG9yYWdlID09PSAnb2JqZWN0JylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Rlc3RpbmdMb2NhbFN0b3JhZ2UnLCAneWVzJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5hdmFpbGFibGUgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKSB7fVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0SXRlbShrZXk6c3RyaW5nKTogc3RyaW5nIHwgbnVsbCB7IHJldHVybiBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShrZXkpOyB9XG4gICAgICAgICAgICBwdWJsaWMgc2V0SXRlbShrZXk6c3RyaW5nLCB2YWx1ZTpzdHJpbmcpOiB2b2lkIHsgbG9jYWxTdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7IH1cbiAgICAgICAgICAgIHB1YmxpYyByZW1vdmVJdGVtKGtleTpzdHJpbmcpOiB2b2lkIHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oa2V5KTsgfVxuICAgICAgICAgICAgcHVibGljIGlzQXZhaWxhYmxlKCk6IGJvb2xlYW4geyByZXR1cm4gdGhpcy5hdmFpbGFibGU7IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXRTaXplQnl0ZXMoKTogbnVtYmVyIHsgcmV0dXJuIC0xOyB9XG4gICAgICAgICAgICBwdWJsaWMgZGVsZXRlU2Vzc2lvbkNhY2hlKCk6IHZvaWQge31cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdG9yYWdlXG4gICAge1xuICAgICAgICBleHBvcnQgZnVuY3Rpb24gbWFrZVN0b3JhZ2UoKTogSUdBU3RvcmFnZVxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IEdBU3RvcmFnZUJyb3dzZXIoKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdGF0ZVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEdBRGV2aWNlID0gZ2FtZWFuYWx5dGljcy5kZXZpY2UuR0FEZXZpY2U7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RhdGVcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZGtFcnJvcjpzdHJpbmcgPSBcInNka19lcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQ6bnVtYmVyID0gNTA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIOm51bWJlciA9IDY0O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSDpudW1iZXIgPSAyNTY7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdGF0ZSA9IG5ldyBHQVN0YXRlKCk7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgdGhpcy5pc1VubG9hZGluZyA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHVzZXJJZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFVzZXJJZCh1c2VySWQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudXNlcklkID0gdXNlcklkO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgaWRlbnRpZmllcjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldElkZW50aWZpZXIoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllcjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBleHRVc2VySWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFeHRVc2VySWQodWlkOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmV4dFVzZXJJZCA9IHVpZDsgXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXh0VXNlcklkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmV4dFVzZXJJZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBpbml0aWFsaXplZDpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0luaXRpYWxpemVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5pbml0aWFsaXplZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SW5pdGlhbGl6ZWQodmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkID0gdmFsdWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZXNzaW9uU3RhcnQ6bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZXNzaW9uU3RhcnQoKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlc3Npb25OdW06bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZXNzaW9uTnVtKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW07XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBpc1VubG9hZGluZzpib29sZWFuO1xuXG4gICAgICAgICAgICBwcml2YXRlIHRyYW5zYWN0aW9uTnVtOm51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VHJhbnNhY3Rpb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW07XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZXNzaW9uSWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZXNzaW9uSWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDM6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVLZXk6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lS2V5KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVLZXk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZ2FtZVNlY3JldDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEdhbWVTZWNyZXQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZVNlY3JldDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMigpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIodmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMiA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkczogeyBba2V5OiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlQ3VycmVuY2llcyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSByZXNvdXJjZSBjdXJyZW5jaWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUl0ZW1UeXBlcyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIHJlc291cmNlIGl0ZW0gdHlwZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBidWlsZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEJ1aWxkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRCdWlsZCh2YWx1ZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5idWlsZCA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYnVpbGQgdmVyc2lvbjogXCIgKyB2YWx1ZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgdXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UudXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIF9pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5faXNFdmVudFN1Ym1pc3Npb25FbmFibGVkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnQ2FjaGVkOntba2V5OnN0cmluZ106IGFueX07XG4gICAgICAgICAgICBwcml2YXRlIGNvbmZpZ3VyYXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgdHJhY2tpbmdDb25maWd1cmF0aW9uczogYW55W10gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgcmVtb3RlQ29uZmlnc0lzUmVhZHk6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgcmVtb3RlQ29uZmlnc0xpc3RlbmVyczpBcnJheTx7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBiZWZvcmVVbmxvYWRMaXN0ZW5lcnM6IEFycmF5PHsgb25CZWZvcmVVbmxvYWQ6ICgpID0+IHZvaWQgfT4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBpbml0QXV0aG9yaXplZDpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIGNsaWVudFNlcnZlclRpbWVPZmZzZXQ6bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIGNvbmZpZ3NIYXNoOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGFiSWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hYklkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIGFiVmFyaWFudElkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QUJUZXN0aW5nVmFyaWFudElkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmFiVmFyaWFudElkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGRlZmF1bHRVc2VySWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzZXREZWZhdWx0SWQodmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuZGVmYXVsdFVzZXJJZCA9ICF2YWx1ZSA/IFwiXCIgOiB2YWx1ZTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXREZWZhdWx0SWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZ0RlZmF1bHQ6e1trZXk6c3RyaW5nXTogc3RyaW5nfSA9IHt9O1xuXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrQ29uZmlnKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaXJzdDpzdHJpbmc7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGpzb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0ID0ganNvbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihmaXJzdCAmJiBjb3VudCA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZztcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaXJzdDpzdHJpbmc7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGpzb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0ID0ganNvbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihmaXJzdCAmJiBjb3VudCA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0RlZmF1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25Ucmllczp7W2tleTpzdHJpbmddOiBudW1iZXJ9ID0ge307XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IERlZmF1bHRVc2VySWRLZXk6c3RyaW5nID0gXCJkZWZhdWx0X3VzZXJfaWRcIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbk51bUtleTpzdHJpbmcgPSBcInNlc3Npb25fbnVtXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFRyYW5zYWN0aW9uTnVtS2V5OnN0cmluZyA9IFwidHJhbnNhY3Rpb25fbnVtXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wMUtleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAxXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wMktleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wM0tleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAzXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFNka0NvbmZpZ0NhY2hlZEtleTpzdHJpbmcgPSBcInNka19jb25maWdfY2FjaGVkXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IExhc3RVc2VkSWRlbnRpZmllcktleTogc3RyaW5nID0gXCJsYXN0X3VzZWRfaWRlbnRpZmllclwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDFLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMktleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50U2Vzc2lvbk51bSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IHNlc3Npb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0cmFuc2FjdGlvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSB0cmFuc2FjdGlvbk51bUludDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJpZXM6bnVtYmVyID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXSA9IHRyaWVzO1xuXG4gICAgICAgICAgICAgICAgLy8gUGVyc2lzdFxuICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInByb2dyZXNzaW9uXCJdID0gcHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgdmFsdWVzW1widHJpZXNcIl0gPSB0cmllcztcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgdmFsdWVzLCB0cnVlLCBcInByb2dyZXNzaW9uXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIERlbGV0ZVxuICAgICAgICAgICAgICAgIHZhciBwYXJtczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBwYXJtcy5wdXNoKFtcInByb2dyZXNzaW9uXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBwcm9ncmVzc2lvbl0pO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlByb2dyZXNzaW9uLCBwYXJtcyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0S2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5ID0gZ2FtZUtleTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQgPSBnYW1lU2VjcmV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmcgPSBmbGFnO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgbWFudWFsIHNlc3Npb24gaGFuZGxpbmc6IFwiICsgZmxhZyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIFBvcnQgb2YgR0FTdGF0ZTo6dXNlRXJyb3JSZXBvcnRpbmcoKS4gQysrIGRlZmF1bHRzIHRoaXMgdG8gdHJ1ZTsgdGhlXG4gICAgICAgICAgICAvLyBKUyBTREsgaGFzIG5ldmVyIHJlcG9ydGVkIGNyYXNoZXMsIHNvIGl0IGRlZmF1bHRzIE9GRiBoZXJlIChzcGVjLFxuICAgICAgICAgICAgLy8gZGl2ZXJnZW5jZSA0KS4gVGhlIE5vZGUgcGxhdGZvcm0gaW5zdGFsbHMgaXRzIG1vbml0b3IgcmVnYXJkbGVzcyBhbmRcbiAgICAgICAgICAgIC8vIGNoZWNrcyB0aGlzIGZsYWcgd2hlbiBpdCBmaXJlcywgc28gZW5hYmxpbmcgbGF0ZSBzdGlsbCB3b3Jrcy5cbiAgICAgICAgICAgIHByaXZhdGUgX2VuYWJsZUVycm9yUmVwb3J0aW5nOmJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVFcnJvclJlcG9ydGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5fZW5hYmxlRXJyb3JSZXBvcnRpbmcgPSBmbGFnO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgZXJyb3IgcmVwb3J0aW5nOiBcIiArIGZsYWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVzZUVycm9yUmVwb3J0aW5nKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5fZW5hYmxlRXJyb3JSZXBvcnRpbmc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5faXNFdmVudFN1Ym1pc3Npb25FbmFibGVkID0gZmxhZztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuICAgICAgICAgICAgICAgIC8vIEV2ZW50IFVVSURcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImV2ZW50X3V1aWRcIl0gPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG4gICAgICAgICAgICAgICAgLy8gVXNlciBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ1c2VyX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyO1xuXG4gICAgICAgICAgICAgICAgLy8gZXh0IHVzZXIgaWRcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmV4dFVzZXJJZCAmJiBHQVN0YXRlLmluc3RhbmNlLmV4dFVzZXJJZC5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ1c2VyX2lkX2V4dFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuZXh0VXNlcklkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENsaWVudCBUaW1lc3RhbXAgKHRoZSBhZGp1c3RlZCB0aW1lc3RhbXApXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjbGllbnRfdHNcIl0gPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcbiAgICAgICAgICAgICAgICAvLyBTREsgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIG1ha2UgKGhhcmRjb2RlZCB0byBhcHBsZSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm1hbnVmYWN0dXJlclwiXSA9IEdBRGV2aWNlLmRldmljZU1hbnVmYWN0dXJlcjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZGV2aWNlXCJdID0gR0FEZXZpY2UuZGV2aWNlTW9kZWw7XG4gICAgICAgICAgICAgICAgLy8gQnJvd3NlciB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJicm93c2VyX3ZlcnNpb25cIl0gPSBHQURldmljZS5icm93c2VyVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcbiAgICAgICAgICAgICAgICAvLyBTZXNzaW9uIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNlc3Npb25faWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgICAgICAvLyBTZXNzaW9uIG51bWJlclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW0dBU3RhdGUuU2Vzc2lvbk51bUtleV0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW07XG5cbiAgICAgICAgICAgICAgICAvLyB0eXBlIG9mIGNvbm5lY3Rpb24gdGhlIHVzZXIgaXMgY3VycmVudGx5IG9uIChhZGQgaWYgdmFsaWQpXG4gICAgICAgICAgICAgICAgdmFyIGNvbm5lY3Rpb25fdHlwZTpzdHJpbmcgPSBHQURldmljZS5nZXRDb25uZWN0aW9uVHlwZSgpO1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25fdHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbm5lY3Rpb25fdHlwZVwiXSA9IGNvbm5lY3Rpb25fdHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImVuZ2luZV92ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmVtb3RlIGNvbmZpZ3NcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnRyYWNraW5nQ29uZmlndXJhdGlvbnMgJiYgR0FTdGF0ZS5pbnN0YW5jZS50cmFja2luZ0NvbmZpZ3VyYXRpb25zLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbmZpZ3VyYXRpb25zX3YzXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS50cmFja2luZ0NvbmZpZ3VyYXRpb25zO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEEvQiB0ZXN0aW5nXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5hYklkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJhYl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYWJJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYWJfdmFyaWFudF9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBDT05ESVRJT05BTCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBBcHAgYnVpbGQgdmVyc2lvbiAodXNlIGlmIG5vdCBuaWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImJ1aWxkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5idWlsZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuICAgICAgICAgICAgICAgIC8vIEV2ZW50IFVVSURcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImV2ZW50X3V1aWRcIl0gPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgICAgICAvLyBDYXRlZ29yeVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2F0ZWdvcnlcIl0gPSBHQVN0YXRlLkNhdGVnb3J5U2RrRXJyb3I7XG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSBtYWtlIChoYXJkY29kZWQgdG8gYXBwbGUpXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImRldmljZVwiXSA9IEdBRGV2aWNlLmRldmljZU1vZGVsO1xuICAgICAgICAgICAgICAgIC8vIFBsYXRmb3JtIChvcGVyYXRpbmcgc3lzdGVtKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uX3R5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBhbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRJbml0QW5ub3RhdGlvbnMoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBpbml0QW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuZ2V0SWRlbnRpZmllcigpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuTGFzdFVzZWRJZGVudGlmaWVyS2V5LCBHQVN0YXRlLmdldElkZW50aWZpZXIoKSk7XG5cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJ1c2VyX2lkXCJdID0gR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCk7XG5cbiAgICAgICAgICAgICAgICAvLyBTREsgdmVyc2lvblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcblxuICAgICAgICAgICAgICAgIC8vIFBsYXRmb3JtIChvcGVyYXRpbmcgc3lzdGVtKVxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIEJ1aWxkXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5nZXRCdWlsZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wiYnVpbGRcIl0gPSBHQVN0YXRlLmdldEJ1aWxkKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcImJ1aWxkXCJdID0gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJzZXNzaW9uX251bVwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpO1xuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInJhbmRvbV9zYWx0XCJdID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gaW5pdEFubm90YXRpb25zO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENsaWVudFRzQWRqdXN0ZWQoKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzOm51bWJlciA9IEdBVXRpbGl0aWVzLnRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpO1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUc0FkanVzdGVkSW50ZWdlcjpudW1iZXIgPSBjbGllbnRUcyArIEdBU3RhdGUuaW5zdGFuY2UuY2xpZW50U2VydmVyVGltZU9mZnNldDtcblxuICAgICAgICAgICAgICAgIGlmKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ2xpZW50VHMoY2xpZW50VHNBZGp1c3RlZEludGVnZXIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2xpZW50VHM7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNlc3Npb25Jc1N0YXJ0ZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCAhPSAwO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjYWNoZUlkZW50aWZpZXIoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UudXNlcklkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyID0gR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQ7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYoR0FTdGF0ZS5pbnN0YW5jZS5kZWZhdWx0VXNlcklkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyID0gR0FTdGF0ZS5pbnN0YW5jZS5kZWZhdWx0VXNlcklkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJpZGVudGlmaWVyLCB7Y2xlYW46XCIgKyBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgKyBcIn1cIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5zdXJlUGVyc2lzdGVkU3RhdGVzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBnZXQgYW5kIGV4dHJhY3Qgc3RvcmVkIHN0YXRlc1xuICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmxvYWQoR0FTdGF0ZS5nZXRHYW1lS2V5KCkpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBpbnRvIEdBU3RhdGUgaW5zdGFuY2VcbiAgICAgICAgICAgICAgICB2YXIgaW5zdGFuY2U6R0FTdGF0ZSA9IEdBU3RhdGUuaW5zdGFuY2U7XG5cbiAgICAgICAgICAgICAgICBpbnN0YW5jZS5zZXREZWZhdWx0SWQoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgOiBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCkpO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5TZXNzaW9uTnVtS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5TZXNzaW9uTnVtS2V5KSkgOiAwLjA7XG5cbiAgICAgICAgICAgICAgICBpbnN0YW5jZS50cmFuc2FjdGlvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkgIT0gbnVsbCA/IE51bWJlcihHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXkpKSA6IDAuMDtcblxuICAgICAgICAgICAgICAgIC8vIHJlc3RvcmUgZGltZW5zaW9uIHNldHRpbmdzXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAxS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDEgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMktleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAyIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDNLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMyBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gZ2V0IGNhY2hlZCBpbml0IGNhbGwgdmFsdWVzXG4gICAgICAgICAgICAgICAgdmFyIHNka0NvbmZpZ0NhY2hlZFN0cmluZzpzdHJpbmcgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChzZGtDb25maWdDYWNoZWRTdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RVc2VkSWRlbnRpZmllcjpzdHJpbmcgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuTGFzdFVzZWRJZGVudGlmaWVyS2V5KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJsYXN0VXNlZElkZW50aWZpZXI9XCIgKyBsYXN0VXNlZElkZW50aWZpZXIgKyBcIiwgR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCk9XCIgKyBHQVN0YXRlLmdldElkZW50aWZpZXIoKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobGFzdFVzZWRJZGVudGlmaWVyICE9IG51bGwgJiYgbGFzdFVzZWRJZGVudGlmaWVyICE9IEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJOZXcgaWRlbnRpZmllciBzcG90dGVkIGNvbXBhcmVkIHRvIGxhc3Qgb25lIHVzZWQsIGNsZWFyaW5nIGNhY2hlZCBjb25maWdzIGhhc2ghIVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoc2RrQ29uZmlnQ2FjaGVkW1wiY29uZmlnc19oYXNoXCJdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIHNka0NvbmZpZ0NhY2hlZFtcImNvbmZpZ3NfaGFzaFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgPSBzZGtDb25maWdDYWNoZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0NvbmZpZygpO1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jb25maWdzSGFzaCA9IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl0gPyBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuYWJJZCA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXSA/IGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmFiVmFyaWFudElkID0gY3VycmVudFNka0NvbmZpZ1tcImFiX3ZhcmlhbnRfaWRcIl0gPyBjdXJyZW50U2RrQ29uZmlnW1wiYWJfdmFyaWFudF9pZFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb246QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5Qcm9ncmVzc2lvbik7XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzdWx0c19nYV9wcm9ncmVzc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzdWx0c19nYV9wcm9ncmVzc2lvbi5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlc3VsdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gcmVzdWx0c19nYV9wcm9ncmVzc2lvbltpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1tyZXN1bHRbXCJwcm9ncmVzc2lvblwiXSBhcyBzdHJpbmddID0gcmVzdWx0W1widHJpZXNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHM6bnVtYmVyKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzOm51bWJlciA9IEdBVXRpbGl0aWVzLnRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXJ2ZXJUcyAtIGNsaWVudFRzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBmb3JtYXRTdHJpbmcoczpzdHJpbmcsIGFyZ3M6QXJyYXk8c3RyaW5nPik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBmb3JtYXR0ZWQ6IHN0cmluZyA9IHM7XG4gICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmdzLmxlbmd0aDsgaSsrKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlZ2V4cCA9IG5ldyBSZWdFeHAoJ1xcXFx7JyArIGkgKyAnXFxcXH0nLCAnZ2knKTtcbiAgICAgICAgICAgICAgICAgICAgZm9ybWF0dGVkID0gZm9ybWF0dGVkLnJlcGxhY2UocmVnZXhwLCBhcmd1bWVudHNbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZm9ybWF0dGVkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgZXJyb3JDYWxsYmFjazooYmFzZU1lc3NhZ2U6c3RyaW5nLCBtZXNzYWdlOnN0cmluZykgPT4gdm9pZD1udWxsKToge1tpZDpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDp7W2lkOnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcih2YXIga2V5IGluIGZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlOmFueSA9IGZpZWxkc1trZXldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZigha2V5IHx8ICF2YWx1ZSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFzZU1lc3NhZ2U6c3RyaW5nID0gXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT17MH0sIHZhbHVlPXsxfSBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIGtleSBvciB2YWx1ZSBpcyBudWxsXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gR0FTdGF0ZS5mb3JtYXRTdHJpbmcoYmFzZU1lc3NhZ2UsIFtrZXksIHZhbHVlXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXJyb3JDYWxsYmFjaylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yQ2FsbGJhY2soYmFzZU1lc3NhZ2UsIG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYoY291bnQgPCBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0NPVU5UKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZWdleCA9IG5ldyBSZWdFeHAoXCJeW2EtekEtWjAtOV9dezEsXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEggKyBcIn0kXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGtleSwgcmVnZXgpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHR5cGUgPSB0eXBlb2YgdmFsdWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHR5cGUgPT09IFwic3RyaW5nXCIgfHwgdmFsdWUgaW5zdGFuY2VvZiBTdHJpbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZUFzU3RyaW5nOnN0cmluZyA9IHZhbHVlIGFzIHN0cmluZztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodmFsdWVBc1N0cmluZy5sZW5ndGggPD0gR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIICYmIHZhbHVlQXNTdHJpbmcubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRba2V5XSA9IHZhbHVlQXNTdHJpbmc7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFzZU1lc3NhZ2U6IHN0cmluZyA9IFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9ezB9LCB2YWx1ZT17MX0gaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyB2YWx1ZSBpcyBhbiBlbXB0eSBzdHJpbmcgb3IgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjaGFyYWN0ZXJzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSCArIFwiKVwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOiBzdHJpbmcgPSBHQVN0YXRlLmZvcm1hdFN0cmluZyhiYXNlTWVzc2FnZSwgW2tleSwgdmFsdWVdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlcnJvckNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yQ2FsbGJhY2soYmFzZU1lc3NhZ2UsIG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmKHR5cGUgPT09IFwibnVtYmVyXCIgfHwgdmFsdWUgaW5zdGFuY2VvZiBOdW1iZXIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZUFzTnVtYmVyOm51bWJlciA9IHZhbHVlIGFzIG51bWJlcjtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0W2tleV0gPSB2YWx1ZUFzTnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiYXNlTWVzc2FnZTogc3RyaW5nID0gXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT17MH0sIHZhbHVlPXsxfSBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIHZhbHVlIGlzIG5vdCBhIHN0cmluZyBvciBudW1iZXJcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOiBzdHJpbmcgPSBHQVN0YXRlLmZvcm1hdFN0cmluZyhiYXNlTWVzc2FnZSwgW2tleSwgdmFsdWVdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXJyb3JDYWxsYmFjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yQ2FsbGJhY2soYmFzZU1lc3NhZ2UsIG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBiYXNlTWVzc2FnZTogc3RyaW5nID0gXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT17MH0sIHZhbHVlPXsxfSBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIGtleSBjb250YWlucyBpbGxlZ2FsIGNoYXJhY3RlciwgaXMgZW1wdHkgb3IgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjaGFyYWN0ZXJzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfS0VZX0xFTkdUSCArIFwiKVwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTogc3RyaW5nID0gR0FTdGF0ZS5mb3JtYXRTdHJpbmcoYmFzZU1lc3NhZ2UsIFtrZXksIHZhbHVlXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlcnJvckNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFzZU1lc3NhZ2U6IHN0cmluZyA9IFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9ezB9LCB2YWx1ZT17MX0gaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0IGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY3VzdG9tIGZpZWxkcyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0NPVU5UICsgXCIpXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6IHN0cmluZyA9IEdBU3RhdGUuZm9ybWF0U3RyaW5nKGJhc2VNZXNzYWdlLCBba2V5LCB2YWx1ZV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVycm9yQ2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAxIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAxKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDEgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMShcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMiBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMigpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAyIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDMgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMyBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XS50b1N0cmluZygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZGVmYXVsdFZhbHVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDb25maWd1cmF0aW9uSnNvblZhbHVlKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTphbnkpOmFueVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBkZWZhdWx0VmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzUmVtb3RlQ29uZmlnc1JlYWR5KCk6Ym9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NJc1JlYWR5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpIDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycy5wdXNoKGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyOnsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5kZXggPSBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMuaW5kZXhPZihsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgaWYoaW5kZXggPiAtMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHBvcHVsYXRlQ29uZmlndXJhdGlvbnMoc2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbnM6YW55W10gPSBzZGtDb25maWdbXCJjb25maWdzXCJdO1xuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS50cmFja2luZ0NvbmZpZ3VyYXRpb25zID0gW11cblxuICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3VyYXRpb25zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9ucyA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY29uZmlndXJhdGlvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uOntba2V5OnN0cmluZ106IGFueX0gPSBjb25maWd1cmF0aW9uc1tpXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY29uZmlndXJhdGlvbilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIga2V5OnN0cmluZyA9IGNvbmZpZ3VyYXRpb25bXCJrZXlcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlOmFueSA9IGNvbmZpZ3VyYXRpb25bXCJ2YWx1ZVwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdID8gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdIDogTnVtYmVyLk1JTl9WQUxVRTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgZW5kX3RzOm51bWJlciA9IGNvbmZpZ3VyYXRpb25bXCJlbmRfdHNcIl0gPyBjb25maWd1cmF0aW9uW1wiZW5kX3RzXCJdIDogTnVtYmVyLk1BWF9WQUxVRTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihrZXkgJiYgdmFsdWUgJiYgY2xpZW50X3RzX2FkanVzdGVkID4gc3RhcnRfdHMgJiYgY2xpZW50X3RzX2FkanVzdGVkIDwgZW5kX3RzKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJjb25maWd1cmF0aW9uIGFkZGVkOiBcIiArIEpTT04uc3RyaW5naWZ5KGNvbmZpZ3VyYXRpb24pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdHJhY2tDb25maWc6YW55ID0ge307XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cmFja0NvbmZpZ1tcImtleVwiXSA9IGNvbmZpZ3VyYXRpb25bXCJrZXlcIl1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cmFja0NvbmZpZ1tcImlkXCJdID0gY29uZmlndXJhdGlvbltcImlkXCJdXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJhY2tDb25maWdbXCJ2c25cIl0gPSBjb25maWd1cmF0aW9uW1widnNuXCJdXG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aGlzLmluc3RhbmNlLnRyYWNraW5nQ29uZmlndXJhdGlvbnMucHVzaCh0cmFja0NvbmZpZylcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NJc1JlYWR5ID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAgIHZhciBsaXN0ZW5lcnM6QXJyYXk8eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfT4gPSBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnM7XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgbGlzdGVuZXJzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYobGlzdGVuZXJzW2ldKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsaXN0ZW5lcnNbaV0ub25SZW1vdGVDb25maWdzVXBkYXRlZCgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZE9uQmVmb3JlVW5sb2FkTGlzdGVuZXIobGlzdGVuZXI6IHsgb25CZWZvcmVVbmxvYWQ6ICgpID0+IHZvaWQgfSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5iZWZvcmVVbmxvYWRMaXN0ZW5lcnMuaW5kZXhPZihsaXN0ZW5lcikgPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5iZWZvcmVVbmxvYWRMaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZU9uQmVmb3JlVW5sb2FkTGlzdGVuZXIobGlzdGVuZXI6IHsgb25CZWZvcmVVbmxvYWQ6ICgpID0+IHZvaWQgfSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5kZXggPSBHQVN0YXRlLmluc3RhbmNlLmJlZm9yZVVubG9hZExpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICBpZiAoaW5kZXggPiAtMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYmVmb3JlVW5sb2FkTGlzdGVuZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIG5vdGlmeUJlZm9yZVVubG9hZExpc3RlbmVycygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGxpc3RlbmVyczogQXJyYXk8eyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9PiA9IEdBU3RhdGUuaW5zdGFuY2UuYmVmb3JlVW5sb2FkTGlzdGVuZXJzO1xuXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBsaXN0ZW5lcnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAobGlzdGVuZXJzW2ldKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsaXN0ZW5lcnNbaV0ub25CZWZvcmVVbmxvYWQoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0YXNrc1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgU2RrRXJyb3JUYXNrXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heENvdW50Om51bWJlciA9IDEwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgY291bnRNYXA6e1trZXk6c3RyaW5nXTogbnVtYmVyfSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgdGltZXN0YW1wTWFwOntba2V5OnN0cmluZ106IERhdGV9ID0ge307XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZXhlY3V0ZSh1cmw6c3RyaW5nLCB0eXBlOnN0cmluZywgcGF5bG9hZERhdGE6c3RyaW5nLCBzZWNyZXRLZXk6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBub3c6RGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgICAgICAgICAgICBpZighU2RrRXJyb3JUYXNrLnRpbWVzdGFtcE1hcFt0eXBlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay50aW1lc3RhbXBNYXBbdHlwZV0gPSBub3c7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmKCFTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgZGlmZjpudW1iZXIgPSBub3cuZ2V0VGltZSgpIC0gU2RrRXJyb3JUYXNrLnRpbWVzdGFtcE1hcFt0eXBlXS5nZXRUaW1lKCk7XG4gICAgICAgICAgICAgICAgdmFyIGRpZmZTZWNvbmRzOm51bWJlciA9IGRpZmYgLyAxMDAwO1xuICAgICAgICAgICAgICAgIGlmKGRpZmZTZWNvbmRzID49IDM2MDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2sudGltZXN0YW1wTWFwW3R5cGVdID0gbm93O1xuICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSAwO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA+PSBTZGtFcnJvclRhc2suTWF4Q291bnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIGhhc2hIbWFjOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoc2VjcmV0S2V5LCBwYXlsb2FkRGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50ID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaS5nZXRDbGllbnQoKTtcbiAgICAgICAgICAgICAgICBpZiAoIWNsaWVudCkgeyByZXR1cm47IH1cbiAgICAgICAgICAgICAgICBjbGllbnQuc2VuZFJlcXVlc3QodXJsLCBoYXNoSG1hYywgbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHBheWxvYWREYXRhKSwgZmFsc2UpLnRoZW4oKHIpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHRleHQ6c3RyaW5nID0gci5wYWNrZXQgJiYgci5wYWNrZXQubGVuZ3RoID8gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHIucGFja2V0KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKCF0ZXh0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2RrIGVycm9yIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgKHIuc3RhdHVzVGV4dCB8fCBcIlwiKSArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByLmNvZGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKHIuY29kZSAhPSAyMDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJzZGsgZXJyb3IgZmFpbGVkLiByZXNwb25zZSBjb2RlIG5vdCAyMDAuIHN0YXR1cyBjb2RlOiBcIiArIHIuY29kZSArIFwiLCBkZXNjcmlwdGlvbjogXCIgKyAoci5zdGF0dXNUZXh0IHx8IFwiXCIpICsgXCIsIGJvZHk6IFwiICsgdGV4dCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdICsgMTtcbiAgICAgICAgICAgICAgICB9KS5jYXRjaCgoZTphbnkpID0+IHsgR0FMb2dnZXIuZShcInNkayBlcnJvciByZXF1ZXN0IGZhaWxlZDogXCIgKyBlKTsgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IFNka0Vycm9yVGFzayA9IGdhbWVhbmFseXRpY3MudGFza3MuU2RrRXJyb3JUYXNrO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JDYXRlZ29yeSA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQ2F0ZWdvcnk7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFyZWEgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFyZWE7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvckFjdGlvbiA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkVHQVNka0Vycm9yQWN0aW9uO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JQYXJhbWV0ZXIgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvclBhcmFtZXRlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIVFRQQXBpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm90b2NvbDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGhvc3ROYW1lOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NCYXNlVXJsOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZVVybFBhdGg6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdXNlR3ppcDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0VSUk9SX01FU1NBR0VfTEVOR1RIOm51bWJlciA9IDI1NjtcblxuICAgICAgICAgICAgLy8gSW5qZWN0ZWQgYnkgR2FtZUFuYWx5dGljcy5pbml0KCkuIEluLWZsaWdodCByZXF1ZXN0cyBhcmUgdHJhY2tlZCBzb1xuICAgICAgICAgICAgLy8gb25RdWl0KCkgY2FuIGF3YWl0IGRlbGl2ZXJ5OyBlYWNoIHByb21pc2Ugd3JhcHMgdGhlIHJlc3BvbnNlIENBTExCQUNLLFxuICAgICAgICAgICAgLy8gbm90IGp1c3QgdGhlIHRyYW5zcG9ydCwgYmVjYXVzZSB0aGUgY2FsbGJhY2sgbXV0YXRlcyB0aGUgc3RvcmUuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjbGllbnQ6SUdBSHR0cENsaWVudCA9IG51bGw7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBpbkZsaWdodDpBcnJheTxQcm9taXNlPHZvaWQ+PiA9IFtdO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldENsaWVudChjOklHQUh0dHBDbGllbnQpOiB2b2lkIHsgR0FIVFRQQXBpLmNsaWVudCA9IGM7IH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q2xpZW50KCk6IElHQUh0dHBDbGllbnQgeyByZXR1cm4gR0FIVFRQQXBpLmNsaWVudDsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbkZsaWdodENvdW50KCk6IG51bWJlciB7IHJldHVybiBHQUhUVFBBcGkuaW5GbGlnaHQubGVuZ3RoOyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHdoZW5JZGxlKCk6IFByb21pc2U8dm9pZD5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FIVFRQQXBpLmluRmxpZ2h0Lmxlbmd0aCA9PT0gMCkgeyByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7IH1cbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5hbGwoR0FIVFRQQXBpLmluRmxpZ2h0LnNsaWNlKCkpLnRoZW4oKCkgPT4gR0FIVFRQQXBpLndoZW5JZGxlKCkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgdHJhY2socDpQcm9taXNlPHZvaWQ+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbkZsaWdodC5wdXNoKHApO1xuICAgICAgICAgICAgICAgIHZhciBkb25lID0gKCkgPT4geyB2YXIgaSA9IEdBSFRUUEFwaS5pbkZsaWdodC5pbmRleE9mKHApOyBpZiAoaSA+PSAwKSB7IEdBSFRUUEFwaS5pbkZsaWdodC5zcGxpY2UoaSwgMSk7IH0gfTtcbiAgICAgICAgICAgICAgICBwLnRoZW4oZG9uZSwgZG9uZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGJhc2UgdXJsIHNldHRpbmdzXG4gICAgICAgICAgICAgICAgdGhpcy5wcm90b2NvbCA9IFwiaHR0cHNcIjtcbiAgICAgICAgICAgICAgICB0aGlzLmhvc3ROYW1lID0gXCJhcGkuZ2FtZWFuYWx5dGljcy5jb21cIjtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSBcInYyXCI7XG4gICAgICAgICAgICAgICAgdGhpcy5yZW1vdGVDb25maWdzVmVyc2lvbiA9IFwidjFcIjtcblxuICAgICAgICAgICAgICAgIC8vIGNyZWF0ZSBiYXNlIHVybFxuICAgICAgICAgICAgICAgIHRoaXMuYmFzZVVybCA9IHRoaXMucHJvdG9jb2wgKyBcIjovL1wiICsgdGhpcy5ob3N0TmFtZSArIFwiL1wiICsgdGhpcy52ZXJzaW9uO1xuICAgICAgICAgICAgICAgIHRoaXMucmVtb3RlQ29uZmlnc0Jhc2VVcmwgPSB0aGlzLnByb3RvY29sICsgXCI6Ly9cIiArIHRoaXMuaG9zdE5hbWUgKyBcIi9yZW1vdGVfY29uZmlncy9cIiArIHRoaXMucmVtb3RlQ29uZmlnc1ZlcnNpb247XG5cbiAgICAgICAgICAgICAgICB0aGlzLmluaXRpYWxpemVVcmxQYXRoID0gXCJpbml0XCI7XG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNVcmxQYXRoID0gXCJldmVudHNcIjtcblxuICAgICAgICAgICAgICAgIHRoaXMudXNlR3ppcCA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgcmVxdWVzdEluaXQoY29uZmlnc0hhc2g6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0pID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMucmVtb3RlQ29uZmlnc0Jhc2VVcmwgKyBcIi9cIiArIHRoaXMuaW5pdGlhbGl6ZVVybFBhdGggKyBcIj9nYW1lX2tleT1cIiArIGdhbWVLZXkgKyBcIiZpbnRlcnZhbF9zZWNvbmRzPTAmY29uZmlnc19oYXNoPVwiICsgY29uZmlnc0hhc2ggKyBcIiZjb25maWdfdnNuX3N1cHBvcnRlZD0zXCI7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2luaXQnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGluaXRBbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRJbml0QW5ub3RhdGlvbnMoKTtcblxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoaW5pdEFubm90YXRpb25zKTtcblxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQsIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZyA9IHRoaXMuY3JlYXRlUGF5bG9hZERhdGEoSlNPTnN0cmluZywgdGhpcy51c2VHemlwKTtcbiAgICAgICAgICAgICAgICB2YXIgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5pbml0UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZW5kRXZlbnRzSW5BcnJheShldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+LCByZXF1ZXN0SWQ6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGV2ZW50QXJyYXkubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZEV2ZW50c0luQXJyYXkgY2FsbGVkIHdpdGggbWlzc2luZyBldmVudEFycmF5XCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5ldmVudHNVcmxQYXRoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdldmVudHMnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBKU09OIHN0cmluZyBmcm9tIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldmVudEFycmF5KTtcblxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRFdmVudHNJbkFycmF5IEpTT04gZW5jb2RpbmcgZmFpbGVkIG9mIGV2ZW50QXJyYXlcIik7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50QXJyYXkubGVuZ3RoKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YSA9IHRoaXMuY3JlYXRlUGF5bG9hZERhdGEoSlNPTnN0cmluZywgdGhpcy51c2VHemlwKTtcbiAgICAgICAgICAgICAgICB2YXIgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChyZXF1ZXN0SWQpO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKGV2ZW50QXJyYXkubGVuZ3RoLnRvU3RyaW5nKCkpO1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5zZW5kUmVxdWVzdCh1cmwsIHBheWxvYWREYXRhLCBleHRyYUFyZ3MsIHRoaXMudXNlR3ppcCwgR0FIVFRQQXBpLnNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2ssIGNhbGxiYWNrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlbmRTZGtFcnJvckV2ZW50KGNhdGVnb3J5OkVHQVNka0Vycm9yQ2F0ZWdvcnksIGFyZWE6RUdBU2RrRXJyb3JBcmVhLCBhY3Rpb246RUdBU2RrRXJyb3JBY3Rpb24sIHBhcmFtZXRlcjpFR0FTZGtFcnJvclBhcmFtZXRlciwgcmVhc29uOnN0cmluZywgZ2FtZUtleTpzdHJpbmcsIHNlY3JldEtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5LCBzZWNyZXRLZXksIGNhdGVnb3J5LCBhcmVhLCBhY3Rpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmV2ZW50c1VybFBhdGg7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEpTT05TdHJpbmc6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgZXJyb3JUeXBlOnN0cmluZyA9IFwiXCJcblxuICAgICAgICAgICAgICAgIHZhciBqc29uOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGNhdGVnb3J5U3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvckNhdGVnb3J5U3RyaW5nKGNhdGVnb3J5KTtcbiAgICAgICAgICAgICAgICBqc29uW1wiZXJyb3JfY2F0ZWdvcnlcIl0gPSBjYXRlZ29yeVN0cmluZztcbiAgICAgICAgICAgICAgICBlcnJvclR5cGUgKz0gY2F0ZWdvcnlTdHJpbmc7XG5cbiAgICAgICAgICAgICAgICB2YXIgYXJlYVN0cmluZzpzdHJpbmcgPSBHQUhUVFBBcGkuc2RrRXJyb3JBcmVhU3RyaW5nKGFyZWEpO1xuICAgICAgICAgICAgICAgIGpzb25bXCJlcnJvcl9hcmVhXCJdID0gYXJlYVN0cmluZztcbiAgICAgICAgICAgICAgICBlcnJvclR5cGUgKz0gXCI6XCIgKyBhcmVhU3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgdmFyIGFjdGlvblN0cmluZzpzdHJpbmcgPSBHQUhUVFBBcGkuc2RrRXJyb3JBY3Rpb25TdHJpbmcoYWN0aW9uKTtcbiAgICAgICAgICAgICAgICBqc29uW1wiZXJyb3JfYWN0aW9uXCJdID0gYWN0aW9uU3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgdmFyIHBhcmFtZXRlclN0cmluZzpzdHJpbmcgPSBHQUhUVFBBcGkuc2RrRXJyb3JQYXJhbWV0ZXJTdHJpbmcocGFyYW1ldGVyKTtcbiAgICAgICAgICAgICAgICBpZihwYXJhbWV0ZXJTdHJpbmcubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGpzb25bXCJlcnJvcl9wYXJhbWV0ZXJcIl0gPSBwYXJhbWV0ZXJTdHJpbmc7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVhc29uLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcmVhc29uVHJpbW1lZCA9IHJlYXNvbjtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVhc29uLmxlbmd0aCA+IEdBSFRUUEFwaS5NQVhfRVJST1JfTUVTU0FHRV9MRU5HVEgpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZWFzb25UcmltbWVkID0gcmVhc29uLnN1YnN0cmluZygwLCBHQUhUVFBBcGkuTUFYX0VSUk9SX01FU1NBR0VfTEVOR1RIKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBqc29uW1wicmVhc29uXCJdID0gcmVhc29uVHJpbW1lZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgICAgIGV2ZW50QXJyYXkucHVzaChqc29uKTtcbiAgICAgICAgICAgICAgICBwYXlsb2FkSlNPTlN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2ZW50QXJyYXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXBheWxvYWRKU09OU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNlbmRTZGtFcnJvckV2ZW50OiBKU09OIGVuY29kaW5nIGZhaWxlZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZFNka0Vycm9yRXZlbnQganNvbjogXCIgKyBwYXlsb2FkSlNPTlN0cmluZyk7XG4gICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmV4ZWN1dGUodXJsLCBlcnJvclR5cGUsIHBheWxvYWRKU09OU3RyaW5nLCBzZWNyZXRLZXkpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrKHJlcXVlc3Q6R0FIdHRwUmVzcG9uc2VMaWtlLCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+ID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBleHRyYVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkOnN0cmluZyA9IGV4dHJhWzJdO1xuICAgICAgICAgICAgICAgIHZhciBldmVudENvdW50Om51bWJlciA9IHBhcnNlSW50KGV4dHJhWzNdKTtcbiAgICAgICAgICAgICAgICB2YXIgYm9keTpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIGJvZHkgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJldmVudHMgcmVxdWVzdCBjb250ZW50OiBcIiArIGJvZHkpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RSZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlID0gR0FIVFRQQXBpLmluc3RhbmNlLnByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlLCByZXF1ZXN0LnN0YXR1c1RleHQsIGJvZHksIFwiRXZlbnRzXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIGV2ZW50cyBDYWxsLiBVUkw6IFwiICsgdXJsICsgXCIsIEF1dGhvcml6YXRpb246IFwiICsgYXV0aG9yaXphdGlvbiArIFwiLCBKU09OU3RyaW5nOiBcIiArIEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gZGVjb2RlIEpTT05cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdEpzb25EaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSBib2R5ID8gSlNPTi5wYXJzZShib2R5KSA6IHt9O1xuXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdEpzb25EaWN0ID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkRlY29kZUZhaWxlZCwgbnVsbCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuSHR0cCwgRUdBU2RrRXJyb3JBcmVhLkV2ZW50c0h0dHAsIEVHQVNka0Vycm9yQWN0aW9uLkZhaWxIdHRwSnNvbkRlY29kZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBib2R5LCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgRXZlbnRzIENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyByZXR1cm4gcmVzcG9uc2VcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCByZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRSZXF1ZXN0KHVybDpzdHJpbmcsIHBheWxvYWREYXRhOnN0cmluZywgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4sIGd6aXA6Ym9vbGVhbiwgY2FsbGJhY2s6KHJlcXVlc3Q6R0FIdHRwUmVzcG9uc2VMaWtlLCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+KSA9PiB2b2lkLCBjYWxsYmFjazI6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBSFRUUEFwaS5jbGllbnQpIHsgR0FMb2dnZXIudyhcIk5vIEhUVFAgY2xpZW50IGNvbmZpZ3VyZWRcIik7IHJldHVybjsgfVxuXG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlIGF1dGhvcml6YXRpb24gaGFzaFxuICAgICAgICAgICAgICAgIHZhciBrZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCk7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gR0FVdGlsaXRpZXMuZ2V0SG1hYyhrZXksIHBheWxvYWREYXRhKTtcblxuICAgICAgICAgICAgICAgIHZhciBhcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBhcmdzLnB1c2goYXV0aG9yaXphdGlvbik7XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gZXh0cmFBcmdzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYXJncy5wdXNoKGV4dHJhQXJnc1tzXSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHA6UHJvbWlzZTx2b2lkPiA9IEdBSFRUUEFwaS5jbGllbnQuc2VuZFJlcXVlc3QodXJsLCBhdXRob3JpemF0aW9uLCBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUocGF5bG9hZERhdGEpLCBnemlwKVxuICAgICAgICAgICAgICAgICAgICAudGhlbigocjpHQUh0dHBSZXNwb25zZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gY29kZSAtMSBtYXBzIHRvIHN0YXR1cyAwLCB3aGljaCBpcyB3aGF0IFhNTEh0dHBSZXF1ZXN0IHJlcG9ydGVkIG9uIGFcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIG5ldHdvcmsgZmFpbHVyZSwgc28gcHJvY2Vzc1JlcXVlc3RSZXNwb25zZSBiZWhhdmVzIGV4YWN0bHkgYXMgYmVmb3JlLlxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxpa2U6R0FIdHRwUmVzcG9uc2VMaWtlID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXR1czogci5jb2RlIDwgMCA/IDAgOiByLmNvZGUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHVzVGV4dDogci5zdGF0dXNUZXh0IHx8IFwiXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzcG9uc2VUZXh0OiByLnBhY2tldCAmJiByLnBhY2tldC5sZW5ndGggPyBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoci5wYWNrZXQpIDogXCJcIlxuICAgICAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKGxpa2UsIHVybCwgY2FsbGJhY2syLCBhcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAgICAgLmNhdGNoKChlOmFueSkgPT4geyBHQUxvZ2dlci5lKFwiSFRUUCBjYWxsYmFjayBmYWlsZWQ6IFwiICsgKGUgJiYgZS5zdGFjayA/IGUuc3RhY2sgOiBlKSk7IH0pO1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS50cmFjayhwKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OkdBSHR0cFJlc3BvbnNlTGlrZSwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICAvLyBwcm9jZXNzIHRoZSByZXNwb25zZVxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJpbml0IHJlcXVlc3QgY29udGVudCA6IFwiICsgYm9keSArIFwiLCBKU09Oc3RyaW5nOiBcIiArIEpTT05zdHJpbmcpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJJbml0XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgSW5pdCBDYWxsLiBKc29uIGRlY29kaW5nIGZhaWxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5IdHRwLCBFR0FTZGtFcnJvckFyZWEuSW5pdEh0dHAsIEVHQVNka0Vycm9yQWN0aW9uLkZhaWxIdHRwSnNvbkRlY29kZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBib2R5LCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gQmFkIHJlcXVlc3QuIFJlc3BvbnNlOiBcIiArIEpTT04uc3RyaW5naWZ5KHJlcXVlc3RKc29uRGljdCkpO1xuICAgICAgICAgICAgICAgICAgICAvLyByZXR1cm4gYmFkIHJlcXVlc3QgcmVzdWx0XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgSW5pdCBjYWxsIHZhbHVlc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0ZWRJbml0VmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSBHQVZhbGlkYXRvci52YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShyZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RSZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkKTtcblxuICAgICAgICAgICAgICAgIGlmKCF2YWxpZGF0ZWRJbml0VmFsdWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGFsbCBva1xuICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIHZhbGlkYXRlZEluaXRWYWx1ZXMsIFwiXCIsIDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGNyZWF0ZVBheWxvYWREYXRhKHBheWxvYWQ6c3RyaW5nLCBnemlwOmJvb2xlYW4pOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGE6c3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgaWYoZ3ppcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIHBheWxvYWREYXRhID0gR0FVdGlsaXRpZXMuR3ppcENvbXByZXNzKHBheWxvYWQpO1xuICAgICAgICAgICAgICAgICAgICAvLyBHQUxvZ2dlci5EKFwiR3ppcCBzdGF0cy4gU2l6ZTogXCIgKyBFbmNvZGluZy5VVEY4LkdldEJ5dGVzKHBheWxvYWQpLkxlbmd0aCArIFwiLCBDb21wcmVzc2VkOiBcIiArIHBheWxvYWREYXRhLkxlbmd0aCArIFwiLCBDb250ZW50OiBcIiArIHBheWxvYWQpO1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJnemlwIG5vdCBzdXBwb3J0ZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHBheWxvYWREYXRhID0gcGF5bG9hZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZERhdGE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgcHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGU6bnVtYmVyLCByZXNwb25zZU1lc3NhZ2U6c3RyaW5nLCBib2R5OnN0cmluZywgcmVxdWVzdElkOnN0cmluZyk6IEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGlmIG5vIHJlc3VsdCAtIG9mdGVuIG5vIGNvbm5lY3Rpb25cbiAgICAgICAgICAgICAgICBpZighYm9keSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyByZXNwb25zZU1lc3NhZ2UgKyBcIiwgU3RhdHVzIGNvZGU6IFwiICsgcmVzcG9uc2VDb2RlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIG9rXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMjAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5PaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlZFxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDIwMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyA0MDEgY2FuIHJldHVybiAwIHN0YXR1c1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDAgfHwgcmVzcG9uc2VDb2RlID09PSA0MDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMSAtIFVuYXV0aG9yaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDQwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAwIC0gQmFkIFJlcXVlc3QuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3Q7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNTAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA1MDAgLSBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3IuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkludGVybmFsU2VydmVyRXJyb3I7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Vbmtub3duUmVzcG9uc2VDb2RlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckNhdGVnb3J5U3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQ2F0ZWdvcnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50X3ZhbGlkYXRpb25cIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkRhdGFiYXNlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkluaXQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JDYXRlZ29yeS5IdHRwOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQ2F0ZWdvcnkuSnNvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25cIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JBcmVhU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQXJlYSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5CdXNpbmVzc0V2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlc291cmNlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5EZXNpZ25FdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImRlc2lnblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuSW5pdEh0dHA6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0X2h0dHBcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuRXZlbnRzSHR0cDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50c19odHRwXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2Nlc3NFdmVudHM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9jZXNzX2V2ZW50c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5BZGRFdmVudHNUb1N0b3JlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYWRkX2V2ZW50c190b19zdG9yZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckFjdGlvblN0cmluZyh2YWx1ZTpFR0FTZGtFcnJvckFjdGlvbik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRDdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfY3VycmVuY3lcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU2hvcnRTdHJpbmc6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Nob3J0X3N0cmluZ1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGg6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfbGVuZ3RoXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfY2hhcmFjdGVyc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc3RvcmVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Zsb3dfdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic3RyaW5nX2VtcHR5X29yX251bGxcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Ob3RGb3VuZEluQXZhaWxhYmxlQ3VycmVuY2llczpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm5vdF9mb3VuZF9pbl9hdmFpbGFibGVfY3VycmVuY2llc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Ftb3VudFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLk5vdEZvdW5kSW5BdmFpbGFibGVJdGVtVHlwZXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJub3RfZm91bmRfaW5fYXZhaWxhYmxlX2l0ZW1fdHlwZXNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3cm9uZ19wcm9ncmVzc2lvbl9vcmRlclwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkTGVuZ3RoOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW52YWxpZF9ldmVudF9pZF9sZW5ndGhcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRJZENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X2lkX2NoYXJhY3RlcnNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkUHJvZ3Jlc3Npb25TdGF0dXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Byb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTZXZlcml0eTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkTG9uZ1N0cmluZzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfbG9uZ19zdHJpbmdcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5EYXRhYmFzZVRvb0xhcmdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJfdG9vX2xhcmdlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uRGF0YWJhc2VPcGVuT3JDcmVhdGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkYl9vcGVuX29yX2NyZWF0ZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkpzb25FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25fZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9kZWNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25FbmNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9lbmNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JQYXJhbWV0ZXJTdHJpbmcodmFsdWU6RUdBU2RrRXJyb3JQYXJhbWV0ZXIpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImN1cnJlbmN5XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ2FydFR5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjYXJ0X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1fdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1faWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5TdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInN0b3JlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmbG93X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5BbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJhbW91bnRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicHJvZ3Jlc3Npb24wMVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvbjAyXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uMDNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5FdmVudElkOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXZlbnRfaWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvblN0YXR1czpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlNldmVyaXR5OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5NZXNzYWdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwibWVzc2FnZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGhlYWx0aFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBIZWFsdGhTbmFwc2hvdFxuICAgICAgICB7XG4gICAgICAgICAgICBtZW1vcnlfdXNlZF9tYjogbnVtYmVyO1xuICAgICAgICAgICAgaGFyZHdhcmVfY29uY3VycmVuY3k6IG51bWJlcjtcbiAgICAgICAgICAgIHNjcmVlbl93aWR0aDogbnVtYmVyO1xuICAgICAgICAgICAgc2NyZWVuX2hlaWdodDogbnVtYmVyO1xuICAgICAgICAgICAgY3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBoYXJkd2FyZTogc3RyaW5nO1xuICAgICAgICAgICAgZ3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogc3RyaW5nO1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBSGVhbHRoXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEZQU19NQVg6IG51bWJlciA9IDEyMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1FTV9JTlRFUlZBTDogbnVtYmVyID0gNTAwMDtcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX2VuYWJsZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJhZklkOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbGFzdEZyYW1lVGltZTogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc0J1Y2tldHM6IG51bWJlcltdID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBmcmFtZUFjY3VtOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZnJhbWVDb3VudDogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc1RpbWVyOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtVGltZXI6IG51bWJlciA9IDA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBtZW1TeXNCdWNrZXRzOiBudW1iZXJbXSA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtQXBwQnVja2V0czogbnVtYmVyW10gPSBbXTtcblxuICAgICAgICAgICAgLy8gSW5qZWN0ZWQgYnkgR2FtZUFuYWx5dGljcy5pbml0KCksIG1pcnJvcmluZyBHQUhlYWx0aChHQVBsYXRmb3JtKikgaW4gQysrLlxuICAgICAgICAgICAgLy8gVGhlIGZpdmUgdmFsdWVzIEMrKyByZWFkcyBpbiBpdHMgY29uc3RydWN0b3IgYXJlIGNhY2hlZCBvbmNlIGhlcmU7XG4gICAgICAgICAgICAvLyBnZXRCb290VGltZS9nZXRBcHBNZW1vcnlVc2FnZS9nZXRTeXNNZW1vcnlVc2FnZSBzdGF5IGxpdmUgY2FsbHMuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwbGF0Zm9ybTogZ2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtID0gbnVsbDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIF9jcHVNb2RlbDogc3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIF9udW1Db3JlczogbnVtYmVyID0gLTE7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfaGFyZHdhcmU6IHN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfZ3B1TW9kZWw6IHN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfdG90YWxNZW1vcnk6IG51bWJlciA9IC0xO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX3NjcmVlblJlc29sdXRpb246IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFBsYXRmb3JtKHA6IGdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5wbGF0Zm9ybSA9IHA7XG4gICAgICAgICAgICAgICAgaWYgKHApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5fY3B1TW9kZWwgICAgPSBwLmdldENwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLl9udW1Db3JlcyAgICA9IHAuZ2V0TnVtQ3B1Q29yZXMoKTtcbiAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguX2hhcmR3YXJlICAgID0gcC5nZXREZXZpY2VNb2RlbCgpO1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5fZ3B1TW9kZWwgICAgPSBwLmdldEdwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLl90b3RhbE1lbW9yeSA9IHAuZ2V0VG90YWxEZXZpY2VNZW1vcnkoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKSB7fVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZXNldCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVBY2N1bSA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgPSAwO1xuICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyID0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2FtcGxlTWVtb3J5KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBSGVhbHRoLnBsYXRmb3JtKSB7IHJldHVybjsgfVxuICAgICAgICAgICAgICAgIHZhciB0b3RhbDogbnVtYmVyID0gR0FIZWFsdGguX3RvdGFsTWVtb3J5O1xuICAgICAgICAgICAgICAgIHZhciBhcHA6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtLmdldEFwcE1lbW9yeVVzYWdlKCk7XG4gICAgICAgICAgICAgICAgdmFyIHN5czogbnVtYmVyID0gR0FIZWFsdGgucGxhdGZvcm0uZ2V0U3lzTWVtb3J5VXNhZ2UoKTtcbiAgICAgICAgICAgICAgICBpZiAodG90YWwgPiAwICYmIHN5cyA+PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGgubWVtU3lzQnVja2V0c1tNYXRoLm1pbigxMDAsIE1hdGgubWF4KDAsIE1hdGgucm91bmQoc3lzIC8gdG90YWwgKiAxMDApKSldKys7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICh0b3RhbCA+IDAgJiYgYXBwID49IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzW01hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChhcHAgLyB0b3RhbCAqIDEwMCkpKV0rKztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEdwdU1vZGVsKCk6IHN0cmluZyB7IHJldHVybiBHQUhlYWx0aC5fZ3B1TW9kZWw7IH1cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEhhcmR3YXJlKCk6IHN0cmluZyB7IHJldHVybiBHQUhlYWx0aC5faGFyZHdhcmU7IH1cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldERldmljZU1lbW9yeUJ5dGVzKCk6IG51bWJlciB7IHJldHVybiBHQUhlYWx0aC5fdG90YWxNZW1vcnk7IH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0U2NyZWVuUmVzb2x1dGlvbigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGguX3NjcmVlblJlc29sdXRpb24gIT09IG51bGwpIHsgcmV0dXJuIEdBSGVhbHRoLl9zY3JlZW5SZXNvbHV0aW9uOyB9XG4gICAgICAgICAgICAgICAgdmFyIHc6IG51bWJlciA9ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4ud2lkdGggOiAtMTtcbiAgICAgICAgICAgICAgICB2YXIgaDogbnVtYmVyID0gKHR5cGVvZiBzY3JlZW4gIT09ICd1bmRlZmluZWQnKSA/IHNjcmVlbi5oZWlnaHQgOiAtMTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbiA9IHcgKyAneCcgKyBoO1xuICAgICAgICAgICAgICAgIHJldHVybiBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmUoZW5hYmxlZDogYm9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fZW5hYmxlZCA9IGVuYWJsZWQ7XG4gICAgICAgICAgICAgICAgaWYgKGVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5zdGFydFRyYWNraW5nKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnN0b3BUcmFja2luZygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnRUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiByZXF1ZXN0QW5pbWF0aW9uRnJhbWUgPT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJlc2V0KCk7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzQnVja2V0cyA9IG5ldyBBcnJheShHQUhlYWx0aC5GUFNfTUFYICsgMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1TeXNCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcpID8gcGVyZm9ybWFuY2Uubm93KCkgOiBEYXRlLm5vdygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpY2sgPSBmdW5jdGlvbihub3c6IG51bWJlcik6IHZvaWRcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FIZWFsdGguX2VuYWJsZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB2YXIgZGVsdGE6IG51bWJlciA9IG5vdyAtIEdBSGVhbHRoLmxhc3RGcmFtZVRpbWU7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkZWx0YSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLmZyYW1lQWNjdW0gKz0gMTAwMCAvIGRlbHRhO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCsrO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgKz0gZGVsdGE7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1UaW1lciArPSBkZWx0YTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKEdBSGVhbHRoLmZwc1RpbWVyID49IDEwMDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGF2Z0ZwczogbnVtYmVyID0gTWF0aC5taW4oR0FIZWFsdGguRlBTX01BWCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChHQUhlYWx0aC5mcmFtZUFjY3VtIC8gR0FIZWFsdGguZnJhbWVDb3VudCkpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNCdWNrZXRzW2F2Z0Zwc10rKztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUFjY3VtID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUNvdW50ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNUaW1lciAtPSAxMDAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGgubWVtVGltZXIgPj0gR0FIZWFsdGguTUVNX0lOVEVSVkFMKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnNhbXBsZU1lbW9yeSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyIC09IEdBSGVhbHRoLk1FTV9JTlRFUlZBTDtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gbm93O1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5yYWZJZCA9IHJlcXVlc3RBbmltYXRpb25GcmFtZSh0aWNrKTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgR0FIZWFsdGgucmFmSWQgPSByZXF1ZXN0QW5pbWF0aW9uRnJhbWUodGljayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3BUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBjYW5jZWxBbmltYXRpb25GcmFtZSAhPT0gJ3VuZGVmaW5lZCcgJiYgR0FIZWFsdGgucmFmSWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYW5jZWxBbmltYXRpb25GcmFtZShHQUhlYWx0aC5yYWZJZCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJhZklkID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U25hcHNob3QoKTogSGVhbHRoU25hcHNob3RcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXBwQnl0ZXM6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtID8gR0FIZWFsdGgucGxhdGZvcm0uZ2V0QXBwTWVtb3J5VXNhZ2UoKSA6IC0xO1xuICAgICAgICAgICAgICAgIHZhciBtZW1NYjogbnVtYmVyID0gYXBwQnl0ZXMgPj0gMCA/IE1hdGgucm91bmQoYXBwQnl0ZXMgLyAxMDQ4NTc2KSA6IC0xO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICAgICAgbWVtb3J5X3VzZWRfbWI6IG1lbU1iLFxuICAgICAgICAgICAgICAgICAgICBoYXJkd2FyZV9jb25jdXJyZW5jeTogR0FIZWFsdGguX251bUNvcmVzLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fd2lkdGg6ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4ud2lkdGggOiAtMSxcbiAgICAgICAgICAgICAgICAgICAgc2NyZWVuX2hlaWdodDogKHR5cGVvZiBzY3JlZW4gIT09ICd1bmRlZmluZWQnKSA/IHNjcmVlbi5oZWlnaHQgOiAtMSxcbiAgICAgICAgICAgICAgICAgICAgY3B1X21vZGVsOiBHQUhlYWx0aC5fY3B1TW9kZWwgfHwgJ3Vua25vd24nLFxuICAgICAgICAgICAgICAgICAgICBoYXJkd2FyZTogR0FIZWFsdGguZ2V0SGFyZHdhcmUoKSxcbiAgICAgICAgICAgICAgICAgICAgZ3B1X21vZGVsOiBHQUhlYWx0aC5nZXRHcHVNb2RlbCgpLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogR0FIZWFsdGguZ2V0U2NyZWVuUmVzb2x1dGlvbigpXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRIZWFsdGhBbm5vdGF0aW9ucyhvdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG91dFsnY3B1X21vZGVsJ10gPSBHQUhlYWx0aC5fY3B1TW9kZWwgfHwgJ3Vua25vd24nO1xuXG4gICAgICAgICAgICAgICAgb3V0WydoYXJkd2FyZSddID0gR0FIZWFsdGguZ2V0SGFyZHdhcmUoKSB8fCAndW5rbm93bic7XG5cbiAgICAgICAgICAgICAgICB2YXIgZ3B1TW9kZWw6IHN0cmluZyA9IEdBSGVhbHRoLmdldEdwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgaWYgKGdwdU1vZGVsKSB7IG91dFsnZ3B1X21vZGVsJ10gPSBncHVNb2RlbDsgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG51bUNvcmVzOiBudW1iZXIgPSBHQUhlYWx0aC5fbnVtQ29yZXM7XG4gICAgICAgICAgICAgICAgaWYgKG51bUNvcmVzID4gMCkgeyBvdXRbJ2NwdV9udW1fY29yZXMnXSA9IG51bUNvcmVzOyB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUGVyZm9ybWFuY2VEYXRhKG91dDoge1trZXk6IHN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgb3V0WydmcHNfZGF0YV90YWJsZSddID0gR0FIZWFsdGguZnBzQnVja2V0cy5zbGljZSgpO1xuXG4gICAgICAgICAgICAgICAgaWYgKEdBSGVhbHRoLmdldERldmljZU1lbW9yeUJ5dGVzKCkgPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgb3V0WydtZW1vcnlfc3lzX2RhdGFfdGFibGUnXSA9IEdBSGVhbHRoLm1lbVN5c0J1Y2tldHMuc2xpY2UoKTtcbiAgICAgICAgICAgICAgICAgICAgb3V0WydtZW1vcnlfYXBwX2RhdGFfdGFibGUnXSA9IEdBSGVhbHRoLm1lbUFwcEJ1Y2tldHMuc2xpY2UoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU0RLSW5pdERhdGEob3V0OiB7W2tleTogc3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYm9vdFRpbWU6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtID8gR0FIZWFsdGgucGxhdGZvcm0uZ2V0Qm9vdFRpbWUoKSA6IC0xO1xuICAgICAgICAgICAgICAgIGlmIChib290VGltZSA+IDApIHsgb3V0WydhcHBfYm9vdF90aW1lJ10gPSBib290VGltZTsgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBSGVhbHRoLl9lbmFibGVkO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGV2ZW50c1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgRUdBSFRUUEFwaVJlc3BvbnNlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcbiAgICAgICAgaW1wb3J0IEdBSFRUUEFwaSA9IGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGk7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IFZhbGlkYXRpb25SZXN1bHQgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuVmFsaWRhdGlvblJlc3VsdDtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FFdmVudHNcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ6c3RyaW5nID0gXCJ1c2VyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNlc3Npb25FbmQ6c3RyaW5nID0gXCJzZXNzaW9uX2VuZFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlEZXNpZ246c3RyaW5nID0gXCJkZXNpZ25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QnVzaW5lc3M6c3RyaW5nID0gXCJidXNpbmVzc1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlQcm9ncmVzc2lvbjpzdHJpbmcgPSBcInByb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVJlc291cmNlOnN0cmluZyA9IFwicmVzb3VyY2VcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RXJyb3I6c3RyaW5nID0gXCJlcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlBZHM6c3RyaW5nID0gXCJhZHNcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U0RLSW5pdDpzdHJpbmcgPSBcInNka19pbml0XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUhlYWx0aDpzdHJpbmcgPSBcImhlYWx0aFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4RXZlbnRDb3VudDpudW1iZXIgPSA1MDA7XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9FUlJPUl9DT1VOVDpudW1iZXIgPSAxMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGNvdW50TWFwOiB7IFtrZXk6IHN0cmluZ106IG51bWJlciB9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSB0aW1lc3RhbXBNYXA6IHsgW2tleTogc3RyaW5nXTogRGF0ZSB9ID0ge307XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHdhc1NES0luaXRFdmVudFNlbnQ6IGJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG5cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlOnN0cmluZywgbWVzc2FnZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbm93OiBEYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgICAgICAgICAgIGlmICghR0FFdmVudHMudGltZXN0YW1wTWFwW2Jhc2VNZXNzYWdlXSkge1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy50aW1lc3RhbXBNYXBbYmFzZU1lc3NhZ2VdID0gbm93O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBRXZlbnRzLmNvdW50TWFwW2Jhc2VNZXNzYWdlXSkge1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgZGlmZjogbnVtYmVyID0gbm93LmdldFRpbWUoKSAtIEdBRXZlbnRzLnRpbWVzdGFtcE1hcFtiYXNlTWVzc2FnZV0uZ2V0VGltZSgpO1xuICAgICAgICAgICAgICAgIHZhciBkaWZmU2Vjb25kczogbnVtYmVyID0gZGlmZiAvIDEwMDA7XG4gICAgICAgICAgICAgICAgaWYgKGRpZmZTZWNvbmRzID49IDM2MDApIHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudGltZXN0YW1wTWFwW2Jhc2VNZXNzYWdlXSA9IG5vdztcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID49IEdBRXZlbnRzLk1BWF9FUlJPUl9DT1VOVCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXJyb3JFdmVudChFR0FFcnJvclNldmVyaXR5Lldhcm5pbmcsIG1lc3NhZ2UsIG51bGwsIHRydWUpO1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gPSBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gKyAxO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25TdGFydEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydDtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBzZXNzaW9uIG51bWJlciAgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2Vzc2lvbk51bUtleSwgR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcztcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFNFU1NJT04gU1RBUlQgZXZlbnRcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIGV2ZW50IHJpZ2h0IGF3YXlcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0LCBmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU2Vzc2lvbkVuZEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbl9zdGFydF90czpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25MZW5ndGg6bnVtYmVyID0gY2xpZW50X3RzX2FkanVzdGVkIC0gc2Vzc2lvbl9zdGFydF90cztcblxuICAgICAgICAgICAgICAgIGlmKHNlc3Npb25MZW5ndGggPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gU2hvdWxkIG5ldmVyIGhhcHBlbi5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ291bGQgYmUgYmVjYXVzZSBvZiBlZGdlIGNhc2VzIHJlZ2FyZGluZyB0aW1lIGFsdGVyaW5nIG9uIGRldmljZS5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNlc3Npb24gbGVuZ3RoIHdhcyBjYWxjdWxhdGVkIHRvIGJlIGxlc3MgdGhlbiAwLiBTaG91bGQgbm90IGJlIHBvc3NpYmxlLiBSZXNldHRpbmcgdG8gMC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25MZW5ndGggPSAwO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEV2ZW50IHNwZWNpZmljIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvbkVuZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJsZW5ndGhcIl0gPSBzZXNzaW9uTGVuZ3RoO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM7XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBTRVNTSU9OIEVORCBldmVudC5cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIGFsbCBldmVudCByaWdodCBhd2F5XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCBmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU0RLSW5pdEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguaXNFbmFibGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRXZlbnRzLndhc1NES0luaXRFdmVudFNlbnQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHNkayBpbml0IG5lZWRzIHRvIGJlIHNlbnQgb25seSBvbmNlIG9uIGFwcCBvcGVuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLndhc1NES0luaXRFdmVudFNlbnQgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U0RLSW5pdDtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbk51bTpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiaXNfZmlyc3Rfc2RrX2luaXRcIl0gPSBzZXNzaW9uTnVtID09PSAxO1xuXG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZEhlYWx0aEFubm90YXRpb25zKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZFNES0luaXREYXRhKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkZWQgc2RrIGluaXQgZXZlbnRcIik7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiYWRkU0RLSW5pdEV2ZW50IC0gRXhjZXB0aW9uIHRocm93bjogXCIgKyBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkSGVhbHRoRXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlIZWFsdGg7XG5cbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguYWRkSGVhbHRoQW5ub3RhdGlvbnMoZXZlbnREaWN0KTtcbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguYWRkUGVyZm9ybWFuY2VEYXRhKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkZWQgaGVhbHRoIGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZEhlYWx0aEV2ZW50IC0gRXhjZXB0aW9uIHRocm93bjogXCIgKyBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZywgY2FydFR5cGU6c3RyaW5nID0gbnVsbCwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGNhcnRUeXBlLCBpdGVtVHlwZSwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCB0cmFuc2FjdGlvbiBudW1iZXIgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5LCBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBSZXF1aXJlZFxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QnVzaW5lc3M7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY3VycmVuY3lcIl0gPSBjdXJyZW5jeTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhbW91bnRcIl0gPSBhbW91bnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W0dBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXldID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gT3B0aW9uYWxcbiAgICAgICAgICAgICAgICBpZiAoY2FydFR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXJ0X3R5cGVcIl0gPSBjYXJ0VHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZihmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEJVU0lORVNTIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIiwgY2FydFR5cGU6XCIgKyBjYXJ0VHlwZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBtZXJnZUZpZWxkczpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0aW9uUmVzdWx0OlZhbGlkYXRpb25SZXN1bHQgPSBHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGUsIGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMoKSk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBJZiBmbG93IHR5cGUgaXMgc2luayByZXZlcnNlIGFtb3VudFxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50ICo9IC0xO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBldmVudCBzcGVjaWZpYyB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgZmxvd1R5cGVTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKGZsb3dUeXBlKTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGZsb3dUeXBlU3RyaW5nICsgXCI6XCIgKyBjdXJyZW5jeSArIFwiOlwiICsgaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UmVzb3VyY2U7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgaWYgKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKG1lcmdlRmllbGRzICYmIGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWZpZWxkc1RvVXNlW2tleV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBSRVNPVVJDRSBldmVudDoge2N1cnJlbmN5OlwiICsgY3VycmVuY3kgKyBcIiwgYW1vdW50OlwiICsgYW1vdW50ICsgXCIsIGl0ZW1UeXBlOlwiICsgaXRlbVR5cGUgKyBcIiwgaXRlbUlkOlwiICsgaXRlbUlkICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXM6RUdBUHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDE6c3RyaW5nLCBwcm9ncmVzc2lvbjAyOnN0cmluZywgcHJvZ3Jlc3Npb24wMzpzdHJpbmcsIHNjb3JlOm51bWJlciwgc2VuZFNjb3JlOmJvb2xlYW4sIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIG1lcmdlRmllbGRzOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHByb2dyZXNzaW9uU3RhdHVzU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLnByb2dyZXNzaW9uU3RhdHVzVG9TdHJpbmcocHJvZ3Jlc3Npb25TdGF0dXMpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRpb25SZXN1bHQ6VmFsaWRhdGlvblJlc3VsdCA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBQcm9ncmVzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgdmFyIHByb2dyZXNzaW9uSWRlbnRpZmllcjpzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBpZiAoIXByb2dyZXNzaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghcHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDEgKyBcIjpcIiArIHByb2dyZXNzaW9uMDI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDEgKyBcIjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIjpcIiArIHByb2dyZXNzaW9uMDM7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlQcm9ncmVzc2lvbjtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IHByb2dyZXNzaW9uU3RhdHVzU3RyaW5nICsgXCI6XCIgKyBwcm9ncmVzc2lvbklkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBBdHRlbXB0XG4gICAgICAgICAgICAgICAgdmFyIGF0dGVtcHRfbnVtOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgc2NvcmUgaWYgc3BlY2lmaWVkIGFuZCBzdGF0dXMgaXMgbm90IHN0YXJ0XG4gICAgICAgICAgICAgICAgaWYgKHNlbmRTY29yZSAmJiBwcm9ncmVzc2lvblN0YXR1cyAhPSBFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcInNjb3JlXCJdID0gTWF0aC5yb3VuZChzY29yZSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ291bnQgYXR0ZW1wdHMgb24gZWFjaCBwcm9ncmVzc2lvbiBmYWlsIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluY3JlbWVudCBhbmQgYWRkIGF0dGVtcHRfbnVtIG9uIGNvbXBsZXRlIGFuZCBkZWxldGUgcGVyc2lzdGVkXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5Db21wbGV0ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBhdHRlbXB0IG51bWJlclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gZXZlbnRcbiAgICAgICAgICAgICAgICAgICAgYXR0ZW1wdF9udW0gPSBHQVN0YXRlLmdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYXR0ZW1wdF9udW1cIl0gPSBhdHRlbXB0X251bTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDbGVhclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmNsZWFyUHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZXJnZUZpZWxkcyAmJiBmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUFJPR1JFU1NJT04gZXZlbnQ6IHtzdGF0dXM6XCIgKyBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiLCBwcm9ncmVzc2lvbjAxOlwiICsgcHJvZ3Jlc3Npb24wMSArIFwiLCBwcm9ncmVzc2lvbjAyOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiLCBwcm9ncmVzc2lvbjAzOlwiICsgcHJvZ3Jlc3Npb24wMyArIFwiLCBzY29yZTpcIiArIHNjb3JlICsgXCIsIGF0dGVtcHQ6XCIgKyBhdHRlbXB0X251bSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyLCBzZW5kVmFsdWU6Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0aW9uUmVzdWx0OlZhbGlkYXRpb25SZXN1bHQgPSBHQVZhbGlkYXRvci52YWxpZGF0ZURlc2lnbkV2ZW50KGV2ZW50SWQpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlEZXNpZ247XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiZXZlbnRfaWRcIl0gPSBldmVudElkO1xuXG4gICAgICAgICAgICAgICAgaWYoc2VuZFZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1widmFsdWVcIl0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gZmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERhdGEsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIERFU0lHTiBldmVudDoge2V2ZW50SWQ6XCIgKyBldmVudElkICsgXCIsIHZhbHVlOlwiICsgdmFsdWUgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5LCBtZXNzYWdlOnN0cmluZywgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbiwgc2tpcEFkZGluZ0ZpZWxkczpib29sZWFuPWZhbHNlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBzZXZlcml0eVN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5lcnJvclNldmVyaXR5VG9TdHJpbmcoc2V2ZXJpdHkpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5RXJyb3I7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wic2V2ZXJpdHlcIl0gPSBzZXZlcml0eVN0cmluZztcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJtZXNzYWdlXCJdID0gbWVzc2FnZTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICBpZighc2tpcEFkZGluZ0ZpZWxkcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgRVJST1IgZXZlbnQ6IHtzZXZlcml0eTpcIiArIHNldmVyaXR5U3RyaW5nICsgXCIsIG1lc3NhZ2U6XCIgKyBtZXNzYWdlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEFkRXZlbnQoYWRBY3Rpb246RUdBQWRBY3Rpb24sIGFkVHlwZTpFR0FBZFR5cGUsIGFkU2RrTmFtZTpzdHJpbmcsIGFkUGxhY2VtZW50OnN0cmluZywgbm9BZFJlYXNvbjpFR0FBZEVycm9yLCBkdXJhdGlvbjpudW1iZXIsIHNlbmREdXJhdGlvbjpib29sZWFuLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBtZXJnZUZpZWxkczpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBhZEFjdGlvblN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5hZEFjdGlvblRvU3RyaW5nKGFkQWN0aW9uKTtcbiAgICAgICAgICAgICAgICB2YXIgYWRUeXBlU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmFkVHlwZVRvU3RyaW5nKGFkVHlwZSk7XG4gICAgICAgICAgICAgICAgdmFyIG5vQWRSZWFzb25TdHJpbmc6c3RyaW5nID0gR0FFdmVudHMuYWRFcnJvclRvU3RyaW5nKG5vQWRSZWFzb24pO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlBZHM7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfc2RrX25hbWVcIl0gPSBhZFNka05hbWU7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfcGxhY2VtZW50XCJdID0gYWRQbGFjZW1lbnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfdHlwZVwiXSA9IGFkVHlwZVN0cmluZztcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJhZF9hY3Rpb25cIl0gPSBhZEFjdGlvblN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmKGFkQWN0aW9uID09IEVHQUFkQWN0aW9uLkZhaWxlZFNob3cgJiYgbm9BZFJlYXNvblN0cmluZy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfZmFpbF9zaG93X3JlYXNvblwiXSA9IG5vQWRSZWFzb25TdHJpbmc7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoc2VuZER1cmF0aW9uICYmIChhZFR5cGUgPT0gRUdBQWRUeXBlLlJld2FyZGVkVmlkZW8gfHwgYWRUeXBlID09IEVHQUFkVHlwZS5WaWRlbykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJhZF9kdXJhdGlvblwiXSA9IGR1cmF0aW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZXJnZUZpZWxkcyAmJiBmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGF0YSwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgQUQgZXZlbnQ6IHthZF9zZGtfbmFtZTpcIiArIGFkU2RrTmFtZSArIFwiLCBhZF9wbGFjZW1lbnQ6XCIgKyBhZFBsYWNlbWVudCArIFwiLCBhZF90eXBlOlwiICsgYWRUeXBlU3RyaW5nICsgXCIsIGFkX2FjdGlvbjpcIiArIGFkQWN0aW9uU3RyaW5nICsgKChhZEFjdGlvbiA9PSBFR0FBZEFjdGlvbi5GYWlsZWRTaG93ICYmIG5vQWRSZWFzb25TdHJpbmcubGVuZ3RoID4gMCkgPyAoXCIsIGFkX2ZhaWxfc2hvd19yZWFzb246XCIgKyBub0FkUmVhc29uU3RyaW5nKSA6IFwiXCIpICsgKChzZW5kRHVyYXRpb24gJiYgKGFkVHlwZSA9PSBFR0FBZFR5cGUuUmV3YXJkZWRWaWRlbyB8fCBhZFR5cGUgPT0gRUdBQWRUeXBlLlZpZGVvKSkgPyAoXCIsIGFkX2R1cmF0aW9uOlwiICsgZHVyYXRpb24pIDogXCJcIikgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcHJvY2Vzc0V2ZW50cyhjYXRlZ29yeTpzdHJpbmcsIHBlcmZvcm1DbGVhblVwOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdGhyb3cgbmV3IEVycm9yKFwicHJvY2Vzc0V2ZW50cyBub3QgaW1wbGVtZW50ZWRcIik7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkZW50aWZpZXI6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFudXBcbiAgICAgICAgICAgICAgICAgICAgaWYocGVyZm9ybUNsZWFuVXApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmNsZWFudXBFdmVudHMoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBQcmVwYXJlIFNRTFxuICAgICAgICAgICAgICAgICAgICB2YXIgc2VsZWN0QXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuICAgICAgICAgICAgICAgICAgICBpZihjYXRlZ29yeSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlU2V0QXJnczpBcnJheTxbc3RyaW5nLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVTZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIHJlcXVlc3RJZGVudGlmaWVyXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gR2V0IGV2ZW50cyB0byBwcm9jZXNzXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudHM6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGZvciBlcnJvcnMgb3IgZW1wdHlcbiAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cyB8fCBldmVudHMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogTm8gZXZlbnRzIHRvIHNlbmRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy51cGRhdGVTZXNzaW9uU3RvcmUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIG51bWJlciBvZiBldmVudHMgYW5kIHRha2Ugc29tZSBhY3Rpb24gaWYgdGhlcmUgYXJlIHRvbyBtYW55P1xuICAgICAgICAgICAgICAgICAgICBpZihldmVudHMubGVuZ3RoID4gR0FFdmVudHMuTWF4RXZlbnRDb3VudClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWFrZSBhIGxpbWl0IHJlcXVlc3RcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2ZW50cyA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncywgdHJ1ZSwgR0FFdmVudHMuTWF4RXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZighZXZlbnRzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gR2V0IGxhc3QgdGltZXN0YW1wXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdEl0ZW06e1trZXk6c3RyaW5nXTogYW55fSA9IGV2ZW50c1tldmVudHMubGVuZ3RoIC0gMV07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdFRpbWVzdGFtcDpzdHJpbmcgPSBsYXN0SXRlbVtcImNsaWVudF90c1wiXSBhcyBzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJjbGllbnRfdHNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWwsIGxhc3RUaW1lc3RhbXBdKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gU2VsZWN0IGFnYWluXG4gICAgICAgICAgICAgICAgICAgICAgICBldmVudHMgPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFldmVudHMpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJjbGllbnRfdHNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWwsIGxhc3RUaW1lc3RhbXBdKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IFNlbmRpbmcgXCIgKyBldmVudHMubGVuZ3RoICsgXCIgZXZlbnRzLlwiKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBTZXQgc3RhdHVzIG9mIGV2ZW50cyB0byAnc2VuZGluZycgKGFsc28gY2hlY2sgZm9yIGVycm9yKVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgdXBkYXRlU2V0QXJncywgdXBkYXRlV2hlcmVBcmdzKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIHBheWxvYWQgZGF0YSBmcm9tIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaTpudW1iZXIgPSAwOyBpIDwgZXZlbnRzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IGV2ZW50c1tpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldmVudERpY3QgPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KGV2W1wiZXZlbnRcIl0pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFdhcyBgZXZlbnREaWN0Lmxlbmd0aCAhPSAwYCwgd2hpY2ggb24gYSBzZXNzaW9uX2VuZCBldmVudCByZWFkXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBpdHMgb3duIGBsZW5ndGhgIChzZXNzaW9uIHNlY29uZHMpIGFuZCBzaWxlbnRseSBkcm9wcGVkIGFueVxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2Vzc2lvbiBzaG9ydGVyIHRoYW4gYSBzZWNvbmQg4oCUIHRoZSBjb21tb24gY2FzZSBoZWFkbGVzcy5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChldmVudERpY3QgJiYgdHlwZW9mIGV2ZW50RGljdCA9PT0gXCJvYmplY3RcIilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6IG51bWJlciA9IGV2ZW50RGljdFtcImNsaWVudF90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGNsaWVudFRzICYmICFHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzKSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBldmVudERpY3RbXCJjbGllbnRfdHNcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBheWxvYWRBcnJheS5wdXNoKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZEV2ZW50c0luQXJyYXkocGF5bG9hZEFycmF5LCByZXF1ZXN0SWRlbnRpZmllciwgR0FFdmVudHMucHJvY2Vzc0V2ZW50c0NhbGxiYWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3IgZHVyaW5nIFByb2Nlc3NFdmVudHMoKTogXCIgKyBlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuSnNvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2Nlc3NFdmVudHMsIEVHQVNka0Vycm9yQWN0aW9uLkpzb25FcnJvciwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBlLnN0YWNrLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcHJvY2Vzc0V2ZW50c0NhbGxiYWNrKHJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UsIGRhdGFEaWN0Ontba2V5OnN0cmluZ106IGFueX0sICByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkV2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgIHJlcXVlc3RJZFdoZXJlQXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgcmVxdWVzdElkXSk7XG5cbiAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5PaylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuRXZlbnRzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IFwiICsgZXZlbnRDb3VudCArIFwiIGV2ZW50cyBzZW50LlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gUHV0IGV2ZW50cyBiYWNrIChPbmx5IGluIGNhc2Ugb2Ygbm8gcmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzOkFycmF5PFtzdHJpbmcsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIFwibmV3XCJdKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMgdG8gY29sbGVjdG9yIC0gUmV0cnlpbmcgbmV4dCB0aW1lXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS51cGRhdGUoRUdBU3RvcmUuRXZlbnRzLCBzZXRBcmdzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gRGVsZXRlIGV2ZW50cyAoV2hlbiBnZXR0aW5nIHNvbWUgYW53c2VyIGJhY2sgYWx3YXlzIGFzc3VtZSBldmVudHMgYXJlIHByb2Nlc3NlZClcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGRhdGFEaWN0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBqc29uOmFueTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogaW4gZGF0YURpY3QpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBqc29uID0gZGF0YURpY3Rbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0ICYmIGpzb24uY29uc3RydWN0b3IgPT09IEFycmF5KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC4gXCIgKyBjb3VudCArIFwiIGV2ZW50cyBmYWlsZWQgR0Egc2VydmVyIHZhbGlkYXRpb24uXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuRXZlbnRzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjbGVhbnVwRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIFtbXCJzdGF0dXNcIiAsIFwibmV3XCJdXSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBHZXQgYWxsIHNlc3Npb25zIHRoYXQgYXJlIG5vdCBjdXJyZW50XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKFtcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWwsIEdBU3RhdGUuZ2V0U2Vzc2lvbklkKCldKTtcblxuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uczpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLlNlc3Npb25zLCBhcmdzKTtcblxuICAgICAgICAgICAgICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShzZXNzaW9ucy5sZW5ndGggKyBcIiBzZXNzaW9uKHMpIGxvY2F0ZWQgd2l0aCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50LlwiKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50c1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgc2Vzc2lvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkVuZEV2ZW50Ontba2V5OnN0cmluZ106IGFueX0gPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KHNlc3Npb25zW2ldW1wiZXZlbnRcIl0gYXMgc3RyaW5nKSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudF90czpudW1iZXIgPSBzZXNzaW9uRW5kRXZlbnRbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gc2Vzc2lvbnNbaV1bXCJ0aW1lc3RhbXBcIl0gYXMgbnVtYmVyO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBsZW5ndGg6bnVtYmVyID0gZXZlbnRfdHMgLSBzdGFydF90cztcbiAgICAgICAgICAgICAgICAgICAgbGVuZ3RoID0gTWF0aC5tYXgoMCwgbGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgICAgICBpZihsZW5ndGggPT09IG51bGwpXG4gICAgICAgICAgICAgICAgICAgICAgICBsZW5ndGggPSAwO1xuICAgICAgICAgICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzIGxlbmd0aCBjYWxjdWxhdGVkOiBcIiArIGxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkVuZEV2ZW50W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImxlbmd0aFwiXSA9IGxlbmd0aDtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKHNlc3Npb25FbmRFdmVudCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgd2UgYXJlIGluaXRpYWxpemVkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3QgYWRkIGV2ZW50OiBTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBkYiBzaXplIGxpbWl0cyAoMTBtYilcbiAgICAgICAgICAgICAgICAgICAgLy8gSWYgZGF0YWJhc2UgaXMgdG9vIGxhcmdlIGJsb2NrIGFsbCBleGNlcHQgdXNlciwgc2Vzc2lvbiBhbmQgYnVzaW5lc3NcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBU3RvcmUuaXNTdG9yZVRvb0xhcmdlRm9yRXZlbnRzKCkgJiYgIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdIGFzIHN0cmluZywgL14odXNlcnxzZXNzaW9uX2VuZHxidXNpbmVzcykkLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJEYXRhYmFzZSB0b28gbGFyZ2UuIEV2ZW50IGhhcyBiZWVuIGJsb2NrZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRGF0YWJhc2UsIEVHQVNka0Vycm9yQXJlYS5BZGRFdmVudHNUb1N0b3JlLCBFR0FTZGtFcnJvckFjdGlvbi5EYXRhYmFzZVRvb0xhcmdlLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIFwiXCIsIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZGVmYXVsdCBhbm5vdGF0aW9uc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIE1lcmdlIHdpdGggZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgZSBpbiBldmVudERhdGEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2W2VdID0gZXZlbnREYXRhW2VdO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gc3RyaW5nIHJlcHJlc2VudGF0aW9uXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2KTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBvdXRwdXQgaWYgVkVSQk9TRSBMT0cgZW5hYmxlZFxuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmlpKFwiRXZlbnQgYWRkZWQgdG8gcXVldWU6IFwiICsganNvbik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzdGF0dXNcIl0gPSBcIm5ld1wiO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjYXRlZ29yeVwiXSA9IGV2W1wiY2F0ZWdvcnlcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNsaWVudF90c1wiXSA9IGV2W1wiY2xpZW50X3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGV2KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuRXZlbnRzLCB2YWx1ZXMpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzZXNzaW9uIHN0b3JlIGlmIG5vdCBsYXN0XG4gICAgICAgICAgICAgICAgICAgIGlmIChldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9PSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlNlc3Npb25zLCBbW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgZXZbXCJzZXNzaW9uX2lkXCJdIGFzIHN0cmluZ11dKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLnVwZGF0ZVNlc3Npb25TdG9yZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zYXZlKEdBU3RhdGUuZ2V0R2FtZUtleSgpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRFdmVudFRvU3RvcmU6IGVycm9yXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5EYXRhYmFzZSwgRUdBU2RrRXJyb3JBcmVhLkFkZEV2ZW50c1RvU3RvcmUsIEVHQVNka0Vycm9yQWN0aW9uLkRhdGFiYXNlVG9vTGFyZ2UsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgZS5zdGFjaywgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHVwZGF0ZVNlc3Npb25TdG9yZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0aW1lc3RhbXBcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBldjogeyBba2V5OiBzdHJpbmddOiBhbnkgfSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldik7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcztcblxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuU2Vzc2lvbnMsIHZhbHVlcywgdHJ1ZSwgXCJzZXNzaW9uX2lkXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZShHQVN0YXRlLmdldEdhbWVLZXkoKSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBhZGQgdG8gZGljdCAoaWYgbm90IG5pbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMVwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAyXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDNcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSwgZmllbGRzOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fZmllbGRzXCJdID0gZmllbGRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU291cmNlIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5Tb3VyY2VdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU291cmNlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNpbmtcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0IHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlN0YXJ0XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29tcGxldGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiRmFpbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGVycm9yU2V2ZXJpdHlUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkRlYnVnIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5EZWJ1Z10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkZWJ1Z1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuSW5mbyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuSW5mb10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbmZvXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndhcm5pbmdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkVycm9yIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5FcnJvcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJlcnJvclwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuQ3JpdGljYWwgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImNyaXRpY2FsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRBY3Rpb25Ub1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FBZEFjdGlvbi5DbGlja2VkIHx8IHZhbHVlID09IEVHQUFkQWN0aW9uW0VHQUFkQWN0aW9uLkNsaWNrZWRdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiY2xpY2tlZFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkQWN0aW9uLlNob3cgfHwgdmFsdWUgPT0gRUdBQWRBY3Rpb25bRUdBQWRBY3Rpb24uU2hvd10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJzaG93XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRBY3Rpb24uRmFpbGVkU2hvdyB8fCB2YWx1ZSA9PSBFR0FBZEFjdGlvbltFR0FBZEFjdGlvbi5GYWlsZWRTaG93XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImZhaWxlZF9zaG93XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRBY3Rpb24uUmV3YXJkUmVjZWl2ZWQgfHwgdmFsdWUgPT0gRUdBQWRBY3Rpb25bRUdBQWRBY3Rpb24uUmV3YXJkUmVjZWl2ZWRdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmV3YXJkX3JlY2VpdmVkXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRFcnJvclRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuVW5rbm93biB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuVW5rbm93bl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ1bmtub3duXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRFcnJvci5PZmZsaW5lIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5PZmZsaW5lXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm9mZmxpbmVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLk5vRmlsbCB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuTm9GaWxsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm5vX2ZpbGxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLkludGVybmFsRXJyb3IgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLkludGVybmFsRXJyb3JdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW50ZXJuYWxfZXJyb3JcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLkludmFsaWRSZXF1ZXN0IHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5JbnZhbGlkUmVxdWVzdF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3JlcXVlc3RcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLlVuYWJsZVRvUHJlY2FjaGUgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLlVuYWJsZVRvUHJlY2FjaGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwidW5hYmxlX3RvX3ByZWNhY2hlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRUeXBlVG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBQWRUeXBlLlZpZGVvIHx8IHZhbHVlID09IEVHQUFkVHlwZVtFR0FBZFR5cGUuVmlkZW9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwidmlkZW9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuUmV3YXJkZWRWaWRlbyB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLlJld2FyZGVkVmlkZW9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmV3YXJkZWRfdmlkZW9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuUGxheWFibGUgfHwgdmFsdWUgPT0gRUdBQWRUeXBlW0VHQUFkVHlwZS5QbGF5YWJsZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwbGF5YWJsZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkVHlwZS5JbnRlcnN0aXRpYWwgfHwgdmFsdWUgPT0gRUdBQWRUeXBlW0VHQUFkVHlwZS5JbnRlcnN0aXRpYWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW50ZXJzdGl0aWFsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRUeXBlLk9mZmVyV2FsbCB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLk9mZmVyV2FsbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJvZmZlcl93YWxsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRUeXBlLkJhbm5lciB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLkJhbm5lcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJiYW5uZXJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVGhyZWFkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBVGhyZWFkaW5nID0gbmV3IEdBVGhyZWFkaW5nKCk7XG4gICAgICAgICAgICBwcml2YXRlIHJlYWRvbmx5IHRhc2tRdWV1ZTpBcnJheTwoKSA9PiB2b2lkPiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZXZlbnRJbnRlcnZhbElkOlJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHB1bXBJZDpSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD47XG5cbiAgICAgICAgICAgIC8vIEluIE5vZGUsIGFuIGFjdGl2ZSBpbnRlcnZhbCBrZWVwcyB0aGUgcHJvY2VzcyBhbGl2ZTsgdW5yZWYoKSBsZXRzIGl0IGV4aXRcbiAgICAgICAgICAgIC8vIG5hdHVyYWxseSBvbmNlIHRoZSBhcHBsaWNhdGlvbiBpcyBkb25lLiBOby1vcCBpbiB0aGUgYnJvd3Nlci5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHVucmVmKHQ6YW55KTogdm9pZCB7IGlmICh0ICYmIHR5cGVvZiB0LnVucmVmID09PSAnZnVuY3Rpb24nKSB7IHQudW5yZWYoKTsgfSB9XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBQcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyID0gOC4wO1xuICAgICAgICAgICAgcHJpdmF0ZSBpc1J1bm5pbmc6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wdW1wSWQgPSBzZXRJbnRlcnZhbChHQVRocmVhZGluZy5ydW4sIDEwMCk7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcudW5yZWYoR0FUaHJlYWRpbmcucHVtcElkKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gUnVuIGV2ZXJ5IHF1ZXVlZCB0YXNrIG5vdy4gb25RdWl0KCkgdXNlcyB0aGlzIGluc3RlYWQgb2Ygd2FpdGluZyBmb3IgdGhlXG4gICAgICAgICAgICAvLyAxMDAgbXMgdGljazsgdGhlIEMrKyBidXN5LXdhaXQgY2Fubm90IGJlIHBvcnRlZCAoc3BlYywgXCJub3QgaXRzIHNwaW5cIikuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGZsdXNoKCk6IHZvaWQgeyBHQVRocmVhZGluZy5ydW4oKTsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZW5kaW5nVGFza0NvdW50KCk6IG51bWJlciB7IHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS50YXNrUXVldWUubGVuZ3RoOyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0b3BQdW1wKCk6IHZvaWQgeyBjbGVhckludGVydmFsKEdBVGhyZWFkaW5nLnB1bXBJZCk7IH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGFza09uR0FUaHJlYWQodGFza0Jsb2NrOigpID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UudGFza1F1ZXVlLnB1c2godGFza0Jsb2NrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmV2ZW50SW50ZXJ2YWxJZCA9IHNldEludGVydmFsKFxuICAgICAgICAgICAgICAgICAgICAgICAgKCkgPT4gR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKEdBVGhyZWFkaW5nLnByb2Nlc3NFdmVudFF1ZXVlKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcyAqIDEwMDBcbiAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcudW5yZWYoR0FUaHJlYWRpbmcuZXZlbnRJbnRlcnZhbElkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkVuZGluZyBzZXNzaW9uLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaXNFbmFibGVkKCkgJiYgR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEhlYWx0aEV2ZW50KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uRW5kRXZlbnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdG9wRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgY2xlYXJJbnRlcnZhbChHQVRocmVhZGluZy5ldmVudEludGVydmFsSWQpO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV2ZW50UHJvY2Vzc0ludGVydmFsKGludGVydmFsOm51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoaW50ZXJ2YWwgPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzID0gaW50ZXJ2YWw7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBydW4oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHdoaWxlIChHQVRocmVhZGluZy5pbnN0YW5jZS50YXNrUXVldWUubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnN0IHRhc2sgPSBHQVRocmVhZGluZy5pbnN0YW5jZS50YXNrUXVldWUuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRhc2spXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRyeSB7IHRhc2soKTsgfVxuICAgICAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGU6IGFueSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3Igb24gR0EgdGhyZWFkXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudFF1ZXVlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiUHJvY2Vzc2luZyBldmVudCBxdWV1ZS4uLlwiKTtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIHRydWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBpbXBvcnQgR0FUaHJlYWRpbmcgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5HQVRocmVhZGluZztcbiAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgaW1wb3J0IEdBSFRUUEFwaSA9IGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGk7XG4gICAgaW1wb3J0IEdBRGV2aWNlID0gZ2FtZWFuYWx5dGljcy5kZXZpY2UuR0FEZXZpY2U7XG4gICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgIGltcG9ydCBFR0FIVFRQQXBpUmVzcG9uc2UgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBSFRUUEFwaVJlc3BvbnNlO1xuICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgIGltcG9ydCBHQUV2ZW50cyA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkdBRXZlbnRzO1xuICAgIGltcG9ydCBHQUhlYWx0aCA9IGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoO1xuXG4gICAgZXhwb3J0IGNsYXNzIEdhbWVBbmFseXRpY3NcbiAgICB7XG5wdWJsaWMgc3RhdGljIG1ldGhvZE1hcDp7W2lkOnN0cmluZ106ICguLi5hcmdzOiBhbnlbXSkgPT4gdm9pZH0gPSB7fTtcblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRHbG9iYWxPYmplY3QoKTogYW55XG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgZ2xvYmFsVGhpcyAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIGdsb2JhbFRoaXM7IH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygc2VsZiAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIHNlbGY7IH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJykgeyByZXR1cm4gd2luZG93OyB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIGdsb2JhbCAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIGdsb2JhbDsgfVxuICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgaW5pdCgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIEJ1aWxkLXRpbWUgcGxhdGZvcm0gc2VsZWN0aW9uLCB0aGUgSlMgYW5hbG9ndWUgb2YgQysrIE1ha2VQbGF0Zm9ybSgpLlxuICAgICAgICAgICAgLy8gR0FEZXZpY2Ugb3ducyBpdDsgR0FIZWFsdGggY2FjaGVzIGl0cyBmaXZlIGNvbnN0cnVjdG9yLXRpbWUgcmVhZHMuXG4gICAgICAgICAgICB2YXIgcGxhdGZvcm06Z2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtID0gZ2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5tYWtlUGxhdGZvcm0oKTtcbiAgICAgICAgICAgIEdBRGV2aWNlLnNldFBsYXRmb3JtKHBsYXRmb3JtKTtcbiAgICAgICAgICAgIEdBSGVhbHRoLnNldFBsYXRmb3JtKHBsYXRmb3JtKTtcbiAgICAgICAgICAgIEdBU3RvcmUuc2V0U3RvcmFnZShnYW1lYW5hbHl0aWNzLnN0b3JhZ2UubWFrZVN0b3JhZ2UoKSk7XG4gICAgICAgICAgICBHQUhUVFBBcGkuc2V0Q2xpZW50KGdhbWVhbmFseXRpY3MuaHR0cC5tYWtlSHR0cENsaWVudCgpKTtcbiAgICAgICAgICAgIEdBRGV2aWNlLnRvdWNoKCk7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDInXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVCdWlsZCddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVCdWlsZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVVc2VySWQnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlVXNlcklkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2dldFVzZXJJZCddID0gR2FtZUFuYWx5dGljcy5nZXRVc2VySWQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXh0VXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLnNldEV4dFVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRFeHRVc2VySWQnXSA9IEdhbWVBbmFseXRpY3MuZ2V0RXh0VXNlcklkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2luaXRpYWxpemUnXSA9IEdhbWVBbmFseXRpY3MuaW5pdGlhbGl6ZTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRCdXNpbmVzc0V2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEJ1c2luZXNzRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkUmVzb3VyY2VFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRSZXNvdXJjZUV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFByb2dyZXNzaW9uRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkUHJvZ3Jlc3Npb25FdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGREZXNpZ25FdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGREZXNpZ25FdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRFcnJvckV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEVycm9yRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkQWRFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRBZEV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRJbmZvTG9nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRJbmZvTG9nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRWZXJib3NlTG9nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRWZXJib3NlTG9nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZW5hYmxlSGVhbHRoRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuZW5hYmxlSGVhbHRoRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDEnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDInXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDMnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMnXSA9IEdhbWVBbmFseXRpY3Muc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwnXSA9IEdhbWVBbmFseXRpY3Muc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWw7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc3RhcnRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnN0YXJ0U2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydlbmRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmVuZFNlc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnb25TdG9wJ10gPSBHYW1lQW5hbHl0aWNzLm9uU3RvcDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblJlc3VtZSddID0gR2FtZUFuYWx5dGljcy5vblJlc3VtZTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRSZW1vdGVDb25maWdzTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MuYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3JlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5yZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmcnXSA9IEdhbWVBbmFseXRpY3MuZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNKU09OJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzSlNPTjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpc1JlbW90ZUNvbmZpZ3NSZWFkeSddID0gR2FtZUFuYWx5dGljcy5pc1JlbW90ZUNvbmZpZ3NSZWFkeTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5hZGRPbkJlZm9yZVVubG9hZExpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3JlbW92ZU9uQmVmb3JlVW5sb2FkTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MucmVtb3ZlT25CZWZvcmVVbmxvYWRMaXN0ZW5lcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkRXJyb3JSZXBvcnRpbmcnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZEVycm9yUmVwb3J0aW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ29uUXVpdCddID0gR2FtZUFuYWx5dGljcy5vblF1aXQ7XG4gICAgICAgICAgICBcblxuICAgICAgICAgICAgaWYgKHR5cGVvZiBHYW1lQW5hbHl0aWNzLmdldEdsb2JhbE9iamVjdCgpICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddWydxJ10gIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBxOiBhbnlbXSA9IEdhbWVBbmFseXRpY3MuZ2V0R2xvYmFsT2JqZWN0KClbJ0dhbWVBbmFseXRpY3MnXVsncSddO1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgaW4gcSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuZ2FDb21tYW5kLmFwcGx5KG51bGwsIHFbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuXG4gICAgICAgICAgICAvLyBQbGF0Zm9ybSBob29rczogYmVmb3JldW5sb2FkIGluIHRoZSBicm93c2VyLCBiZWZvcmVFeGl0ICsgdGhlXG4gICAgICAgICAgICAvLyB1bmNhdWdodC1leGNlcHRpb24gbW9uaXRvciBpbiBOb2RlLiBCb3RoIGxpdmUgaW4gdGhlIHBsYXRmb3JtIG5vdy5cbiAgICAgICAgICAgIHBsYXRmb3JtLm9uSW5pdCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnYUNvbW1hbmQoLi4uYXJnczogYW55W10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKGFyZ3MubGVuZ3RoID4gMClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihhcmdzWzBdIGluIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihhcmdzLmxlbmd0aCA+IDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbYXJnc1swXV0uYXBwbHkobnVsbCwgQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJncywgMSkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFthcmdzWzBdXSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGl0ZW0gdHlwZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVCdWlsZChidWlsZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJCdWlsZCB2ZXJzaW9uIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdWlsZChidWlsZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGJ1aWxkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgMzIgbGVuZ3RoLiBTdHJpbmc6IFwiICsgYnVpbGQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QnVpbGQoYnVpbGQpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2RrV3JhcHBlclZlcnNpb24oc2RrR2FtZUVuZ2luZVZlcnNpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBzZGsgdmVyc2lvbjogU2RrIHZlcnNpb24gbm90IHN1cHBvcnRlZC4gU3RyaW5nOiBcIiArIHNka0dhbWVFbmdpbmVWZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbiA9IHNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uKGdhbWVFbmdpbmVWZXJzaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGdhbWUgZW5naW5lIHZlcnNpb246IEdhbWUgZW5naW5lIHZlcnNpb24gbm90IHN1cHBvcnRlZC4gU3RyaW5nOiBcIiArIGdhbWVFbmdpbmVWZXJzaW9uKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbiA9IGdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVVzZXJJZCh1SWQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQSBjdXN0b20gdXNlciBpZCBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlVXNlcklkKHVJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHVzZXJfaWQ6IENhbm5vdCBiZSBudWxsLCBlbXB0eSBvciBhYm92ZSA2NCBsZW5ndGguIFdpbGwgdXNlIGRlZmF1bHQgdXNlcl9pZCBtZXRob2QuIFVzZWQgc3RyaW5nOiBcIiArIHVJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldFVzZXJJZCh1SWQpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV4dFVzZXJJZCh1SWQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRFeHRVc2VySWQodUlkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRFeHRVc2VySWQoKTogc3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldEV4dFVzZXJJZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRVc2VySWQoKSA6IHN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGluaXRpYWxpemUoZ2FtZUtleTpzdHJpbmcgPSBcIlwiLCBnYW1lU2VjcmV0OnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNESyBhbHJlYWR5IGluaXRpYWxpemVkLiBDYW4gb25seSBiZSBjYWxsZWQgb25jZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGZhaWxlZCBpbml0aWFsaXplLiBHYW1lIGtleSBvciBzZWNyZXQga2V5IGlzIGludmFsaWQuIENhbiBvbmx5IGNvbnRhaW4gY2hhcmFjdGVycyBBLXogMC05LCBnYW1lS2V5IGlzIDMyIGxlbmd0aCwgZ2FtZVNlY3JldCBpcyA0MCBsZW5ndGguIEZhaWxlZCBrZXlzIC0gZ2FtZUtleTogXCIgKyBnYW1lS2V5ICsgXCIsIHNlY3JldEtleTogXCIgKyBnYW1lU2VjcmV0KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0S2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KTtcblxuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW50ZXJuYWxJbml0aWFsaXplKCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIsIGNhcnRUeXBlOnN0cmluZyA9IFwiXCIsIGN1c3RvbUZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZighR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgY2FydFR5cGUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUgPSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZCwgY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiLCBjdXN0b21GaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30sIG1lcmdlRmllbGRzOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHJlc291cmNlIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czogRUdBUHJvZ3Jlc3Npb25TdGF0dXMgPSBFR0FQcm9ncmVzc2lvblN0YXR1cy5VbmRlZmluZWQsIHByb2dyZXNzaW9uMDE6IHN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDI6IHN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDM6IHN0cmluZyA9IFwiXCIsIHNjb3JlPzogbnVtYmVyLCBjdXN0b21GaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9LCBtZXJnZUZpZWxkczogYm9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHByb2dyZXNzaW9uIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOiBib29sZWFuID0gdHlwZW9mIHNjb3JlID09PSBcIm51bWJlclwiO1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzLCBzZW5kU2NvcmUgPyBzY29yZSA6IDAsIHNlbmRTY29yZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHByb2dyZXNzaW9uIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgIHZhciBzZW5kU2NvcmU6IGJvb2xlYW4gPSB0eXBlb2Ygc2NvcmUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMywgc2VuZFNjb3JlID8gc2NvcmUgOiAwLCBzZW5kU2NvcmUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOiBzdHJpbmcsIHZhbHVlPzogbnVtYmVyLCBjdXN0b21GaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9LCBtZXJnZUZpZWxkczogYm9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZW5kVmFsdWU6IGJvb2xlYW4gPSB0eXBlb2YgdmFsdWUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERlc2lnbkV2ZW50KGV2ZW50SWQsIHNlbmRWYWx1ZSA/IHZhbHVlIDogMCwgc2VuZFZhbHVlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgZGVzaWduIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIHNlbmRWYWx1ZTogYm9vbGVhbiA9IHR5cGVvZiB2YWx1ZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREZXNpZ25FdmVudChldmVudElkLCBzZW5kVmFsdWUgPyB2YWx1ZSA6IDAsIHNlbmRWYWx1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6IEVHQUVycm9yU2V2ZXJpdHkgPSBFR0FFcnJvclNldmVyaXR5LlVuZGVmaW5lZCwgbWVzc2FnZTogc3RyaW5nID0gXCJcIiwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEVycm9yRXZlbnQoc2V2ZXJpdHksIG1lc3NhZ2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEVycm9yRXZlbnQoc2V2ZXJpdHksIG1lc3NhZ2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50V2l0aE5vQWRSZWFzb24oYWRBY3Rpb246IEVHQUFkQWN0aW9uID0gRUdBQWRBY3Rpb24uVW5kZWZpbmVkLCBhZFR5cGU6IEVHQUFkVHlwZSA9IEVHQUFkVHlwZS5VbmRlZmluZWQsIGFkU2RrTmFtZTogc3RyaW5nID0gXCJcIiwgYWRQbGFjZW1lbnQ6IHN0cmluZyA9IFwiXCIsIG5vQWRSZWFzb246IEVHQUFkRXJyb3IgPSBFR0FBZEVycm9yLlVuZGVmaW5lZCwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgbm9BZFJlYXNvbiwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgbm9BZFJlYXNvbiwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50V2l0aER1cmF0aW9uKGFkQWN0aW9uOiBFR0FBZEFjdGlvbiA9IEVHQUFkQWN0aW9uLlVuZGVmaW5lZCwgYWRUeXBlOiBFR0FBZFR5cGUgPSBFR0FBZFR5cGUuVW5kZWZpbmVkLCBhZFNka05hbWU6IHN0cmluZyA9IFwiXCIsIGFkUGxhY2VtZW50OiBzdHJpbmcgPSBcIlwiLCBkdXJhdGlvbjogbnVtYmVyID0gMCwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgRUdBQWRFcnJvci5VbmRlZmluZWQsIGR1cmF0aW9uLCB0cnVlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIEVHQUFkRXJyb3IuVW5kZWZpbmVkLCBkdXJhdGlvbiwgdHJ1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEFkRXZlbnQoYWRBY3Rpb246IEVHQUFkQWN0aW9uID0gRUdBQWRBY3Rpb24uVW5kZWZpbmVkLCBhZFR5cGU6IEVHQUFkVHlwZSA9IEVHQUFkVHlwZS5VbmRlZmluZWQsIGFkU2RrTmFtZTogc3RyaW5nID0gXCJcIiwgYWRQbGFjZW1lbnQ6IHN0cmluZyA9IFwiXCIsIGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30sIG1lcmdlRmllbGRzOiBib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIEVHQUFkRXJyb3IuVW5kZWZpbmVkLCAwLCBmYWxzZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGFkIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQWRFdmVudChhZEFjdGlvbiwgYWRUeXBlLCBhZFNka05hbWUsIGFkUGxhY2VtZW50LCBFR0FBZEVycm9yLlVuZGVmaW5lZCwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkSW5mb0xvZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRJbmZvTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5mbyBsb2dnaW5nIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbmZvIGxvZ2dpbmcgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldEluZm9Mb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRWZXJib3NlTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZlcmJvc2UgbG9nZ2luZyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0VmVyYm9zZUxvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBzdWJtaXNzaW9uIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBzdWJtaXNzaW9uIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGVuYWJsZUhlYWx0aEV2ZW50KGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5jb25maWd1cmUoZmxhZyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMoY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBnbG9iYWwgY3VzdG9tIGV2ZW50IGZpZWxkczogXCIgKyBKU09OLnN0cmluZ2lmeShjdXN0b21GaWVsZHMpKTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcyA9IGN1c3RvbUZpZWxkcztcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbEluU2Vjb25kczpudW1iZXIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNldEV2ZW50UHJvY2Vzc0ludGVydmFsKGludGVydmFsSW5TZWNvbmRzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzdGFydFNlc3Npb24oKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvL2lmKEdBU3RhdGUuZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5yZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy9pZihHQVN0YXRlLmdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3Mub25TdG9wKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uU3RvcCgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoRXhjZXB0aW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQb3J0IG9mIEdhbWVBbmFseXRpY3M6OnNldEVuYWJsZWRFcnJvclJlcG9ydGluZyAoR2FtZUFuYWx5dGljcy5oOjEwNSkuXG4gICAgICAgICAqIE9mZiBieSBkZWZhdWx0IChzcGVjLCBkaXZlcmdlbmNlIDQpLiBTZXQgc3luY2hyb25vdXNseSByYXRoZXIgdGhhbiBvbiB0aGVcbiAgICAgICAgICogdGFzayBxdWV1ZSBzbyBhIGNyYXNoIHRoYXQgZm9sbG93cyBpbW1lZGlhdGVseSBpcyBzdGlsbCByZXBvcnRlZC5cbiAgICAgICAgICovXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEVycm9yUmVwb3J0aW5nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLnNldEVuYWJsZUVycm9yUmVwb3J0aW5nKGZsYWcpO1xuICAgICAgICB9XG5cbiAgICAgICAgLyoqXG4gICAgICAgICAqIFBvcnQgb2YgR2FtZUFuYWx5dGljczo6b25RdWl0IChHYW1lQW5hbHl0aWNzLmg6MTQ5KSDigJQgUkVRVUlSRUQgaW4gaGVhZGxlc3NcbiAgICAgICAgICogYmVmb3JlIHRoZSBwcm9jZXNzIGV4aXRzLiBSZXNvbHZlcyBvbmNlIHRoZSBxdWV1ZSBoYXMgZHJhaW5lZCBhbmQgdGhlXG4gICAgICAgICAqIHNlc3Npb24gY2FjaGUgZmlsZSBpcyBkZWxldGVkLiBOZXZlciBidXN5LXdhaXRzOiB0aGVyZSBpcyBvbmUgdGhyZWFkLlxuICAgICAgICAgKlxuICAgICAgICAgKiBPcmRlciBtYXR0ZXJzOiBhIHF1ZXVlZCBpbml0aWFsaXplKCkgc3RhcnRzIGl0cyBzZXNzaW9uIG9ubHkgaW5zaWRlIHRoZVxuICAgICAgICAgKiBhc3luYyBpbml0IGNhbGxiYWNrLCBzbyBzZXR0bGUgdGhhdCBmaXJzdCwgdGhlbiBlbmQgdGhlIHNlc3Npb24sIHRoZW5cbiAgICAgICAgICogc2V0dGxlIHRoZSBzZXNzaW9uX2VuZCBzZW5kLlxuICAgICAgICAgKi9cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcXVpdFByb21pc2U6UHJvbWlzZTx2b2lkPiA9IG51bGw7XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblF1aXQoKTogUHJvbWlzZTx2b2lkPlxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBPbmUtc2hvdCwgbGlrZSBDKysncyBgaWYoX2VuZFRocmVhZCkgcmV0dXJuO2A6IGFuIGV4cGxpY2l0IGNhbGwgYW5kIHRoZVxuICAgICAgICAgICAgLy8gcGxhdGZvcm0ncyBiZWZvcmVFeGl0IGhhbmRsZXIgbXVzdCBub3QgZHJhaW4gdHdpY2UuXG4gICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5xdWl0UHJvbWlzZSkgeyByZXR1cm4gR2FtZUFuYWx5dGljcy5xdWl0UHJvbWlzZTsgfVxuICAgICAgICAgICAgcmV0dXJuIEdhbWVBbmFseXRpY3MucXVpdFByb21pc2UgPSBHYW1lQW5hbHl0aWNzLnNldHRsZSgxMClcbiAgICAgICAgICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFRoZSA4IHMgdGljayBpcyB0aGUgb25seSBjYWxsZXIgb2YgcHJvY2Vzc0V2ZW50cyB3aXRoIGNsZWFudXAsIHdoaWNoXG4gICAgICAgICAgICAgICAgICAgIC8vIGlzIHdoYXQgc3ludGhlc2lzZXMgc2Vzc2lvbl9lbmQgZm9yIGFkb3B0ZWQgb3JwaGFuIHNlc3Npb25zLiBBXG4gICAgICAgICAgICAgICAgICAgIC8vIHByb2Nlc3MgdGhhdCBleGl0cyBpbiBhIHNlY29uZCBuZXZlciByZWFjaGVzIGl0LCBzbyBkbyBvbmUgcGFzcyBoZXJlLlxuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4geyBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIHRydWUpOyB9KTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHsgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOyB9KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdhbWVBbmFseXRpY3Muc2V0dGxlKDEwKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgLy8gU3BlYzogdGhlIGNhY2hlIGlzIGRlbGV0ZWQgYWZ0ZXIgYSBTVUNDRVNTRlVMIGRyYWluLiBPbiBhXG4gICAgICAgICAgICAgICAgICAgIC8vIE5vUmVzcG9uc2UgdGhlIGV2ZW50cyB3ZXJlIHB1dCBiYWNrIGFzICduZXcnIGFuZCBtdXN0IHN1cnZpdmVcbiAgICAgICAgICAgICAgICAgICAgLy8gZm9yIHRoZSBuZXh0IHJ1bidzIHN3ZWVwOyBkZWxldGluZyBoZXJlIHdvdWxkIGxvc2UgdGhlbS5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGxlZnQgPSBHQVN0b3JlLnNlbGVjdChnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlLkV2ZW50cyk7XG4gICAgICAgICAgICAgICAgICAgIGlmICghbGVmdCB8fCBsZWZ0Lmxlbmd0aCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGVTZXNzaW9uQ2FjaGUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJvblF1aXQ6IFwiICsgbGVmdC5sZW5ndGggKyBcIiBldmVudChzKSBjb3VsZCBub3QgYmUgZGVsaXZlcmVkOyBzZXNzaW9uIGNhY2hlIGtlcHQgZm9yIHRoZSBuZXh0IHJ1blwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wUHVtcCgpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2V0dGxlKG1heFJvdW5kczpudW1iZXIpOiBQcm9taXNlPHZvaWQ+XG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLmZsdXNoKCk7XG4gICAgICAgICAgICBpZiAobWF4Um91bmRzIDw9IDAgfHwgKEdBSFRUUEFwaS5pbkZsaWdodENvdW50KCkgPT09IDAgJiYgR0FUaHJlYWRpbmcucGVuZGluZ1Rhc2tDb3VudCgpID09PSAwKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gR0FIVFRQQXBpLndoZW5JZGxlKCkudGhlbigoKSA9PiBHYW1lQW5hbHl0aWNzLnNldHRsZShtYXhSb3VuZHMgLSAxKSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5yZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzU3RyaW5nKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTpzdHJpbmcgPSBudWxsKTpzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0Q29uZmlndXJhdGlvblN0cmluZ1ZhbHVlKGtleSwgZGVmYXVsdFZhbHVlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNKU09OKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTphbnkgPSBudWxsKTphbnlcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0Q29uZmlndXJhdGlvbkpzb25WYWx1ZShrZXksIGRlZmF1bHRWYWx1ZSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGlzUmVtb3RlQ29uZmlnc1JlYWR5KCk6Ym9vbGVhblxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pc1JlbW90ZUNvbmZpZ3NSZWFkeSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmFkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUucmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZygpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ0lkKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldEFCVGVzdGluZ0lkKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ1ZhcmlhbnRJZCgpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRBQlRlc3RpbmdWYXJpYW50SWQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcjogeyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmFkZE9uQmVmb3JlVW5sb2FkTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyOiB7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUucmVtb3ZlT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbnRlcm5hbEluaXRpYWxpemUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmVuc3VyZVBlcnNpc3RlZFN0YXRlcygpO1xuICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXksIEdBU3RhdGUuZ2V0RGVmYXVsdElkKCkpO1xuXG4gICAgICAgICAgICBHQVN0YXRlLnNldEluaXRpYWxpemVkKHRydWUpO1xuXG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm5ld1Nlc3Npb24oKTtcblxuICAgICAgICAgICAgaWYgKEdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbmV3U2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTdGFydGluZyBhIG5ldyBzZXNzaW9uLlwiKTtcblxuICAgICAgICAgICAgLy8gbWFrZSBzdXJlIHRoZSBjdXJyZW50IGN1c3RvbSBkaW1lbnNpb25zIGFyZSB2YWxpZFxuICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5yZXF1ZXN0SW5pdChHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3NIYXNoLCBHYW1lQW5hbHl0aWNzLnN0YXJ0TmV3U2Vzc2lvbkNhbGxiYWNrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHN0YXJ0TmV3U2Vzc2lvbkNhbGxiYWNrKGluaXRSZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGluaXRSZXNwb25zZURpY3Q6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gaW5pdCBpcyBva1xuICAgICAgICAgICAgaWYoKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQpICYmIGluaXRSZXNwb25zZURpY3QpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gc2V0IHRoZSB0aW1lIG9mZnNldCAtIGhvdyBtYW55IHNlY29uZHMgdGhlIGxvY2FsIHRpbWUgaXMgZGlmZmVyZW50IGZyb20gc2VydmVydGltZVxuICAgICAgICAgICAgICAgIHZhciB0aW1lT2Zmc2V0U2Vjb25kczpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyVHM6bnVtYmVyID0gaW5pdFJlc3BvbnNlRGljdFtcInNlcnZlcl90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIHRpbWVPZmZzZXRTZWNvbmRzID0gR0FTdGF0ZS5jYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcInRpbWVfb2Zmc2V0XCJdID0gdGltZU9mZnNldFNlY29uZHM7XG5cbiAgICAgICAgICAgICAgICBpZihpbml0UmVzcG9uc2UgIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY3VycmVudFNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRTZGtDb25maWcoKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gdXNlIGNhY2hlZCBpZiBub3QgQ3JlYXRlZFxuICAgICAgICAgICAgICAgICAgICBpZihjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc1wiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImNvbmZpZ3NcIl0gPSBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc1wiXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZihjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc19oYXNoXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZihjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJhYl9pZFwiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZihjdXJyZW50U2RrQ29uZmlnW1wiYWJfdmFyaWFudF9pZFwiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImFiX3ZhcmlhbnRfaWRcIl0gPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfdmFyaWFudF9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlnc0hhc2ggPSBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc19oYXNoXCJdID8gaW5pdFJlc3BvbnNlRGljdFtcImNvbmZpZ3NfaGFzaFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hYklkID0gaW5pdFJlc3BvbnNlRGljdFtcImFiX2lkXCJdID8gaW5pdFJlc3BvbnNlRGljdFtcImFiX2lkXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmFiVmFyaWFudElkID0gaW5pdFJlc3BvbnNlRGljdFtcImFiX3ZhcmlhbnRfaWRcIl0gPyBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA6IFwiXCI7XG5cbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgbmV3IGNvbmZpZyBpbiBzcWwgbGl0ZSBjcm9zcyBzZXNzaW9uIHN0b3JhZ2VcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5LCBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShpbml0UmVzcG9uc2VEaWN0KSkpO1xuXG4gICAgICAgICAgICAgICAgLy8gc2V0IG5ldyBjb25maWcgYW5kIGNhY2hlIGluIG1lbW9yeVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gaW5pdFJlc3BvbnNlRGljdDtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IGluaXRSZXNwb25zZURpY3Q7XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09IEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkluaXRpYWxpemUgU0RLIGZhaWxlZCAtIFVuYXV0aG9yaXplZFwiKTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbG9nIHRoZSBzdGF0dXMgaWYgbm8gY29ubmVjdGlvblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuUmVxdWVzdFRpbWVvdXQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBubyByZXNwb25zZS4gQ291bGQgYmUgb2ZmbGluZSBvciB0aW1lb3V0LlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVzcG9uc2UuIENvdWxkIGJlIGJhZCByZXNwb25zZSBmcm9tIHByb3h5IG9yIEdBIHNlcnZlcnMuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXF1ZXN0IG9yIHVua25vd24gcmVzcG9uc2UuXCIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluaXQgY2FsbCBmYWlsZWQgKHBlcmhhcHMgb2ZmbGluZSlcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgY2FjaGVkIGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBsYXN0IGNyb3NzIHNlc3Npb24gc3RvcmVkIGNvbmZpZyBpbml0IHZhbHVlc1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGRlZmF1bHQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgaW5pdCB2YWx1ZXNcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGNhY2hlZCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBzZXQgb2Zmc2V0IGluIHN0YXRlIChtZW1vcnkpIGZyb20gY3VycmVudCBjb25maWcgKGNvbmZpZyBjb3VsZCBiZSBmcm9tIGNhY2hlIGV0Yy4pXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQgPSBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gPyBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gYXMgbnVtYmVyIDogMDtcblxuICAgICAgICAgICAgLy8gcG9wdWxhdGUgY29uZmlndXJhdGlvbnNcbiAgICAgICAgICAgIEdBU3RhdGUucG9wdWxhdGVDb25maWd1cmF0aW9ucyhHQVN0YXRlLmdldFNka0NvbmZpZygpKTtcblxuICAgICAgICAgICAgLy8gaWYgU0RLIGlzIGRpc2FibGVkIGluIGNvbmZpZ1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzdGFydCBzZXNzaW9uOiBTREsgaXMgZGlzYWJsZWQuXCIpO1xuICAgICAgICAgICAgICAgIC8vIHN0b3AgZXZlbnQgcXVldWVcbiAgICAgICAgICAgICAgICAvLyArIG1ha2Ugc3VyZSBpdCdzIGFibGUgdG8gcmVzdGFydCBpZiBhbm90aGVyIHNlc3Npb24gZGV0ZWN0cyBpdCdzIGVuYWJsZWQgYWdhaW5cbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wRXZlbnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIGdlbmVyYXRlIHRoZSBuZXcgc2Vzc2lvblxuICAgICAgICAgICAgdmFyIG5ld1Nlc3Npb25JZDpzdHJpbmcgPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIGlkXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZCA9IG5ld1Nlc3Npb25JZDtcblxuICAgICAgICAgICAgLy8gU2V0IHNlc3Npb24gc3RhcnRcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgIC8vIEFkZCBzZXNzaW9uIHN0YXJ0IGV2ZW50XG4gICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uU3RhcnRFdmVudCgpO1xuXG4gICAgICAgICAgICAvLyBBZGQgc2RrIGluaXQgZXZlbnQgaWYgZW5hYmxlZFxuICAgICAgICAgICAgR0FFdmVudHMuYWRkU0RLSW5pdEV2ZW50KCk7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyByZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiUmVzdW1pbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICBpZighR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5uZXdTZXNzaW9uKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpc1Nka1JlYWR5KG5lZWRzSW5pdGlhbGl6ZWQ6Ym9vbGVhbiwgd2Fybjpib29sZWFuID0gdHJ1ZSwgbWVzc2FnZTpzdHJpbmcgPSBcIlwiKTogYm9vbGVhblxuICAgICAgICB7XG4gICAgICAgICAgICBpZihtZXNzYWdlKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlICsgXCI6IFwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBJcyBTREsgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAod2FybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU0RLIGlzIG5vdCBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgU0RLIGVuYWJsZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIElzIHNlc3Npb24gc3RhcnRlZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTZXNzaW9uIGhhcyBub3Qgc3RhcnRlZCB5ZXRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgfVxufVxuZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmluaXQoKTtcbnZhciBHYW1lQW5hbHl0aWNzID0gZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmdhQ29tbWFuZDtcbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdG9yYWdlXG4gICAge1xuICAgICAgICAvLyBLZXkvdmFsdWUgc3RvcmFnZSwgdGhlIHNoYXBlIG9mIGxvY2FsU3RvcmFnZS4gRGl2ZXJnZW5jZSAxIGluIHRoZSBzcGVjOlxuICAgICAgICAvLyBDKysgbW9kZWxzIHBlcnNpc3RlbmNlIGFzIGEgcGF0aCBiZWNhdXNlIGV2ZXJ5IHBsYXRmb3JtIGhhcyBhXG4gICAgICAgIC8vIGZpbGVzeXN0ZW07IHRoZSBicm93c2VyIGRvZXMgbm90LCBzbyB0aGUgYWJzdHJhY3Rpb24gaXMgdGhpcyBpbnRlcmZhY2UuXG4gICAgICAgIC8vXG4gICAgICAgIC8vIFR3byBKUy1wb3J0IGV4dGVuc2lvbnMgYmV5b25kIHRoZSBzcGVjJ3MgZm91ciBtZXRob2RzOlxuICAgICAgICAvLyAgLSBnZXRTaXplQnl0ZXMoKTogdGhlIHNwZWMgZGVjaWRlcyBOb2RlIG1lYXN1cmVzIHRoZSBzdG9yZSBpbiBieXRlcyBhbmRcbiAgICAgICAgLy8gICAgdGhlIGJyb3dzZXIgaW4gZW50cmllczsgR0FTdG9yZSBoYXMgdG8gYmUgYWJsZSB0byBhc2suIC0xID0gY2Fubm90XG4gICAgICAgIC8vICAgIG1lYXN1cmUgKGJyb3dzZXIpLCBhbmQgR0FTdG9yZSBmYWxscyBiYWNrIHRvIHRoZSBlbnRyeSBjb3VudC5cbiAgICAgICAgLy8gIC0gZGVsZXRlU2Vzc2lvbkNhY2hlKCk6IHRoZSBzcGVjIHB1dHMgdGhlIHBlci1zZXNzaW9uIHRtcCBjYWNoZSBpbnNpZGVcbiAgICAgICAgLy8gICAgSUdBU3RvcmFnZSBhbmQgaGFzIG9uUXVpdCgpIGRlbGV0ZSBpdCBhZnRlciBhIHN1Y2Nlc3NmdWwgZHJhaW4uXG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgSUdBU3RvcmFnZVxuICAgICAgICB7XG4gICAgICAgICAgICBnZXRJdGVtKGtleTpzdHJpbmcpOiBzdHJpbmcgfCBudWxsO1xuICAgICAgICAgICAgc2V0SXRlbShrZXk6c3RyaW5nLCB2YWx1ZTpzdHJpbmcpOiB2b2lkO1xuICAgICAgICAgICAgcmVtb3ZlSXRlbShrZXk6c3RyaW5nKTogdm9pZDtcbiAgICAgICAgICAgIGlzQXZhaWxhYmxlKCk6IGJvb2xlYW47XG4gICAgICAgICAgICBnZXRTaXplQnl0ZXMoKTogbnVtYmVyO1xuICAgICAgICAgICAgZGVsZXRlU2Vzc2lvbkNhY2hlKCk6IHZvaWQ7XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgLy8gUG9ydCBvZiBpbmNsdWRlL0dhbWVBbmFseXRpY3MvR0FIdHRwQ2xpZW50LmguIERpdmVyZ2VuY2UgMjogQysrIHJldHVybnMgdGhlXG4gICAgICAgIC8vIFJlc3BvbnNlIHN5bmNocm9ub3VzbHk7IEpTIHJldHVybnMgYSBwcm9taXNlLiBjb2RlID0gLTEgaXMgdGhlIGZhaWx1cmVcbiAgICAgICAgLy8gc2VudGluZWwuIHN0YXR1c1RleHQgaXMgYSBKUyBhZGRpdGlvbiB1c2VkIG9ubHkgZm9yIGxvZyBsaW5lcy5cbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBHQUh0dHBSZXNwb25zZVxuICAgICAgICB7XG4gICAgICAgICAgICBjb2RlOm51bWJlcjtcbiAgICAgICAgICAgIHBhY2tldDpVaW50OEFycmF5O1xuICAgICAgICAgICAgc3RhdHVzVGV4dD86c3RyaW5nO1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBJR0FIdHRwQ2xpZW50XG4gICAgICAgIHtcbiAgICAgICAgICAgIGluaXRpYWxpemUoKTogdm9pZDtcbiAgICAgICAgICAgIGNsZWFudXAoKTogdm9pZDtcbiAgICAgICAgICAgIHNlbmRSZXF1ZXN0KHVybDpzdHJpbmcsIGF1dGg6c3RyaW5nLCBwYXlsb2FkOlVpbnQ4QXJyYXksIHVzZUd6aXA6Ym9vbGVhbik6IFByb21pc2U8R0FIdHRwUmVzcG9uc2U+O1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gV2hhdCB0aGUgZXhpc3RpbmcgcmVzcG9uc2UgY2FsbGJhY2tzIHJlYWQuIFhNTEh0dHBSZXF1ZXN0IHNhdGlzZmllcyBpdC5cbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBHQUh0dHBSZXNwb25zZUxpa2VcbiAgICAgICAge1xuICAgICAgICAgICAgc3RhdHVzOm51bWJlcjtcbiAgICAgICAgICAgIHN0YXR1c1RleHQ6c3RyaW5nO1xuICAgICAgICAgICAgcmVzcG9uc2VUZXh0OnN0cmluZztcbiAgICAgICAgfVxuICAgIH1cbn1cbiJdfQ==

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
