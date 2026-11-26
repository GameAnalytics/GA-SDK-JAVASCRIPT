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
            GALogger.setHandler = function (handler) {
                GALogger.handler = handler;
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
                if (GALogger.handler) {
                    GALogger.handler(message, EGALoggerMessageType[type]);
                    return;
                }
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
            GALogger.handler = null;
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
                    request.timeout = 10000;
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
            GADevice.setPlatform = function (platform) {
                GADevice.platform = platform;
            };
            GADevice.getPlatform = function () {
                return GADevice.platform;
            };
            GADevice.getWritablePath = function () {
                return GADevice.writablePath || (GADevice.platform ? GADevice.platform.getPersistentPath() : "");
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
            GADevice.sdkWrapperVersion = "javascript 5.1.0";
            GADevice.platform = null;
            GADevice.writablePath = "";
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
            GAStore.setStorage = function (storage) {
                GAStore.storage = storage;
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
                client.sendRequest(url, hashHmac, new TextEncoder().encode(payloadData), false).then(function (response) {
                    var text = response.packet && response.packet.length ? new TextDecoder().decode(response.packet) : "";
                    if (!text) {
                        GALogger.d("sdk error failed. Might be no connection. Description: " + (response.statusText || "") + ", Status code: " + response.code);
                        return;
                    }
                    if (response.code != 200) {
                        GALogger.w("sdk error failed. response code not 200. status code: " + response.code + ", description: " + (response.statusText || "") + ", body: " + text);
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
            GAHTTPApi.setClient = function (client) { GAHTTPApi.client = client; };
            GAHTTPApi.getClient = function () { return GAHTTPApi.client; };
            GAHTTPApi.inFlightCount = function () { return GAHTTPApi.inFlight.length; };
            GAHTTPApi.whenIdle = function () {
                if (GAHTTPApi.inFlight.length === 0) {
                    return Promise.resolve();
                }
                return Promise.all(GAHTTPApi.inFlight.slice()).then(function () { return GAHTTPApi.whenIdle(); });
            };
            GAHTTPApi.track = function (request) {
                GAHTTPApi.inFlight.push(request);
                var done = function () { GAHTTPApi.inFlight = GAHTTPApi.inFlight.filter(function (other) { return other !== request; }); };
                request.then(done, done);
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
                var request = GAHTTPApi.client.sendRequest(url, authorization, new TextEncoder().encode(payloadData), gzip)
                    .then(function (response) {
                    var like = {
                        status: response.code < 0 ? 0 : response.code,
                        statusText: response.statusText || "",
                        responseText: response.packet && response.packet.length ? new TextDecoder().decode(response.packet) : ""
                    };
                    callback(like, url, callback2, args);
                })
                    .catch(function (e) { GALogger.e("HTTP callback failed: " + (e && e.stack ? e.stack : e)); });
                GAHTTPApi.track(request);
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
                var requestJsonDict = null;
                try {
                    requestJsonDict = body ? JSON.parse(body) : {};
                }
                catch (e) { }
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
                if (!body || /^\s*</.test(body)) {
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
            GAThreading.unref = function (timer) { if (timer && typeof timer.unref === 'function') {
                timer.unref();
            } };
            GAThreading.flush = function () { GAThreading.run(); };
            GAThreading.pendingTaskCount = function () { return GAThreading.instance.taskQueue.length; };
            GAThreading.stopPump = function () { clearInterval(GAThreading.pumpId); GAThreading.stopped = true; };
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
                while (!GAThreading.held && GAThreading.instance.taskQueue.length > 0) {
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
                if (gameanalytics.http.GAHTTPApi.inFlightCount() > 0) {
                    return;
                }
                GALogger.d("Processing event queue...");
                GAEvents.processEvents("", true);
            };
            GAThreading.instance = new GAThreading();
            GAThreading.held = false;
            GAThreading.stopped = false;
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
            GameAnalytics.methodMap['configureWritablePath'] = GameAnalytics.configureWritablePath;
            GameAnalytics.methodMap['configureLogHandler'] = GameAnalytics.configureLogHandler;
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
        GameAnalytics.configureWritablePath = function (path) {
            if (path === void 0) { path = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Writable path must be set before SDK is initialized.");
                    return;
                }
                GADevice.writablePath = path;
            });
        };
        GameAnalytics.configureLogHandler = function (handler) {
            if (handler === void 0) { handler = null; }
            GALogger.setHandler(handler);
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
        GameAnalytics.onQuit = function (timeoutMs) {
            if (GameAnalytics.quitPromise) {
                return GameAnalytics.quitPromise;
            }
            var deadline = typeof timeoutMs === "number" ? setTimeout(function () { return GAHTTPApi.getClient().cleanup(); }, timeoutMs) : null;
            return GameAnalytics.quitPromise = GameAnalytics.settle(10)
                .then(function () {
                GAThreading.performTaskOnGAThread(function () { if (GAState.isInitialized()) {
                    GAEvents.processEvents("", true);
                } });
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
                clearTimeout(deadline);
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
            GAStore.save(GAState.getGameKey());
            GAState.setInitialized(true);
            GameAnalytics.newSession();
            if (GAState.isEnabled()) {
                GAThreading.ensureEventQueueIsRunning();
            }
        };
        GameAnalytics.newSession = function () {
            GALogger.i("Starting a new session.");
            GAState.validateAndFixCurrentDimensions();
            GAThreading.held = true;
            try {
                GAHTTPApi.instance.requestInit(GAState.instance.configsHash, GameAnalytics.startNewSessionCallback);
            }
            catch (e) {
                GAThreading.held = false;
                throw e;
            }
        };
        GameAnalytics.startNewSessionCallback = function (initResponse, initResponseDict) {
            GAThreading.held = false;
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9QdWJsaWNFbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy9odHRwL0dBSHR0cENsaWVudEJyb3dzZXIudHMiLCJzcmMvaHR0cC9tYWtlSHR0cENsaWVudC5icm93c2VyLnRzIiwic3JjL3ZhbGlkYXRvcnMvR0FWYWxpZGF0b3IudHMiLCJzcmMvcGxhdGZvcm0vR0FQbGF0Zm9ybS50cyIsInNyYy9kZXZpY2UvR0FEZXZpY2UudHMiLCJzcmMvcGxhdGZvcm0vR0FQbGF0Zm9ybUJyb3dzZXIudHMiLCJzcmMvcGxhdGZvcm0vbWFrZVBsYXRmb3JtLmJyb3dzZXIudHMiLCJzcmMvc3RvcmUvR0FTdG9yZS50cyIsInNyYy9zdG9yYWdlL0dBU3RvcmFnZUJyb3dzZXIudHMiLCJzcmMvc3RvcmFnZS9tYWtlU3RvcmFnZS5icm93c2VyLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2hlYWx0aC9HQUhlYWx0aC50cyIsInNyYy9ldmVudHMvR0FFdmVudHMudHMiLCJzcmMvdGhyZWFkaW5nL0dBVGhyZWFkaW5nLnRzIiwic3JjL0dhbWVBbmFseXRpY3MudHMiLCJzcmMvc3RvcmFnZS9JR0FTdG9yYWdlLnRzIiwic3JjL2h0dHAvSUdBSHR0cENsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7QUFBQSxJQUFPLGFBQWEsQ0F1Sm5CO0FBdkpELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQU9YO0lBUEQsV0FBWSxnQkFBZ0I7UUFDeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFQ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SUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsRUFDNUM7Z0JBQ0ksSUFBSSxJQUFJLEVBQ1I7b0JBQ0ksUUFBUSxDQUFDLENBQUMsQ0FBQyxPQUFPLEdBQUcsaUJBQWlCLENBQUMsQ0FBQztpQkFDM0M7Z0JBQ0QsT0FBTyxLQUFLLENBQUM7YUFDaEI7WUFFRCxJQUFJLGdCQUFnQixJQUFJLENBQUMsT0FBTyxDQUFDLGdCQUFnQixFQUFFLEVBQ25EO2dCQUNJLElBQUksSUFBSSxFQUNSO29CQUNJLFFBQVEsQ0FBQyxDQUFDLENBQUMsT0FBTyxHQUFHLDZCQUE2QixDQUFDLENBQUM7aUJBQ3ZEO2dCQUNELE9BQU8sS0FBSyxDQUFDO2FBQ2hCO1lBQ0QsT0FBTyxJQUFJLENBQUM7UUFDaEIsQ0FBQztRQWw5QkssdUJBQVMsR0FBMkMsRUFBRSxDQUFDO1FBNnBCOUMseUJBQVcsR0FBaUIsSUFBSSxDQUFDO1FBc1RwRCxvQkFBQztLQXI5QkQsQUFxOUJDLElBQUE7SUFyOUJZLDJCQUFhLGdCQXE5QnpCLENBQUE7QUFDTCxDQUFDLEVBcCtCTSxhQUFhLEtBQWIsYUFBYSxRQW8rQm5CO0FBQ0QsYUFBYSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUNuQyxJQUFJLGFBQWEsR0FBRyxhQUFhLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyIsImZpbGUiOiJkaXN0L0dhbWVBbmFseXRpY3MuZGVidWcuanMiLCJzb3VyY2VzQ29udGVudCI6WyJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHkge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBEZWJ1ZyA9IDEsXG4gICAgICAgIEluZm8gPSAyLFxuICAgICAgICBXYXJuaW5nID0gMyxcbiAgICAgICAgRXJyb3IgPSA0LFxuICAgICAgICBDcml0aWNhbCA9IDVcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FQcm9ncmVzc2lvblN0YXR1cyB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFN0YXJ0ID0gMSxcbiAgICAgICAgQ29tcGxldGUgPSAyLFxuICAgICAgICBGYWlsID0gM1xuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVJlc291cmNlRmxvd1R5cGUge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkQWN0aW9uIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgQ2xpY2tlZCA9IDEsXG4gICAgICAgIFNob3cgPSAyLFxuICAgICAgICBGYWlsZWRTaG93ID0gMyxcbiAgICAgICAgUmV3YXJkUmVjZWl2ZWQgPSA0XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRFcnJvciB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFVua25vd24gPSAxLFxuICAgICAgICBPZmZsaW5lID0gMixcbiAgICAgICAgTm9GaWxsID0gMyxcbiAgICAgICAgSW50ZXJuYWxFcnJvciA9IDQsXG4gICAgICAgIEludmFsaWRSZXF1ZXN0ID0gNSxcbiAgICAgICAgVW5hYmxlVG9QcmVjYWNoZSA9IDZcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZFR5cGUge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBWaWRlbyA9IDEsXG4gICAgICAgIFJld2FyZGVkVmlkZW8gPSAyLFxuICAgICAgICBQbGF5YWJsZSA9IDMsXG4gICAgICAgIEludGVyc3RpdGlhbCA9IDQsXG4gICAgICAgIE9mZmVyV2FsbCA9IDUsXG4gICAgICAgIEJhbm5lciA9IDZcbiAgICB9XG5cbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBjbGllbnRcbiAgICAgICAgICAgIE5vUmVzcG9uc2UsXG4gICAgICAgICAgICBCYWRSZXNwb25zZSxcbiAgICAgICAgICAgIFJlcXVlc3RUaW1lb3V0LCAvLyA0MDhcbiAgICAgICAgICAgIEpzb25FbmNvZGVGYWlsZWQsXG4gICAgICAgICAgICBKc29uRGVjb2RlRmFpbGVkLFxuICAgICAgICAgICAgLy8gc2VydmVyXG4gICAgICAgICAgICBJbnRlcm5hbFNlcnZlckVycm9yLFxuICAgICAgICAgICAgQmFkUmVxdWVzdCwgLy8gNDAwXG4gICAgICAgICAgICBVbmF1dGhvcml6ZWQsIC8vIDQwMVxuICAgICAgICAgICAgVW5rbm93blJlc3BvbnNlQ29kZSxcbiAgICAgICAgICAgIE9rLFxuICAgICAgICAgICAgQ3JlYXRlZFxuICAgICAgICB9XG4gICAgfVxuXG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcbiAgICB7XG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQ2F0ZWdvcnlcbiAgICAgICAge1xuICAgICAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgICAgIEV2ZW50VmFsaWRhdGlvbiA9IDEsXG4gICAgICAgICAgICBEYXRhYmFzZSA9IDIsXG4gICAgICAgICAgICBJbml0ID0gMyxcbiAgICAgICAgICAgIEh0dHAgPSA0LFxuICAgICAgICAgICAgSnNvbiA9IDVcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQXJlYVxuICAgICAgICB7XG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICAgICAgQnVzaW5lc3NFdmVudCA9IDEsXG4gICAgICAgICAgICBSZXNvdXJjZUV2ZW50ID0gMixcbiAgICAgICAgICAgIFByb2dyZXNzaW9uRXZlbnQgPSAzLFxuICAgICAgICAgICAgRGVzaWduRXZlbnQgPSA0LFxuICAgICAgICAgICAgRXJyb3JFdmVudCA9IDUsXG4gICAgICAgICAgICBJbml0SHR0cCA9IDksXG4gICAgICAgICAgICBFdmVudHNIdHRwID0gMTAsXG4gICAgICAgICAgICBQcm9jZXNzRXZlbnRzID0gMTEsXG4gICAgICAgICAgICBBZGRFdmVudHNUb1N0b3JlID0gMTIsXG4gICAgICAgICAgICBBZEV2ZW50ID0gMjBcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yQWN0aW9uXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBJbnZhbGlkQ3VycmVuY3kgPSAxLFxuICAgICAgICAgICAgSW52YWxpZFNob3J0U3RyaW5nID0gMixcbiAgICAgICAgICAgIEludmFsaWRFdmVudFBhcnRMZW5ndGggPSAzLFxuICAgICAgICAgICAgSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMgPSA0LFxuICAgICAgICAgICAgSW52YWxpZFN0b3JlID0gNSxcbiAgICAgICAgICAgIEludmFsaWRGbG93VHlwZSA9IDYsXG4gICAgICAgICAgICBTdHJpbmdFbXB0eU9yTnVsbCA9IDcsXG4gICAgICAgICAgICBOb3RGb3VuZEluQXZhaWxhYmxlQ3VycmVuY2llcyA9IDgsXG4gICAgICAgICAgICBJbnZhbGlkQW1vdW50ID0gOSxcbiAgICAgICAgICAgIE5vdEZvdW5kSW5BdmFpbGFibGVJdGVtVHlwZXMgPSAxMCxcbiAgICAgICAgICAgIFdyb25nUHJvZ3Jlc3Npb25PcmRlciA9IDExLFxuICAgICAgICAgICAgSW52YWxpZEV2ZW50SWRMZW5ndGggPSAxMixcbiAgICAgICAgICAgIEludmFsaWRFdmVudElkQ2hhcmFjdGVycyA9IDEzLFxuICAgICAgICAgICAgSW52YWxpZFByb2dyZXNzaW9uU3RhdHVzID0gMTUsXG4gICAgICAgICAgICBJbnZhbGlkU2V2ZXJpdHkgPSAxNixcbiAgICAgICAgICAgIEludmFsaWRMb25nU3RyaW5nID0gMTcsXG4gICAgICAgICAgICBEYXRhYmFzZVRvb0xhcmdlID0gMTgsXG4gICAgICAgICAgICBEYXRhYmFzZU9wZW5PckNyZWF0ZSA9IDE5LFxuICAgICAgICAgICAgSnNvbkVycm9yID0gMjUsXG4gICAgICAgICAgICBGYWlsSHR0cEpzb25EZWNvZGUgPSAyOSxcbiAgICAgICAgICAgIEZhaWxIdHRwSnNvbkVuY29kZSA9IDMwLFxuICAgICAgICAgICAgSW52YWxpZEFkQWN0aW9uID0gMzEsXG4gICAgICAgICAgICBJbnZhbGlkQWRUeXBlID0gMzIsXG4gICAgICAgICAgICBJbnZhbGlkU3RyaW5nID0gMzNcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yUGFyYW1ldGVyXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBDdXJyZW5jeSA9IDEsXG4gICAgICAgICAgICBDYXJ0VHlwZSA9IDIsXG4gICAgICAgICAgICBJdGVtVHlwZSA9IDMsXG4gICAgICAgICAgICBJdGVtSWQgPSA0LFxuICAgICAgICAgICAgU3RvcmUgPSA1LFxuICAgICAgICAgICAgRmxvd1R5cGUgPSA2LFxuICAgICAgICAgICAgQW1vdW50ID0gNyxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uMDEgPSA4LFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24wMiA9IDksXG4gICAgICAgICAgICBQcm9ncmVzc2lvbjAzID0gMTAsXG4gICAgICAgICAgICBFdmVudElkID0gMTEsXG4gICAgICAgICAgICBQcm9ncmVzc2lvblN0YXR1cyA9IDEyLFxuICAgICAgICAgICAgU2V2ZXJpdHkgPSAxMyxcbiAgICAgICAgICAgIE1lc3NhZ2UgPSAxNCxcbiAgICAgICAgICAgIEFkQWN0aW9uID0gMTUsXG4gICAgICAgICAgICBBZFR5cGUgPSAxNixcbiAgICAgICAgICAgIEFkU2RrTmFtZSA9IDE3LFxuICAgICAgICAgICAgQWRQbGFjZW1lbnQgPSAxOFxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIHB1YmxpY19lbnVtc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHlcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIERlYnVnID0gMSxcbiAgICAgICAgSW5mbyA9IDIsXG4gICAgICAgIFdhcm5pbmcgPSAzLFxuICAgICAgICBFcnJvciA9IDQsXG4gICAgICAgIENyaXRpY2FsID0gNVxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVByb2dyZXNzaW9uU3RhdHVzXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTdGFydCA9IDEsXG4gICAgICAgIENvbXBsZXRlID0gMixcbiAgICAgICAgRmFpbCA9IDNcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUFkQWN0aW9uXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBDbGlja2VkID0gMSxcbiAgICAgICAgU2hvdyA9IDIsXG4gICAgICAgIEZhaWxlZFNob3cgPSAzLFxuICAgICAgICBSZXdhcmRSZWNlaXZlZCA9IDRcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FBZEVycm9yXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBVbmtub3duID0gMSxcbiAgICAgICAgT2ZmbGluZSA9IDIsXG4gICAgICAgIE5vRmlsbCA9IDMsXG4gICAgICAgIEludGVybmFsRXJyb3IgPSA0LFxuICAgICAgICBJbnZhbGlkUmVxdWVzdCA9IDUsXG4gICAgICAgIFVuYWJsZVRvUHJlY2FjaGUgPSA2XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBQWRUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBWaWRlbyA9IDEsXG4gICAgICAgIFJld2FyZGVkVmlkZW8gPSAyLFxuICAgICAgICBQbGF5YWJsZSA9IDMsXG4gICAgICAgIEludGVyc3RpdGlhbCA9IDQsXG4gICAgICAgIE9mZmVyV2FsbCA9IDUsXG4gICAgICAgIEJhbm5lciA9IDZcbiAgICB9XG59XG4iLCIvL0dBTE9HR0VSX1NUQVJUXG5tb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xuICAgIHtcbiAgICAgICAgZW51bSBFR0FMb2dnZXJNZXNzYWdlVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBFcnJvciA9IDAsXG4gICAgICAgICAgICBXYXJuaW5nID0gMSxcbiAgICAgICAgICAgIEluZm8gPSAyLFxuICAgICAgICAgICAgRGVidWcgPSAzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FMb2dnZXJcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUxvZ2dlciA9IG5ldyBHQUxvZ2dlcigpO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nVmVyYm9zZUVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGRlYnVnRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaGFuZGxlcjoobWVzc2FnZTpzdHJpbmcsIGxldmVsOnN0cmluZykgPT4gdm9pZCA9IG51bGw7XG5cbiAgICAgICAgICAgIC8vIEZpZWxkcyBhbmQgcHJvcGVydGllczogRU5EXG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmRlYnVnRW5hYmxlZCA9IHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ldGhvZHM6IFNUQVJUXG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SW5mb0xvZyh2YWx1ZTpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkID0gdmFsdWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SGFuZGxlcihoYW5kbGVyOihtZXNzYWdlOnN0cmluZywgbGV2ZWw6c3RyaW5nKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmhhbmRsZXIgPSBoYW5kbGVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFZlcmJvc2VMb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiSW5mby9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB3KGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJXYXJuaW5nL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGUoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkVycm9yL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkluZm8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGQoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRGVidWcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQUxvZ2dlci5oYW5kbGVyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaGFuZGxlcihtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZVt0eXBlXSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBzd2l0Y2godHlwZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRXJyb3I6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4obWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5EZWJ1ZzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYodHlwZW9mIGNvbnNvbGUuZGVidWcgPT09IFwiZnVuY3Rpb25cIilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBFTkRcbiAgICAgICAgfVxuICAgIH1cbn1cbi8vR0FMT0dHRVJfRU5EXG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdXRpbGl0aWVzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVXRpbGl0aWVzXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SG1hYyhrZXk6c3RyaW5nLCBkYXRhOnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBlbmNyeXB0ZWRNZXNzYWdlID0gQ3J5cHRvSlMuSG1hY1NIQTI1NihkYXRhLCBrZXkpO1xuICAgICAgICAgICAgICAgIHJldHVybiBDcnlwdG9KUy5lbmMuQmFzZTY0LnN0cmluZ2lmeShlbmNyeXB0ZWRNZXNzYWdlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdHJpbmdNYXRjaChzOnN0cmluZywgcGF0dGVybjpSZWdFeHApOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIXMgfHwgIXBhdHRlcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBhdHRlcm4udGVzdChzKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBqb2luU3RyaW5nQXJyYXkodjpBcnJheTxzdHJpbmc+LCBkZWxpbWl0ZXI6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcIlwiO1xuXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDAsIGlsID0gdi5sZW5ndGg7IGkgPCBpbDsgaSsrKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGkgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQgKz0gZGVsaW1pdGVyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSB2W2ldO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXJyYXk6QXJyYXk8c3RyaW5nPiwgc2VhcmNoOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYXJyYXkubGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBhcnJheSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGFycmF5W3NdID09PSBzZWFyY2gpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkga2V5U3RyOnN0cmluZyA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz1cIjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpbnB1dCA9IGVuY29kZVVSSShpbnB1dCk7XG4gICAgICAgICAgICAgICAgdmFyIG91dHB1dDpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciBjaHIxOm51bWJlciwgY2hyMjpudW1iZXIsIGNocjM6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgZW5jMTpudW1iZXIsIGVuYzI6bnVtYmVyLCBlbmMzOm51bWJlciwgZW5jNDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBpID0gMDtcblxuICAgICAgICAgICAgICAgIGRvXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgIGNocjEgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuXG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGNocjEgPj4gMjtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gKChjaHIxICYgMykgPDwgNCkgfCAoY2hyMiA+PiA0KTtcbiAgICAgICAgICAgICAgICAgICBlbmMzID0gKChjaHIyICYgMTUpIDw8IDIpIHwgKGNocjMgPj4gNik7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IGNocjMgJiA2MztcblxuICAgICAgICAgICAgICAgICAgIGlmIChpc05hTihjaHIyKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jMyA9IGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoaXNOYU4oY2hyMykpXG4gICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMSkgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMikgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMykgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkZWNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVtb3ZlIGFsbCBjaGFyYWN0ZXJzIHRoYXQgYXJlIG5vdCBBLVosIGEteiwgMC05LCArLCAvLCBvciA9XG4gICAgICAgICAgICAgICAgdmFyIGJhc2U2NHRlc3QgPSAvW15BLVphLXowLTlcXCtcXC9cXD1dL2c7XG4gICAgICAgICAgICAgICAgaWYgKGJhc2U2NHRlc3QuZXhlYyhpbnB1dCkpIHtcbiAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVGhlcmUgd2VyZSBpbnZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGluIHRoZSBpbnB1dCB0ZXh0LiBWYWxpZCBiYXNlNjQgY2hhcmFjdGVycyBhcmUgQS1aLCBhLXosIDAtOSwgJysnLCAnLycsYW5kICc9Jy4gRXhwZWN0IGVycm9ycyBpbiBkZWNvZGluZy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlucHV0ID0gaW5wdXQucmVwbGFjZSgvW15BLVphLXowLTlcXCtcXC9cXD1dL2csIFwiXCIpO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSAoZW5jMSA8PCAyKSB8IChlbmMyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGNocjIgPSAoKGVuYzIgJiAxNSkgPDwgNCkgfCAoZW5jMyA+PiAyKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gKChlbmMzICYgMykgPDwgNikgfCBlbmM0O1xuXG4gICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIxKTtcblxuICAgICAgICAgICAgICAgICAgIGlmIChlbmMzICE9IDY0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIyKTtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzQgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjMpO1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSBjaHIyID0gY2hyMyA9IDA7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGVuYzIgPSBlbmMzID0gZW5jNCA9IDA7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGRlY29kZVVSSShvdXRwdXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZGF0ZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gTWF0aC5yb3VuZChkYXRlLmdldFRpbWUoKSAvIDEwMDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZUd1aWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIChcIjEwMDAwMDAwLTEwMDAtNDAwMC04MDAwLTEwMDAwMDAwMDAwMFwiKS5yZXBsYWNlKC9bMDE4XS9nLCBjID0+ICgrYyBeIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoMSkpWzBdICYgMTUgPj4gK2MgLyA0KS50b1N0cmluZygxNikpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIdHRwQ2xpZW50QnJvd3NlciBpbXBsZW1lbnRzIElHQUh0dHBDbGllbnRcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIGluaXRpYWxpemUoKTogdm9pZCB7fVxuICAgICAgICAgICAgcHVibGljIGNsZWFudXAoKTogdm9pZCB7fVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZFJlcXVlc3QodXJsOnN0cmluZywgYXV0aDpzdHJpbmcsIHBheWxvYWQ6VWludDhBcnJheSwgdXNlR3ppcDpib29sZWFuKTogUHJvbWlzZTxHQUh0dHBSZXNwb25zZT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFByb21pc2U8R0FIdHRwUmVzcG9uc2U+KChyZXNvbHZlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh1c2VHemlwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiZ3ppcCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoZSBicm93c2VyIEhUVFAgY2xpZW50XCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh7Y29kZTogLTEsIHBhY2tldDogbmV3IFVpbnQ4QXJyYXkoMCksIHN0YXR1c1RleHQ6IFwiZ3ppcCB1bnN1cHBvcnRlZFwifSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0ZXh0OnN0cmluZyA9IHJlcXVlc3QucmVzcG9uc2VUZXh0IHx8IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh7Y29kZTogcmVxdWVzdC5zdGF0dXMgfHwgLTEsIHBhY2tldDogbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpLCBzdGF0dXNUZXh0OiByZXF1ZXN0LnN0YXR1c1RleHQgfHwgXCJcIn0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3QudGltZW91dCA9IDEwMDAwO1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGF1dGgpO1xuICAgICAgICAgICAgICAgICAgICB0cnkgeyByZXF1ZXN0LnNlbmQocGF5bG9hZCk7IH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHsgR0FMb2dnZXIuZShlICYmIGUuc3RhY2sgPyBlLnN0YWNrIDogU3RyaW5nKGUpKTsgcmVzb2x2ZSh7Y29kZTogLTEsIHBhY2tldDogbmV3IFVpbnQ4QXJyYXkoMCksIHN0YXR1c1RleHQ6IFwic2VuZCBmYWlsZWRcIn0pOyB9XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGZ1bmN0aW9uIG1ha2VIdHRwQ2xpZW50KCk6IElHQUh0dHBDbGllbnRcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBHQUh0dHBDbGllbnRCcm93c2VyKCk7XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdmFsaWRhdG9yc1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yQ2F0ZWdvcnkgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckNhdGVnb3J5O1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBcmVhID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JBcmVhO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBY3Rpb24gPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFjdGlvbjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yUGFyYW1ldGVyID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JQYXJhbWV0ZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIGNhdGVnb3J5OkVHQVNka0Vycm9yQ2F0ZWdvcnk7XG4gICAgICAgICAgICBwdWJsaWMgYXJlYTpFR0FTZGtFcnJvckFyZWE7XG4gICAgICAgICAgICBwdWJsaWMgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uO1xuICAgICAgICAgICAgcHVibGljIHBhcmFtZXRlcjpFR0FTZGtFcnJvclBhcmFtZXRlcjtcbiAgICAgICAgICAgIHB1YmxpYyByZWFzb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IoY2F0ZWdvcnk6RUdBU2RrRXJyb3JDYXRlZ29yeSwgYXJlYTpFR0FTZGtFcnJvckFyZWEsIGFjdGlvbjpFR0FTZGtFcnJvckFjdGlvbiwgcGFyYW1ldGVyOkVHQVNka0Vycm9yUGFyYW1ldGVyLCByZWFzb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuY2F0ZWdvcnkgPSBjYXRlZ29yeTtcbiAgICAgICAgICAgICAgICB0aGlzLmFyZWEgPSBhcmVhO1xuICAgICAgICAgICAgICAgIHRoaXMuYWN0aW9uID0gYWN0aW9uO1xuICAgICAgICAgICAgICAgIHRoaXMucGFyYW1ldGVyID0gcGFyYW1ldGVyO1xuICAgICAgICAgICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVmFsaWRhdG9yXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgY2FydFR5cGU6c3RyaW5nLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVuY3lcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VycmVuY3koY3VycmVuY3kpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbCkgYW5kIG5lZWQgdG8gYmUgQS1aLCAzIGNoYXJhY3RlcnMgYW5kIGluIHRoZSBzdGFuZGFyZCBhdCBvcGVuZXhjaGFuZ2VyYXRlcy5vcmcuIEZhaWxlZCBjdXJyZW5jeTogXCIgKyBjdXJyZW5jeSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRDdXJyZW5jeSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ3VycmVuY3ksIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoYW1vdW50IDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGFtb3VudC4gQ2Fubm90IGJlIGxlc3MgdGhhbiAwLiBGYWlsZWQgYW1vdW50OiBcIiArIGFtb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkFtb3VudCwgYW1vdW50ICsgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY2FydFR5cGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY2FydFR5cGUuIENhbm5vdCBiZSBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBjYXJ0VHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTaG9ydFN0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ2FydFR5cGUsIGNhcnRUeXBlKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbVR5cGUsIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBjaGFyc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1UeXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQnVzaW5lc3NFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1UeXBlLCBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbUlkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZC4gQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZCwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkJ1c2luZXNzRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtSWQsIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBhdmFpbGFibGVDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4sIGF2YWlsYWJsZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+KTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGZsb3dUeXBlOiBJbnZhbGlkIGZsb3cgdHlwZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRGbG93VHlwZSwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRmxvd1R5cGUsIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsLCBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVDdXJyZW5jaWVzLCBjdXJyZW5jeSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBjdXJyZW5jeTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMuIFN0cmluZzogXCIgKyBjdXJyZW5jeSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLk5vdEZvdW5kSW5BdmFpbGFibGVDdXJyZW5jaWVzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeSwgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIShhbW91bnQgPiAwKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGFtb3VudDogRmxvYXQgYW1vdW50IGNhbm5vdCBiZSAwIG9yIG5lZ2F0aXZlLiBWYWx1ZTogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkQW1vdW50LCBFR0FTZGtFcnJvclBhcmFtZXRlci5BbW91bnQsIGFtb3VudCArIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWl0ZW1UeXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZSwgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlSXRlbVR5cGVzLCBpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGl0ZW1UeXBlcy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uTm90Rm91bmRJbkF2YWlsYWJsZUl0ZW1UeXBlcywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbVR5cGUsIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlJlc291cmNlRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGgsIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZCwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5SZXNvdXJjZUV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuSXRlbUlkLCBpdGVtSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXM6RUdBUHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDE6c3RyaW5nLCBwcm9ncmVzc2lvbjAyOnN0cmluZywgcHJvZ3Jlc3Npb24wMzpzdHJpbmcpOiBWYWxpZGF0aW9uUmVzdWx0XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogSW52YWxpZCBwcm9ncmVzc2lvbiBzdGF0dXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkUHJvZ3Jlc3Npb25TdGF0dXMsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uU3RhdHVzLCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBNYWtlIHN1cmUgcHJvZ3Jlc3Npb25zIGFyZSBkZWZpbmVkIGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiAwMyBmb3VuZCBidXQgMDErMDIgYXJlIGludmFsaWQuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXIsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHByb2dyZXNzaW9uMDIgJiYgIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAyIGZvdW5kIGJ1dCBub3QgMDEuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLldyb25nUHJvZ3Jlc3Npb25PcmRlciwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uV3JvbmdQcm9ncmVzc2lvbk9yZGVyLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIChwcm9ncmVzc2lvbjAxID8gcHJvZ3Jlc3Npb24wMSA6IFwiXCIpICsgXCI6XCIgKyAocHJvZ3Jlc3Npb24wMiA/IHByb2dyZXNzaW9uMDIgOiBcIlwiKSArIFwiOlwiICsgKHByb2dyZXNzaW9uMDMgPyBwcm9ncmVzc2lvbjAzIDogXCJcIikpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDEgKHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMiwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDI6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0TGVuZ3RoLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAyKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMjogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRDaGFyYWN0ZXJzLCBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAzXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDMsIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAzOiBDYW5ub3QgYmUgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuUHJvZ3Jlc3Npb25FdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMywgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5Qcm9ncmVzc2lvbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRQYXJ0Q2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMywgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkOnN0cmluZyk6IFZhbGlkYXRpb25SZXN1bHRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRJZExlbmd0aChldmVudElkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBDYW5ub3QgYmUgKG51bGwpIG9yIGVtcHR5LiBPbmx5IDUgZXZlbnQgcGFydHMgYWxsb3dlZCBzZXBlcmF0ZWQgYnkgOi4gRWFjaCBwYXJ0IG5lZWQgdG8gYmUgNjQgY2hhcmFjdGVycyBvciBsZXNzLiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkRlc2lnbkV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRJZExlbmd0aCwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRXZlbnRJZCwgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBOb24gdmFsaWQgY2hhcmFjdGVycy4gT25seSBhbGxvd2VkIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuRGVzaWduRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkQ2hhcmFjdGVycywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRXZlbnRJZCwgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbHVlOiBhbGxvdyAwLCBuZWdhdGl2ZSBhbmQgbmlsIChub3QgcmVxdWlyZWQpXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5OkVHQUVycm9yU2V2ZXJpdHksIG1lc3NhZ2U6c3RyaW5nKTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChzZXZlcml0eSA9PSBFR0FFcnJvclNldmVyaXR5LlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIHNldmVyaXR5OiBTZXZlcml0eSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU2V2ZXJpdHksIEVHQVNka0Vycm9yUGFyYW1ldGVyLlNldmVyaXR5LCBcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUxvbmdTdHJpbmcobWVzc2FnZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBtZXNzYWdlOiBNZXNzYWdlIGNhbm5vdCBiZSBhYm92ZSA4MTkyIGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkTG9uZ1N0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQWRFdmVudChhZEFjdGlvbjpFR0FBZEFjdGlvbiwgYWRUeXBlOkVHQUFkVHlwZSwgYWRTZGtOYW1lOnN0cmluZywgYWRQbGFjZW1lbnQ6c3RyaW5nKTogVmFsaWRhdGlvblJlc3VsdFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhZEFjdGlvbiA9PSBFR0FBZEFjdGlvbi5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBzZXZlcml0eTogU2V2ZXJpdHkgd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldyBWYWxpZGF0aW9uUmVzdWx0KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRXZlbnRWYWxpZGF0aW9uLCBFR0FTZGtFcnJvckFyZWEuQWRFdmVudCwgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEFkQWN0aW9uLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZEFjdGlvbiwgXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChhZFR5cGUgPT0gRUdBQWRUeXBlLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBhZCBldmVudCAtIGFkVHlwZTogQWQgdHlwZSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5BZEV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkQWRUeXBlLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZFR5cGUsIFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoYWRTZGtOYW1lLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYWQgZXZlbnQgLSBtZXNzYWdlOiBBZCBTREsgbmFtZSBjYW5ub3QgYmUgYWJvdmUgMzIgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBuZXcgVmFsaWRhdGlvblJlc3VsdChFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbiwgRUdBU2RrRXJyb3JBcmVhLkFkRXZlbnQsIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTaG9ydFN0cmluZywgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQWRTZGtOYW1lLCBhZFNka05hbWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU3RyaW5nKGFkUGxhY2VtZW50LCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYWQgZXZlbnQgLSBtZXNzYWdlOiBBZCBwbGFjZW1lbnQgY2Fubm90IGJlIGFib3ZlIDY0IGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbmV3IFZhbGlkYXRpb25SZXN1bHQoRUdBU2RrRXJyb3JDYXRlZ29yeS5FdmVudFZhbGlkYXRpb24sIEVHQVNka0Vycm9yQXJlYS5BZEV2ZW50LCBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU3RyaW5nLCBFR0FTZGtFcnJvclBhcmFtZXRlci5BZFBsYWNlbWVudCwgYWRQbGFjZW1lbnQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka0Vycm9yRXZlbnQoZ2FtZUtleTpzdHJpbmcsIGdhbWVTZWNyZXQ6c3RyaW5nLCBjYXRlZ29yeTpFR0FTZGtFcnJvckNhdGVnb3J5LCBhcmVhOkVHQVNka0Vycm9yQXJlYSwgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGNhdGVnb3J5ID09PSBFR0FTZGtFcnJvckNhdGVnb3J5LlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBzZGsgZXJyb3IgZXZlbnQgLSB0eXBlOiBDYXRlZ29yeSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChhcmVhID09PSBFR0FTZGtFcnJvckFyZWEuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHNkayBlcnJvciBldmVudCAtIHR5cGU6IEFyZWEgd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoYWN0aW9uID09PSBFR0FTZGtFcnJvckFjdGlvbi5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogQWN0aW9uIHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVLZXlzKGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZUtleSwgL15bQS16MC05XXszMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZVNlY3JldCwgL15bQS16MC05XXs0MH0kLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGN1cnJlbmN5LCAvXltBLVpdezN9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydExlbmd0aChldmVudFBhcnQ6c3RyaW5nLCBhbGxvd051bGw6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOdWxsICYmICFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50UGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoZXZlbnRQYXJ0Lmxlbmd0aCA+IDY0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoZXZlbnRQYXJ0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50UGFydCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZExlbmd0aChldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXlteOl17MSw2NH0oPzo6W146XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSg6W0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9KXswLDR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShpbml0UmVzcG9uc2U6e1trZXk6c3RyaW5nXTogYW55fSwgY29uZmlnc0NyZWF0ZWQ6Ym9vbGVhbik6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBtYWtlIHN1cmUgd2UgaGF2ZSBhIHZhbGlkIGRpY3RcbiAgICAgICAgICAgICAgICBpZiAoaW5pdFJlc3BvbnNlID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIG5vIHJlc3BvbnNlIGRpY3Rpb25hcnkuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBzZXJ2ZXJfdHNcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUc051bWJlcjpudW1iZXIgPSBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl07XG4gICAgICAgICAgICAgICAgICAgIGlmIChzZXJ2ZXJUc051bWJlciA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJzZXJ2ZXJfdHNcIl0gPSBzZXJ2ZXJUc051bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB2YWx1ZSBpbiAnc2VydmVyX3RzJyBmaWVsZC5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdzZXJ2ZXJfdHMnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihjb25maWdzQ3JlYXRlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGNvbmZpZ3MgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uczphbnlbXSA9IGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiY29uZmlnc1wiXSA9IGNvbmZpZ3VyYXRpb25zO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnY29uZmlncycgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiY29uZmlnc1wiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWdzX2hhc2g6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImNvbmZpZ3NfaGFzaFwiXSA9IGNvbmZpZ3NfaGFzaDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2NvbmZpZ3NfaGFzaCcgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiY29uZmlnc19oYXNoXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX2lkIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYWJfaWQ6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiYWJfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfaWRcIl0gPSBhYl9pZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2FiX2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl9pZFwiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImFiX2lkXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX3ZhcmlhbnRfaWQgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhYl92YXJpYW50X2lkOnN0cmluZyA9IGluaXRSZXNwb25zZVtcImFiX3ZhcmlhbnRfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGFiX3ZhcmlhbnRfaWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdhYl92YXJpYW50X2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl92YXJpYW50X2lkXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiYWJfdmFyaWFudF9pZFwiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cblxuICAgICAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZWREaWN0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVpbGQoYnVpbGQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhidWlsZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHdyYXBwZXJWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHdyYXBwZXJWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZHxnb2RvdHxmbHV0dGVyKSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRW5naW5lVmVyc2lvbihlbmdpbmVWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWVuZ2luZVZlcnNpb24gfHwgIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGVuZ2luZVZlcnNpb24sIC9eKHVuaXR5fHVucmVhbHxnYW1lbWFrZXJ8Y29jb3MyZHxjb25zdHJ1Y3R8ZGVmb2xkfGdvZG90KSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlVXNlcklkKHVJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVN0cmluZyh1SWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSB1c2VyIGlkOiBpZCBjYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNob3J0U3RyaW5nKHNob3J0U3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5IG9yIG5pbFxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzaG9ydFN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghc2hvcnRTdHJpbmcgfHwgc2hvcnRTdHJpbmcubGVuZ3RoID4gMzIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU3RyaW5nKHM6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIXMgfHwgcy5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVMb25nU3RyaW5nKGxvbmdTdHJpbmc6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhbG9uZ1N0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghbG9uZ1N0cmluZyB8fCBsb25nU3RyaW5nLmxlbmd0aCA+IDgxOTIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvblR5cGU6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjb25uZWN0aW9uVHlwZSwgL14od3dhbnx3aWZpfGxhbnxvZmZsaW5lKSQvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnMoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwiY3VzdG9tIGRpbWVuc2lvbnNcIiwgY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCA2NCwgZmFsc2UsIFwicmVzb3VyY2UgY3VycmVuY2llc1wiLCByZXNvdXJjZUN1cnJlbmNpZXMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nIGZvciByZWdleFxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzb3VyY2VDdXJyZW5jaWVzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChyZXNvdXJjZUN1cnJlbmNpZXNbaV0sIC9eW0EtWmEtel0rJC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwicmVzb3VyY2UgY3VycmVuY2llcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBjdXJyZW5jeSBjYW4gb25seSBiZSBBLVosIGEtei4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUN1cnJlbmNpZXNbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJyZXNvdXJjZSBpdGVtIHR5cGVzXCIsIHJlc291cmNlSXRlbVR5cGVzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHJlc291cmNlSXRlbVR5cGUgZm9yIGV2ZW50cGFydCB2YWxpZGF0aW9uXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXNvdXJjZUl0ZW1UeXBlcy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHJlc291cmNlSXRlbVR5cGVzW2ldKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInJlc291cmNlIGl0ZW0gdHlwZXMgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgcmVzb3VyY2UgaXRlbSB0eXBlIGNhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmcgd2FzOiBcIiArIHJlc291cmNlSXRlbVR5cGVzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAxKGRpbWVuc2lvbjAxOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAxKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24wMjpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uMDM6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKG1heENvdW50Om51bWJlciwgbWF4U3RyaW5nTGVuZ3RoOm51bWJlciwgYWxsb3dOb1ZhbHVlczpib29sZWFuLCBsb2dUYWc6c3RyaW5nLCBhcnJheU9mU3RyaW5nczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhcnJheVRhZzpzdHJpbmcgPSBsb2dUYWc7XG5cbiAgICAgICAgICAgICAgICAvLyB1c2UgYXJyYXlUYWcgdG8gYW5ub3RhdGUgd2FybmluZyBsb2dcbiAgICAgICAgICAgICAgICBpZiAoIWFycmF5VGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYXJyYXlUYWcgPSBcIkFycmF5XCI7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoIWFycmF5T2ZTdHJpbmdzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgYmUgbnVsbC4gXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOb1ZhbHVlcyA9PSBmYWxzZSAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIGVtcHR5LiBcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBleGNlZWRpbmcgbWF4IGNvdW50XG4gICAgICAgICAgICAgICAgaWYgKG1heENvdW50ID4gMCAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGV4Y2VlZCBcIiArIG1heENvdW50ICsgXCIgdmFsdWVzLiBJdCBoYXMgXCIgKyBhcnJheU9mU3RyaW5ncy5sZW5ndGggKyBcIiB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmdcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5T2ZTdHJpbmdzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHN0cmluZ0xlbmd0aDpudW1iZXIgPSAhYXJyYXlPZlN0cmluZ3NbaV0gPyAwIDogYXJyYXlPZlN0cmluZ3NbaV0ubGVuZ3RoO1xuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eSAobm90IGFsbG93ZWQpXG4gICAgICAgICAgICAgICAgICAgIGlmIChzdHJpbmdMZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogY29udGFpbmVkIGFuIGVtcHR5IHN0cmluZy4gQXJyYXk9XCIgKyBKU09OLnN0cmluZ2lmeShhcnJheU9mU3RyaW5ncykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZXhjZWVkaW5nIG1heCBsZW5ndGhcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1heFN0cmluZ0xlbmd0aCA+IDAgJiYgc3RyaW5nTGVuZ3RoID4gbWF4U3RyaW5nTGVuZ3RoKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgc3RyaW5nIGV4Y2VlZGVkIG1heCBhbGxvd2VkIGxlbmd0aCAod2hpY2ggaXM6IFwiICsgbWF4U3RyaW5nTGVuZ3RoICsgXCIpLiBTdHJpbmcgd2FzOiBcIiArIGFycmF5T2ZTdHJpbmdzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoY2xpZW50VHMgPCAoMCkgfHwgY2xpZW50VHMgPiAoOTk5OTk5OTk5OTkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBwbGF0Zm9ybVxuICAgIHtcbiAgICAgICAgLy8gUG9ydCBvZiB0aGUgQysrIFNESydzIFBsYXRmb3JtL0dBUGxhdGZvcm0uaC4gQWJzdHJhY3QgbWVtYmVycyBhcmUgdGhlXG4gICAgICAgIC8vIEMrKyBwdXJlIHZpcnR1YWxzOyB0aGUgcmVzdCBkZWZhdWx0IHRvIHRoZSBzYW1lIHNlbnRpbmVscyBHQVBsYXRmb3JtLmNwcFxuICAgICAgICAvLyByZXR1cm5zOiBcIlwiIGZvciBzdHJpbmdzLCAtMSBmb3IgbnVtYmVycy4gLTEgbWVhbnMgXCJub3QgbWVhc3VyYWJsZSBvblxuICAgICAgICAvLyB0aGlzIHBsYXRmb3JtXCIsIHdoaWNoIGRvd25zdHJlYW0gY2FuIHRlbGwgYXBhcnQgZnJvbSBhIHJlYWwgMC5cbiAgICAgICAgZXhwb3J0IGFic3RyYWN0IGNsYXNzIEdBUGxhdGZvcm1cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIGFic3RyYWN0IGdldE9TVmVyc2lvbigpOiBzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgYWJzdHJhY3QgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6IHN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBhYnN0cmFjdCBnZXRCdWlsZFBsYXRmb3JtKCk6IHN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBhYnN0cmFjdCBnZXRQZXJzaXN0ZW50UGF0aCgpOiBzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgYWJzdHJhY3QgZ2V0RGV2aWNlTW9kZWwoKTogc3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIGFic3RyYWN0IGdldENvbm5lY3Rpb25UeXBlKCk6IHN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGdldEFkdmVydGlzaW5nSWQoKTogc3RyaW5nIHsgcmV0dXJuIFwiXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXREZXZpY2VJZCgpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0Q3B1TW9kZWwoKTogc3RyaW5nIHsgcmV0dXJuIFwiXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXRHcHVNb2RlbCgpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuICAgICAgICAgICAgcHVibGljIGdldE51bUNwdUNvcmVzKCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuICAgICAgICAgICAgcHVibGljIGdldFRvdGFsRGV2aWNlTWVtb3J5KCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuICAgICAgICAgICAgcHVibGljIGdldEFwcE1lbW9yeVVzYWdlKCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuICAgICAgICAgICAgcHVibGljIGdldFN5c01lbW9yeVVzYWdlKCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuICAgICAgICAgICAgcHVibGljIGdldEJvb3RUaW1lKCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuXG4gICAgICAgICAgICAvLyBKUy1vbmx5LCBsaWtlIHRoZSBpdGVtcyBzdG9yZTogYnJvd3Nlcl92ZXJzaW9uIGlzIG9uIHRoZSB3aXJlIGFuZFxuICAgICAgICAgICAgLy8gQysrIGhhcyBubyBicm93c2VyLiBEZWZhdWx0ZWQgc28gTm9kZSBpbmhlcml0cyB0aGUgc2VudGluZWwuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0QnJvd3NlclZlcnNpb24oKTogc3RyaW5nIHsgcmV0dXJuIFwiXCI7IH1cblxuICAgICAgICAgICAgLy8gQysrIGluc3RhbGxzIGl0cyB0ZXJtaW5hdGUgaGFuZGxlciBoZXJlLCBnYXRlZCBvbiB1c2VFcnJvclJlcG9ydGluZygpLlxuICAgICAgICAgICAgcHVibGljIG9uSW5pdCgpOiB2b2lkIHt9XG4gICAgICAgICAgICBwdWJsaWMgc2V0dXBVbmNhdWdodEV4Y2VwdGlvbkhhbmRsZXIoKTogdm9pZCB7fVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGRldmljZVxuICAgIHtcbiAgICAgICAgZXhwb3J0IGNsYXNzIE5hbWVWYWx1ZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZhbHVlOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKG5hbWU6c3RyaW5nLCB2YWx1ZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQURldmljZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBzZGtXcmFwcGVyVmVyc2lvbjpzdHJpbmcgPSBcImphdmFzY3JpcHQgNS4xLjBcIjtcblxuICAgICAgICAgICAgLy8gT3duZWQgaGVyZSwgbWlycm9yaW5nIEdBRGV2aWNlOjpfcGxhdGZvcm0gaW4gdGhlIEMrKyBTREsuIFNldCBieVxuICAgICAgICAgICAgLy8gR2FtZUFuYWx5dGljcy5pbml0KCkgYmVmb3JlIGFueXRoaW5nIHJlYWRzIGRldmljZSBpbmZvcm1hdGlvbiwgc29cbiAgICAgICAgICAgIC8vIG5vdGhpbmcgYmVsb3cgdG91Y2hlcyBhIGJyb3dzZXIgZ2xvYmFsIGF0IGNsYXNzLWRlZmluaXRpb24gdGltZS5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHBsYXRmb3JtOmdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybSA9IG51bGw7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2RrR2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjb25uZWN0aW9uVHlwZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHdyaXRhYmxlUGF0aDpzdHJpbmcgPSBcIlwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFBsYXRmb3JtKHBsYXRmb3JtOmdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQURldmljZS5wbGF0Zm9ybSA9IHBsYXRmb3JtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFBsYXRmb3JtKCk6IGdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5wbGF0Zm9ybTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gV3JhcHMgZ2V0UGVyc2lzdGVudFBhdGgoKSwgYXMgR0FEZXZpY2U6OmdldFdyaXRhYmxlUGF0aCgpIGRvZXMgaW4gQysrLlxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRXcml0YWJsZVBhdGgoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLndyaXRhYmxlUGF0aCB8fCAoR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRQZXJzaXN0ZW50UGF0aCgpIDogXCJcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0IGJ1aWxkUGxhdGZvcm0oKTogc3RyaW5nIHsgcmV0dXJuIEdBRGV2aWNlLnBsYXRmb3JtID8gR0FEZXZpY2UucGxhdGZvcm0uZ2V0QnVpbGRQbGF0Zm9ybSgpIDogXCJ1bmtub3duXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0IGRldmljZU1vZGVsKCk6IHN0cmluZyB7IHJldHVybiBHQURldmljZS5wbGF0Zm9ybSA/IEdBRGV2aWNlLnBsYXRmb3JtLmdldERldmljZU1vZGVsKCkgOiBcInVua25vd25cIjsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXQgZGV2aWNlTWFudWZhY3R1cmVyKCk6IHN0cmluZyB7IHJldHVybiBHQURldmljZS5wbGF0Zm9ybSA/IEdBRGV2aWNlLnBsYXRmb3JtLmdldERldmljZU1hbnVmYWN0dXJlcigpIDogXCJ1bmtub3duXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0IG9zVmVyc2lvbigpOiBzdHJpbmcgeyByZXR1cm4gR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRPU1ZlcnNpb24oKSA6IFwidW5rbm93biAwLjAuMFwiOyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldCBicm93c2VyVmVyc2lvbigpOiBzdHJpbmcgeyByZXR1cm4gR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRCcm93c2VyVmVyc2lvbigpIDogXCJcIjsgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRvdWNoKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRSZWxldmFudFNka1ZlcnNpb24oKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5zZGtXcmFwcGVyVmVyc2lvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDb25uZWN0aW9uVHlwZSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UuY29ubmVjdGlvblR5cGU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdXBkYXRlQ29ubmVjdGlvblR5cGUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gR0FEZXZpY2UucGxhdGZvcm0gPyBHQURldmljZS5wbGF0Zm9ybS5nZXRDb25uZWN0aW9uVHlwZSgpIDogXCJvZmZsaW5lXCI7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgcGxhdGZvcm1cbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IE5hbWVWYWx1ZVZlcnNpb24gPSBnYW1lYW5hbHl0aWNzLmRldmljZS5OYW1lVmFsdWVWZXJzaW9uO1xuICAgICAgICBpbXBvcnQgTmFtZVZlcnNpb24gPSBnYW1lYW5hbHl0aWNzLmRldmljZS5OYW1lVmVyc2lvbjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FQbGF0Zm9ybUJyb3dzZXIgZXh0ZW5kcyBHQVBsYXRmb3JtXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgb3NWZXJzaW9uUGFpcjpOYW1lVmVyc2lvbiA9IG51bGw7XG5cbiAgICAgICAgICAgIHByaXZhdGUgZ2V0T3NWZXJzaW9uUGFpcigpOiBOYW1lVmVyc2lvblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh0aGlzLm9zVmVyc2lvblBhaXIgPT09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgYWdlbnQ6c3RyaW5nID0gKHR5cGVvZiBuYXZpZ2F0b3IgIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAgICAgICAgICAgICAgPyBbbmF2aWdhdG9yLnBsYXRmb3JtLCBuYXZpZ2F0b3IudXNlckFnZW50LCBuYXZpZ2F0b3IuYXBwVmVyc2lvbiwgbmF2aWdhdG9yLnZlbmRvcl0uam9pbignICcpXG4gICAgICAgICAgICAgICAgICAgICAgICA6ICcnO1xuICAgICAgICAgICAgICAgICAgICB0aGlzLm9zVmVyc2lvblBhaXIgPSBHQVBsYXRmb3JtQnJvd3Nlci5tYXRjaEl0ZW0oYWdlbnQsIFtcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwid2luZG93c19waG9uZVwiLCBcIldpbmRvd3MgUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwid2luZG93c1wiLCBcIldpblwiLCBcIk5UXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBhZFwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUG9kXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImFuZHJvaWRcIiwgXCJBbmRyb2lkXCIsIFwiQW5kcm9pZFwiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYmxhY2tCZXJyeVwiLCBcIkJsYWNrQmVycnlcIiwgXCIvXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJtYWNfb3N4XCIsIFwiTWFjXCIsIFwiT1MgWFwiKSxcbiAgICAgICAgICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwidGl6ZW5cIiwgXCJUaXplblwiLCBcIlRpemVuXCIpLFxuICAgICAgICAgICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJsaW51eFwiLCBcIkxpbnV4XCIsIFwicnZcIiksXG4gICAgICAgICAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImthaV9vc1wiLCBcIktBSU9TXCIsIFwiS0FJT1NcIilcbiAgICAgICAgICAgICAgICAgICAgXSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLm9zVmVyc2lvblBhaXI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRPU1ZlcnNpb24oKTogc3RyaW5nIHsgcmV0dXJuIHRoaXMuZ2V0QnVpbGRQbGF0Zm9ybSgpICsgXCIgXCIgKyB0aGlzLmdldE9zVmVyc2lvblBhaXIoKS52ZXJzaW9uOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0QnVpbGRQbGF0Zm9ybSgpOiBzdHJpbmcgeyByZXR1cm4gdGhpcy5nZXRPc1ZlcnNpb25QYWlyKCkubmFtZTsgfVxuICAgICAgICAgICAgcHVibGljIGdldERldmljZU1hbnVmYWN0dXJlcigpOiBzdHJpbmcgeyByZXR1cm4gXCJ1bmtub3duXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXREZXZpY2VNb2RlbCgpOiBzdHJpbmcgeyByZXR1cm4gXCJ1bmtub3duXCI7IH1cbiAgICAgICAgICAgIHB1YmxpYyBnZXRQZXJzaXN0ZW50UGF0aCgpOiBzdHJpbmcgeyByZXR1cm4gXCJcIjsgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0Q29ubmVjdGlvblR5cGUoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBuYXZpZ2F0b3IgPT09ICd1bmRlZmluZWQnIHx8IG5hdmlnYXRvci5vbkxpbmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcDpzdHJpbmcgPSB0aGlzLmdldEJ1aWxkUGxhdGZvcm0oKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChwID09PSBcImlvc1wiIHx8IHAgPT09IFwiYW5kcm9pZFwiKSA/IFwid3dhblwiIDogXCJsYW5cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIFwib2ZmbGluZVwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0TnVtQ3B1Q29yZXMoKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICh0eXBlb2YgbmF2aWdhdG9yICE9PSAndW5kZWZpbmVkJyAmJiBuYXZpZ2F0b3IuaGFyZHdhcmVDb25jdXJyZW5jeSkgPyBuYXZpZ2F0b3IuaGFyZHdhcmVDb25jdXJyZW5jeSA6IC0xO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0VG90YWxEZXZpY2VNZW1vcnkoKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICh0eXBlb2YgbmF2aWdhdG9yICE9PSAndW5kZWZpbmVkJyAmJiAobmF2aWdhdG9yIGFzIGFueSkuZGV2aWNlTWVtb3J5KSA/IChuYXZpZ2F0b3IgYXMgYW55KS5kZXZpY2VNZW1vcnkgKiAxMDczNzQxODI0IDogLTE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRBcHBNZW1vcnlVc2FnZSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcgJiYgKHBlcmZvcm1hbmNlIGFzIGFueSkubWVtb3J5KSA/IChwZXJmb3JtYW5jZSBhcyBhbnkpLm1lbW9yeS51c2VkSlNIZWFwU2l6ZSA6IC0xO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZ2V0Qm9vdFRpbWUoKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICh0eXBlb2YgcGVyZm9ybWFuY2UgIT09ICd1bmRlZmluZWQnKSA/IE1hdGgucm91bmQocGVyZm9ybWFuY2Uubm93KCkpIDogLTE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBnZXRHcHVNb2RlbCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgZG9jdW1lbnQgIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2FudmFzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnY2FudmFzJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZ2w6IGFueSA9IGNhbnZhcy5nZXRDb250ZXh0KCd3ZWJnbCcpIHx8IGNhbnZhcy5nZXRDb250ZXh0KCdleHBlcmltZW50YWwtd2ViZ2wnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChnbClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXh0ID0gZ2wuZ2V0RXh0ZW5zaW9uKCdXRUJHTF9kZWJ1Z19yZW5kZXJlcl9pbmZvJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGV4dCkgeyByZXR1cm4gZ2wuZ2V0UGFyYW1ldGVyKGV4dC5VTk1BU0tFRF9SRU5ERVJFUl9XRUJHTCkgfHwgJyc7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSkge31cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGdldEJyb3dzZXJWZXJzaW9uKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgbmF2aWdhdG9yID09PSAndW5kZWZpbmVkJykgeyByZXR1cm4gXCJcIjsgfVxuICAgICAgICAgICAgICAgIHZhciB1YTpzdHJpbmcgPSBuYXZpZ2F0b3IudXNlckFnZW50O1xuICAgICAgICAgICAgICAgIHZhciB0ZW06c3RyaW5nW10gfCBudWxsO1xuICAgICAgICAgICAgICAgIHZhciBNOnN0cmluZ1tdID0gdWEubWF0Y2goLyhvcGVyYXxjaHJvbWV8c2FmYXJpfGZpcmVmb3h8dWJyb3dzZXJ8bXNpZXx0cmlkZW50fGZiYXYoPz1cXC8pKVxcLz9cXHMqKFxcZCspL2kpIHx8IFtdO1xuXG4gICAgICAgICAgICAgICAgaWYoTS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKHRoaXMuZ2V0QnVpbGRQbGF0Zm9ybSgpID09PSBcImlvc1wiKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3ZWJraXRfXCIgKyB0aGlzLmdldE9TVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoL3RyaWRlbnQvaS50ZXN0KE1bMV0pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGVtID0gL1xcYnJ2WyA6XSsoXFxkKykvZy5leGVjKHVhKSB8fCBbXTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICdJRSAnICsgKHRlbVsxXSB8fCAnJyk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoTVsxXSA9PT0gJ0Nocm9tZScpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0ZW0gPSB1YS5tYXRjaCgvXFxiKE9QUnxFZGdlfFVCcm93c2VyKVxcLyhcXGQrKS8pO1xuICAgICAgICAgICAgICAgICAgICBpZih0ZW0hPSBudWxsKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGVtLnNsaWNlKDEpLmpvaW4oJyAnKS5yZXBsYWNlKCdPUFInLCAnT3BlcmEnKS5yZXBsYWNlKCdVQnJvd3NlcicsICdVQycpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihNWzFdICYmIE1bMV0udG9Mb3dlckNhc2UoKSA9PT0gJ2ZiYXYnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVsxXSA9IFwiZmFjZWJvb2tcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoTVsyXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZmFjZWJvb2sgXCIgKyBNWzJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIE1TdHJpbmc6c3RyaW5nW10gPSBNWzJdPyBbTVsxXSwgTVsyXV06IFtuYXZpZ2F0b3IuYXBwTmFtZSwgbmF2aWdhdG9yLmFwcFZlcnNpb24sICctPyddO1xuXG4gICAgICAgICAgICAgICAgaWYoKHRlbSA9IHVhLm1hdGNoKC92ZXJzaW9uXFwvKFxcZCspL2kpKSAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVN0cmluZy5zcGxpY2UoMSwgMSwgdGVtWzFdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gTVN0cmluZy5qb2luKCcgJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gYmVmb3JldW5sb2FkIGlzIGEgYnJvd3NlciBkZXRhaWwsIHJlZ2lzdGVyZWQgaGVyZSByYXRoZXIgdGhhbiBpblxuICAgICAgICAgICAgLy8gR2FtZUFuYWx5dGljcy5pbml0KCkgd2hlcmUgaXQgdXNlZCB0byB0aHJvdyBvbiBpbXBvcnQgaW4gTm9kZS5cbiAgICAgICAgICAgIHB1YmxpYyBvbkluaXQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSAndW5kZWZpbmVkJyB8fCB0eXBlb2Ygd2luZG93LmFkZEV2ZW50TGlzdGVuZXIgIT09ICdmdW5jdGlvbicpIHsgcmV0dXJuOyB9XG4gICAgICAgICAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXCJiZWZvcmV1bmxvYWRcIiwgKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKCdhZGRFdmVudExpc3RlbmVyIHVubG9hZCcpO1xuICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGUubm90aWZ5QmVmb3JlVW5sb2FkTGlzdGVuZXJzKCk7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MudGhyZWFkaW5nLkdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1hdGNoSXRlbShhZ2VudDpzdHJpbmcsIGRhdGE6QXJyYXk8TmFtZVZhbHVlVmVyc2lvbj4pOk5hbWVWZXJzaW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpOYW1lVmVyc2lvbiA9IG5ldyBOYW1lVmVyc2lvbihcInVua25vd25cIiwgXCIwLjAuMFwiKTtcbiAgICAgICAgICAgICAgICB2YXIgbWF0aGNlc1Jlc3VsdDpzdHJpbmc7XG4gICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKG5ldyBSZWdFeHAoZGF0YVtpXS52YWx1ZSwgJ2knKS50ZXN0KGFnZW50KSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1hdGNoZXM6UmVnRXhwTWF0Y2hBcnJheSA9IGFnZW50Lm1hdGNoKG5ldyBSZWdFeHAoZGF0YVtpXS52ZXJzaW9uICsgJ1stIC86O10oW1xcXFxkLl9dKyknLCAnaScpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2ZXJzaW9uOnN0cmluZyA9ICcnO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGNoZXMgJiYgbWF0Y2hlc1sxXSkgeyBtYXRoY2VzUmVzdWx0ID0gbWF0Y2hlc1sxXTsgfVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGhjZXNSZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHBhcnRzOnN0cmluZ1tdID0gbWF0aGNlc1Jlc3VsdC5zcGxpdCgvWy5fXSsvKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IE1hdGgubWluKHBhcnRzLmxlbmd0aCwgMyk7IGogKz0gMSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gKz0gcGFydHNbal0gKyAoaiA8IE1hdGgubWluKHBhcnRzLmxlbmd0aCwgMykgLSAxID8gJy4nIDogJycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJzAuMC4wJztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5uYW1lID0gZGF0YVtpXS5uYW1lO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnZlcnNpb24gPSB2ZXJzaW9uO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHBsYXRmb3JtXG4gICAge1xuICAgICAgICAvLyBCcm93c2VyIGJ1aWxkIHRhcmdldC4gVGhlIE5vZGUgYnVuZGxlIGNvbXBpbGVzIG1ha2VQbGF0Zm9ybS5ub2RlLnRzXG4gICAgICAgIC8vIGluc3RlYWQ7IHRoaXMgaXMgdGhlIEpTIGFuYWxvZ3VlIG9mIEMrKydzIEdBRGV2aWNlUGxhdGZvcm0uaCBzZWxlY3Rpb24uXG4gICAgICAgIGV4cG9ydCBmdW5jdGlvbiBtYWtlUGxhdGZvcm0oKTogR0FQbGF0Zm9ybVxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IEdBUGxhdGZvcm1Ccm93c2VyKCk7XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmVcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IElHQVN0b3JhZ2UgPSBnYW1lYW5hbHl0aWNzLnN0b3JhZ2UuSUdBU3RvcmFnZTtcblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTdG9yZUFyZ3NPcGVyYXRvclxuICAgICAgICB7XG4gICAgICAgICAgICBFcXVhbCxcbiAgICAgICAgICAgIExlc3NPckVxdWFsLFxuICAgICAgICAgICAgTm90RXF1YWxcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVN0b3JlXG4gICAgICAgIHtcbiAgICAgICAgICAgIEV2ZW50cyA9IDAsXG4gICAgICAgICAgICBTZXNzaW9ucyA9IDEsXG4gICAgICAgICAgICBQcm9ncmVzc2lvbiA9IDJcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVN0b3JlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBU3RvcmUgPSBuZXcgR0FTdG9yZSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RvcmFnZTpJR0FTdG9yYWdlID0gbnVsbDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heE51bWJlck9mRW50cmllczpudW1iZXIgPSAyMDAwOyAgIC8vIGJyb3dzZXI6IGVudHJ5IGNvdW50XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhEYlNpemVCeXRlczpudW1iZXIgPSA2MjkxNDU2OyAgICAgLy8gTm9kZTogYnl0ZXMsIEdBU3RvcmUuY3BwOjE5XG4gICAgICAgICAgICBwcml2YXRlIGV2ZW50c1N0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHNlc3Npb25zU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25TdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdG9yZUl0ZW1zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFN0cmluZ0Zvcm1hdCA9IChzdHI6c3RyaW5nLCAuLi5hcmdzOnN0cmluZ1tdKSA9PiBzdHIucmVwbGFjZSgveyhcXGQrKX0vZywgKF8sIGluZGV4Om51bWJlcikgPT4gYXJnc1tpbmRleF0gfHwgJycpO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgS2V5Rm9ybWF0OnN0cmluZyA9IFwiR0E6OnswfTo6ezF9XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBFdmVudHNTdG9yZUtleTpzdHJpbmcgPSBcImdhX2V2ZW50XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBTZXNzaW9uc1N0b3JlS2V5OnN0cmluZyA9IFwiZ2Ffc2Vzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgUHJvZ3Jlc3Npb25TdG9yZUtleTpzdHJpbmcgPSBcImdhX3Byb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBJdGVtc1N0b3JlS2V5OnN0cmluZyA9IFwiZ2FfaXRlbXNcIjtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpIHt9XG5cbiAgICAgICAgICAgIC8vIEluamVjdGVkIGJ5IEdhbWVBbmFseXRpY3MuaW5pdCgpOiBsb2NhbFN0b3JhZ2UgaW4gdGhlIGJyb3dzZXIsIHRoZVxuICAgICAgICAgICAgLy8gdHdvLXRpZXIgZmlsZSBzdG9yZSBpbiBOb2RlIChzcGVjLCBcIlN0b3JhZ2VcIikuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFN0b3JhZ2Uoc3RvcmFnZTpJR0FTdG9yYWdlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlN0b3JhZ2UgaXMgYXZhaWxhYmxlPzogXCIgKyBHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JhZ2VBdmFpbGFibGUoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuc3RvcmFnZSAhPT0gbnVsbCAmJiBHQVN0b3JlLnN0b3JhZ2UuaXNBdmFpbGFibGUoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBieXRlczpudW1iZXIgPSBHQVN0b3JlLnN0b3JhZ2UgPyBHQVN0b3JlLnN0b3JhZ2UuZ2V0U2l6ZUJ5dGVzKCkgOiAtMTtcbiAgICAgICAgICAgICAgICBpZiAoYnl0ZXMgPj0gMCkgeyByZXR1cm4gYnl0ZXMgPiBHQVN0b3JlLk1heERiU2l6ZUJ5dGVzOyB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUubGVuZ3RoICsgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlLmxlbmd0aCA+IEdBU3RvcmUuTWF4TnVtYmVyT2ZFbnRyaWVzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlbGV0ZVNlc3Npb25DYWNoZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RvcmUuc3RvcmFnZSkgeyBHQVN0b3JlLnN0b3JhZ2UuZGVsZXRlU2Vzc2lvbkNhY2hlKCk7IH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcHV0KGtleTpzdHJpbmcsIHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBBIGZhaWxlZCB3cml0ZSB1c2VkIHRvIGJlIHN3YWxsb3dlZCBieSBhZGRFdmVudFRvU3RvcmUncyBjYXRjaDsgbG9nIGl0LlxuICAgICAgICAgICAgICAgIHRyeSB7IEdBU3RvcmUuc3RvcmFnZS5zZXRJdGVtKGtleSwgdmFsdWUpOyB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHsgR0FMb2dnZXIudyhcIlN0b3JlIHdyaXRlIGZhaWxlZCBmb3IgXCIgKyBrZXkgKyBcIjogXCIgKyAoZSAmJiBlLm5hbWUgPyBlLm5hbWUgOiBlKSk7IH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZWxlY3Qoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10sIHNvcnQ6Ym9vbGVhbiA9IGZhbHNlLCBtYXhDb3VudDpudW1iZXIgPSAwKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBhZGQ6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBhcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighYWRkKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoYWRkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQucHVzaChlbnRyeSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihzb3J0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnNvcnQoKGE6e1trZXk6c3RyaW5nXTogYW55fSwgYjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGFbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKSAtIChiW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYobWF4Q291bnQgPiAwICYmIHJlc3VsdC5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHJlc3VsdC5zbGljZSgwLCBtYXhDb3VudCArIDEpXG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGUoc3RvcmU6RUdBU3RvcmUsIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgYW55XT4sIHdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgd2hlcmVBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gd2hlcmVBcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZih1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBzZXRBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzRW50cnk6W3N0cmluZywgYW55XSA9IHNldEFyZ3Nbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc2V0QXJnc0VudHJ5WzBdXSA9IHNldEFyZ3NFbnRyeVsxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlbGV0ZShzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGRlbDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFkZWwpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihkZWwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5zcGxpY2UoaSwgMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAtLWk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5zZXJ0KHN0b3JlOkVHQVN0b3JlLCBuZXdFbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9LCByZXBsYWNlOmJvb2xlYW4gPSBmYWxzZSwgcmVwbGFjZUtleTpzdHJpbmcgPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVwbGFjZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlS2V5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgcmVwbGFjZWQ6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVtyZXBsYWNlS2V5XSA9PSBuZXdFbnRyeVtyZXBsYWNlS2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gbmV3RW50cnkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzXSA9IG5ld0VudHJ5W3NdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXBsYWNlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighcmVwbGFjZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNhdmUoZ2FtZUtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3Qgc2F2ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0b3JlLnB1dChHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5FdmVudHNTdG9yZUtleSksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnB1dChHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5KSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKSk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5wdXQoR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuUHJvZ3Jlc3Npb25TdG9yZUtleSksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSkpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUucHV0KEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpLCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBsb2FkKGdhbWVLZXk6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlN0b3JhZ2UgaXMgbm90IGF2YWlsYWJsZSwgY2Fubm90IGxvYWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gSlNPTi5wYXJzZShHQVN0b3JlLnN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5FdmVudHNTdG9yZUtleSkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdldmVudHMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IEpTT04ucGFyc2UoR0FTdG9yZS5zdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5TdHJpbmdGb3JtYXQoR0FTdG9yZS5LZXlGb3JtYXQsIGdhbWVLZXksIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnc2Vzc2lvbnMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gSlNPTi5wYXJzZShHQVN0b3JlLnN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5KSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdwcm9ncmVzc2lvbicgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSBKU09OLnBhcnNlKEdBU3RvcmUuc3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpKSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0ge307XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2l0ZW1zJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSB7fTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SXRlbShnYW1lS2V5OnN0cmluZywga2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuU3RyaW5nRm9ybWF0KEdBU3RvcmUuS2V5Rm9ybWF0LCBnYW1lS2V5LCBrZXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoa2V5V2l0aFByZWZpeCBpbiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEl0ZW0oZ2FtZUtleTpzdHJpbmcsIGtleTpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLlN0cmluZ0Zvcm1hdChHQVN0b3JlLktleUZvcm1hdCwgZ2FtZUtleSwga2V5KTtcbiAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gYXMgc3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldFN0b3JlKHN0b3JlOkVHQVN0b3JlKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2goc3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLkV2ZW50czpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlNlc3Npb25zOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5Qcm9ncmVzc2lvbjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJHQVN0b3JlLmdldFN0b3JlKCk6IENhbm5vdCBmaW5kIHN0b3JlOiBcIiArIHN0b3JlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0b3JhZ2VcbiAgICB7XG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVN0b3JhZ2VCcm93c2VyIGltcGxlbWVudHMgSUdBU3RvcmFnZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZTpib29sZWFuID0gZmFsc2U7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGxvY2FsU3RvcmFnZSA9PT0gJ29iamVjdCcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJywgJ3llcycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Rlc3RpbmdMb2NhbFN0b3JhZ2UnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuYXZhaWxhYmxlID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSkge31cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGdldEl0ZW0oa2V5OnN0cmluZyk6IHN0cmluZyB8IG51bGwgeyByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oa2V5KTsgfVxuICAgICAgICAgICAgcHVibGljIHNldEl0ZW0oa2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZCB7IGxvY2FsU3RvcmFnZS5zZXRJdGVtKGtleSwgdmFsdWUpOyB9XG4gICAgICAgICAgICBwdWJsaWMgcmVtb3ZlSXRlbShrZXk6c3RyaW5nKTogdm9pZCB7IGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKGtleSk7IH1cbiAgICAgICAgICAgIHB1YmxpYyBpc0F2YWlsYWJsZSgpOiBib29sZWFuIHsgcmV0dXJuIHRoaXMuYXZhaWxhYmxlOyB9XG4gICAgICAgICAgICBwdWJsaWMgZ2V0U2l6ZUJ5dGVzKCk6IG51bWJlciB7IHJldHVybiAtMTsgfVxuICAgICAgICAgICAgcHVibGljIGRlbGV0ZVNlc3Npb25DYWNoZSgpOiB2b2lkIHt9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmFnZVxuICAgIHtcbiAgICAgICAgZXhwb3J0IGZ1bmN0aW9uIG1ha2VTdG9yYWdlKCk6IElHQVN0b3JhZ2VcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBHQVN0b3JhZ2VCcm93c2VyKCk7XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RhdGVcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBHQURldmljZSA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLkdBRGV2aWNlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVN0YXRlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2RrRXJyb3I6c3RyaW5nID0gXCJzZGtfZXJyb3JcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9DVVNUT01fRklFTERTX0NPVU5UOm51bWJlciA9IDUwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0NVU1RPTV9GSUVMRFNfS0VZX0xFTkdUSDpudW1iZXIgPSA2NDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9DVVNUT01fRklFTERTX1ZBTFVFX1NUUklOR19MRU5HVEg6bnVtYmVyID0gMjU2O1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBU3RhdGUgPSBuZXcgR0FTdGF0ZSgpO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLl9pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQgPSB0cnVlO1xuICAgICAgICAgICAgICAgIHRoaXMuaXNVbmxvYWRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VySWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRVc2VySWQodXNlcklkOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnVzZXJJZCA9IHVzZXJJZDtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGlkZW50aWZpZXI6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRJZGVudGlmaWVyKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZXh0VXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXh0VXNlcklkKHVpZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5leHRVc2VySWQgPSB1aWQ7IFxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEV4dFVzZXJJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5leHRVc2VySWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNJbml0aWFsaXplZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluaXRpYWxpemVkKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0aWFsaXplZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvblN0YXJ0Om51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvblN0YXJ0KCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzZXNzaW9uTnVtOm51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbk51bSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgaXNVbmxvYWRpbmc6Ym9vbGVhbjtcblxuICAgICAgICAgICAgcHJpdmF0ZSB0cmFuc2FjdGlvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFRyYW5zYWN0aW9uTnVtKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvbklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbklkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAzOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lS2V5OnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZUtleSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVTZWNyZXQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lU2VjcmV0KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMzpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBjdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM6IHsgW2tleTogc3RyaW5nXTogYW55IH0gPSB7fTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VJdGVtVHlwZXModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtIHR5cGVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYnVpbGQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRCdWlsZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5idWlsZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QnVpbGQodmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQgPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGJ1aWxkIHZlcnNpb246IFwiICsgdmFsdWUpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHVzZU1hbnVhbFNlc3Npb25IYW5kbGluZzpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnVzZU1hbnVhbFNlc3Npb25IYW5kbGluZztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBfaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZ0NhY2hlZDp7W2tleTpzdHJpbmddOiBhbnl9O1xuICAgICAgICAgICAgcHJpdmF0ZSBjb25maWd1cmF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHRyYWNraW5nQ29uZmlndXJhdGlvbnM6IGFueVtdID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NJc1JlYWR5OmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnM6QXJyYXk8eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgYmVmb3JlVW5sb2FkTGlzdGVuZXJzOiBBcnJheTx7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgaW5pdEF1dGhvcml6ZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBjbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0Om51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBjb25maWdzSGFzaDpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBhYklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QUJUZXN0aW5nSWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYWJJZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBhYlZhcmlhbnRJZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ1ZhcmlhbnRJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBkZWZhdWx0VXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc2V0RGVmYXVsdElkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlZmF1bHRVc2VySWQgPSAhdmFsdWUgPyBcIlwiIDogdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RGVmYXVsdElkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWdEZWZhdWx0Ontba2V5OnN0cmluZ106IHN0cmluZ30gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNka0NvbmZpZygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmlyc3Q6c3RyaW5nO1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqc29uIGluIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZmlyc3QgJiYgY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWc7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmlyc3Q6c3RyaW5nO1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqc29uIGluIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZmlyc3QgJiYgY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHByb2dyZXNzaW9uVHJpZXM6e1trZXk6c3RyaW5nXTogbnVtYmVyfSA9IHt9O1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBEZWZhdWx0VXNlcklkS2V5OnN0cmluZyA9IFwiZGVmYXVsdF91c2VyX2lkXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFNlc3Npb25OdW1LZXk6c3RyaW5nID0gXCJzZXNzaW9uX251bVwiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBUcmFuc2FjdGlvbk51bUtleTpzdHJpbmcgPSBcInRyYW5zYWN0aW9uX251bVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDFLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDJLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDNLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wM1wiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZGtDb25maWdDYWNoZWRLZXk6c3RyaW5nID0gXCJzZGtfY29uZmlnX2NhY2hlZFwiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBMYXN0VXNlZElkZW50aWZpZXJLZXk6IHN0cmluZyA9IFwibGFzdF91c2VkX2lkZW50aWZpZXJcIjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0VuYWJsZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAxS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFNlc3Npb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uTnVtSW50Om51bWJlciA9IEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpICsgMTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW0gPSBzZXNzaW9uTnVtSW50O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJhbnNhY3Rpb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpICsgMTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtID0gdHJhbnNhY3Rpb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRyaWVzOm51bWJlciA9IEdBU3RhdGUuZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbikgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl0gPSB0cmllcztcblxuICAgICAgICAgICAgICAgIC8vIFBlcnNpc3RcbiAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICB2YWx1ZXNbXCJwcm9ncmVzc2lvblwiXSA9IHByb2dyZXNzaW9uO1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInRyaWVzXCJdID0gdHJpZXM7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuUHJvZ3Jlc3Npb24sIHZhbHVlcywgdHJ1ZSwgXCJwcm9ncmVzc2lvblwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihwcm9ncmVzc2lvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBkZWxldGUgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBEZWxldGVcbiAgICAgICAgICAgICAgICB2YXIgcGFybXM6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgcGFybXMucHVzaChbXCJwcm9ncmVzc2lvblwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgcHJvZ3Jlc3Npb25dKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgcGFybXMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEtleXMoZ2FtZUtleTpzdHJpbmcsIGdhbWVTZWNyZXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZUtleSA9IGdhbWVLZXk7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lU2VjcmV0ID0gZ2FtZVNlY3JldDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nID0gZmxhZztcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVXNlIG1hbnVhbCBzZXNzaW9uIGhhbmRsaW5nOiBcIiArIGZsYWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBQb3J0IG9mIEdBU3RhdGU6OnVzZUVycm9yUmVwb3J0aW5nKCkuIEMrKyBkZWZhdWx0cyB0aGlzIHRvIHRydWU7IHRoZVxuICAgICAgICAgICAgLy8gSlMgU0RLIGhhcyBuZXZlciByZXBvcnRlZCBjcmFzaGVzLCBzbyBpdCBkZWZhdWx0cyBPRkYgaGVyZSAoc3BlYyxcbiAgICAgICAgICAgIC8vIGRpdmVyZ2VuY2UgNCkuIFRoZSBOb2RlIHBsYXRmb3JtIGluc3RhbGxzIGl0cyBtb25pdG9yIHJlZ2FyZGxlc3MgYW5kXG4gICAgICAgICAgICAvLyBjaGVja3MgdGhpcyBmbGFnIHdoZW4gaXQgZmlyZXMsIHNvIGVuYWJsaW5nIGxhdGUgc3RpbGwgd29ya3MuXG4gICAgICAgICAgICBwcml2YXRlIF9lbmFibGVFcnJvclJlcG9ydGluZzpib29sZWFuID0gZmFsc2U7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlRXJyb3JSZXBvcnRpbmcoZmxhZzpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuX2VuYWJsZUVycm9yUmVwb3J0aW5nID0gZmxhZztcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVXNlIGVycm9yIHJlcG9ydGluZzogXCIgKyBmbGFnKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1c2VFcnJvclJlcG9ydGluZygpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuX2VuYWJsZUVycm9yUmVwb3J0aW5nO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZzpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCA9IGZsYWc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gUkVRVUlSRUQgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ2XCJdID0gMjtcbiAgICAgICAgICAgICAgICAvLyBFdmVudCBVVUlEXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJldmVudF91dWlkXCJdID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuICAgICAgICAgICAgICAgIC8vIFVzZXIgaWRlbnRpZmllclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1widXNlcl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllcjtcblxuICAgICAgICAgICAgICAgIC8vIGV4dCB1c2VyIGlkXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5leHRVc2VySWQgJiYgR0FTdGF0ZS5pbnN0YW5jZS5leHRVc2VySWQubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1widXNlcl9pZF9leHRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmV4dFVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDbGllbnQgVGltZXN0YW1wICh0aGUgYWRqdXN0ZWQgdGltZXN0YW1wKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2xpZW50X3RzXCJdID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSBtYWtlIChoYXJkY29kZWQgdG8gYXBwbGUpXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImRldmljZVwiXSA9IEdBRGV2aWNlLmRldmljZU1vZGVsO1xuICAgICAgICAgICAgICAgIC8vIEJyb3dzZXIgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnJvd3Nlcl92ZXJzaW9uXCJdID0gR0FEZXZpY2UuYnJvd3NlclZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBudW1iZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLlNlc3Npb25OdW1LZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uX3R5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHJlbW90ZSBjb25maWdzXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS50cmFja2luZ0NvbmZpZ3VyYXRpb25zICYmIEdBU3RhdGUuaW5zdGFuY2UudHJhY2tpbmdDb25maWd1cmF0aW9ucy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25maWd1cmF0aW9uc192M1wiXSA9IEdBU3RhdGUuaW5zdGFuY2UudHJhY2tpbmdDb25maWd1cmF0aW9ucztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBL0IgdGVzdGluZ1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuYWJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYWJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmFiSWQ7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImFiX3ZhcmlhbnRfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmFiVmFyaWFudElkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gQ09ORElUSU9OQUwgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwIGJ1aWxkIHZlcnNpb24gKHVzZSBpZiBub3QgbmlsKVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJ1aWxkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGFubm90YXRpb25zO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gUkVRVUlSRUQgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ2XCJdID0gMjtcbiAgICAgICAgICAgICAgICAvLyBFdmVudCBVVUlEXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJldmVudF91dWlkXCJdID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmdldElkZW50aWZpZXIoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkxhc3RVc2VkSWRlbnRpZmllcktleSwgR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCkpO1xuXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1widXNlcl9pZFwiXSA9IEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpO1xuXG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XG5cbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG5cbiAgICAgICAgICAgICAgICAvLyBCdWlsZFxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuZ2V0QnVpbGQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcImJ1aWxkXCJdID0gR0FTdGF0ZS5nZXRCdWlsZCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2Vzc2lvbl9udW1cIl0gPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJyYW5kb21fc2FsdFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGluaXRBbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnRUc0FkanVzdGVkKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHNBZGp1c3RlZEludGVnZXI6bnVtYmVyID0gY2xpZW50VHMgKyBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQ7XG5cbiAgICAgICAgICAgICAgICBpZihHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUc0FkanVzdGVkSW50ZWdlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXNzaW9uSXNTdGFydGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQgIT0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2FjaGVJZGVudGlmaWVyKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UudXNlcklkO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiaWRlbnRpZmllciwge2NsZWFuOlwiICsgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyICsgXCJ9XCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZVBlcnNpc3RlZFN0YXRlcygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gZ2V0IGFuZCBleHRyYWN0IHN0b3JlZCBzdGF0ZXNcbiAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5sb2FkKEdBU3RhdGUuZ2V0R2FtZUtleSgpKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgaW50byBHQVN0YXRlIGluc3RhbmNlXG4gICAgICAgICAgICAgICAgdmFyIGluc3RhbmNlOkdBU3RhdGUgPSBHQVN0YXRlLmluc3RhbmNlO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2V0RGVmYXVsdElkKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXkpIDogR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpKTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNlc3Npb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2Vzc2lvbk51bUtleSkgIT0gbnVsbCA/IE51bWJlcihHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2Vzc2lvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5KSkgOiAwLjA7XG5cbiAgICAgICAgICAgICAgICAvLyByZXN0b3JlIGRpbWVuc2lvbiBzZXR0aW5nc1xuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAxS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAxS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAxIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMktleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5EaW1lbnNpb24wMktleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMiBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDNLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuRGltZW5zaW9uMDNLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDMgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGdldCBjYWNoZWQgaW5pdCBjYWxsIHZhbHVlc1xuICAgICAgICAgICAgICAgIHZhciBzZGtDb25maWdDYWNoZWRTdHJpbmc6c3RyaW5nID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICBpZiAoc2RrQ29uZmlnQ2FjaGVkU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gZGVjb2RlIEpTT05cbiAgICAgICAgICAgICAgICAgICAgdmFyIHNka0NvbmZpZ0NhY2hlZCA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2RrQ29uZmlnQ2FjaGVkU3RyaW5nKSk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYXN0VXNlZElkZW50aWZpZXI6c3RyaW5nID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkxhc3RVc2VkSWRlbnRpZmllcktleSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwibGFzdFVzZWRJZGVudGlmaWVyPVwiICsgbGFzdFVzZWRJZGVudGlmaWVyICsgXCIsIEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpPVwiICsgR0FTdGF0ZS5nZXRJZGVudGlmaWVyKCkpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGxhc3RVc2VkSWRlbnRpZmllciAhPSBudWxsICYmIGxhc3RVc2VkSWRlbnRpZmllciAhPSBHQVN0YXRlLmdldElkZW50aWZpZXIoKSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTmV3IGlkZW50aWZpZXIgc3BvdHRlZCBjb21wYXJlZCB0byBsYXN0IG9uZSB1c2VkLCBjbGVhcmluZyBjYWNoZWQgY29uZmlncyBoYXNoISFcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZFtcImNvbmZpZ3NfaGFzaFwiXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBzZGtDb25maWdDYWNoZWRbXCJjb25maWdzX2hhc2hcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY3VycmVudFNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRTZGtDb25maWcoKTtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY29uZmlnc0hhc2ggPSBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmFiSWQgPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl0gPyBjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5hYlZhcmlhbnRJZCA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImFiX3ZhcmlhbnRfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciByZXN1bHRzX2dhX3Byb2dyZXNzaW9uOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuUHJvZ3Jlc3Npb24pO1xuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb24ubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6e1trZXk6c3RyaW5nXTogYW55fSA9IHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb25baV07XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVzdWx0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcmVzdWx0W1wicHJvZ3Jlc3Npb25cIl0gYXMgc3RyaW5nXSA9IHJlc3VsdFtcInRyaWVzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzOm51bWJlcik6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gc2VydmVyVHMgLSBjbGllbnRUcztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZm9ybWF0U3RyaW5nKHM6c3RyaW5nLCBhcmdzOkFycmF5PHN0cmluZz4pOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZm9ybWF0dGVkOiBzdHJpbmcgPSBzO1xuICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7IGkrKylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciByZWdleHAgPSBuZXcgUmVnRXhwKCdcXFxceycgKyBpICsgJ1xcXFx9JywgJ2dpJyk7XG4gICAgICAgICAgICAgICAgICAgIGZvcm1hdHRlZCA9IGZvcm1hdHRlZC5yZXBsYWNlKHJlZ2V4cCwgYXJndW1lbnRzW2ldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZvcm1hdHRlZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIGVycm9yQ2FsbGJhY2s6KGJhc2VNZXNzYWdlOnN0cmluZywgbWVzc2FnZTpzdHJpbmcpID0+IHZvaWQ9bnVsbCk6IHtbaWQ6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6e1tpZDpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICBpZihmaWVsZHMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgICAgICBmb3IodmFyIGtleSBpbiBmaWVsZHMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZTphbnkgPSBmaWVsZHNba2V5XTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWtleSB8fCAhdmFsdWUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJhc2VNZXNzYWdlOnN0cmluZyA9IFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9ezB9LCB2YWx1ZT17MX0gaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyBrZXkgb3IgdmFsdWUgaXMgbnVsbFwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IEdBU3RhdGUuZm9ybWF0U3RyaW5nKGJhc2VNZXNzYWdlLCBba2V5LCB2YWx1ZV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVycm9yQ2FsbGJhY2spXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmKGNvdW50IDwgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVnZXggPSBuZXcgUmVnRXhwKFwiXlthLXpBLVowLTlfXXsxLFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIICsgXCJ9JFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChrZXksIHJlZ2V4KSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0eXBlID0gdHlwZW9mIHZhbHVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlID09PSBcInN0cmluZ1wiIHx8IHZhbHVlIGluc3RhbmNlb2YgU3RyaW5nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVBc1N0cmluZzpzdHJpbmcgPSB2YWx1ZSBhcyBzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHZhbHVlQXNTdHJpbmcubGVuZ3RoIDw9IEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSCAmJiB2YWx1ZUFzU3RyaW5nLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0W2tleV0gPSB2YWx1ZUFzU3RyaW5nO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJhc2VNZXNzYWdlOiBzdHJpbmcgPSBcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PXswfSwgdmFsdWU9ezF9IGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMgdmFsdWUgaXMgYW4gZW1wdHkgc3RyaW5nIG9yIGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY2hhcmFjdGVycyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX1ZBTFVFX1NUUklOR19MRU5HVEggKyBcIilcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTogc3RyaW5nID0gR0FTdGF0ZS5mb3JtYXRTdHJpbmcoYmFzZU1lc3NhZ2UsIFtrZXksIHZhbHVlXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXJyb3JDYWxsYmFjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZih0eXBlID09PSBcIm51bWJlclwiIHx8IHZhbHVlIGluc3RhbmNlb2YgTnVtYmVyKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVBc051bWJlcjpudW1iZXIgPSB2YWx1ZSBhcyBudW1iZXI7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFtrZXldID0gdmFsdWVBc051bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFzZU1lc3NhZ2U6IHN0cmluZyA9IFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9ezB9LCB2YWx1ZT17MX0gaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyB2YWx1ZSBpcyBub3QgYSBzdHJpbmcgb3IgbnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTogc3RyaW5nID0gR0FTdGF0ZS5mb3JtYXRTdHJpbmcoYmFzZU1lc3NhZ2UsIFtrZXksIHZhbHVlXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGVycm9yQ2FsbGJhY2spIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlLCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYmFzZU1lc3NhZ2U6IHN0cmluZyA9IFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9ezB9LCB2YWx1ZT17MX0gaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyBrZXkgY29udGFpbnMgaWxsZWdhbCBjaGFyYWN0ZXIsIGlzIGVtcHR5IG9yIGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY2hhcmFjdGVycyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEggKyBcIilcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6IHN0cmluZyA9IEdBU3RhdGUuZm9ybWF0U3RyaW5nKGJhc2VNZXNzYWdlLCBba2V5LCB2YWx1ZV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXJyb3JDYWxsYmFjaykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXJyb3JDYWxsYmFjayhiYXNlTWVzc2FnZSwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGJhc2VNZXNzYWdlOiBzdHJpbmcgPSBcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PXswfSwgdmFsdWU9ezF9IGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdCBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGN1c3RvbSBmaWVsZHMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVCArIFwiKVwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOiBzdHJpbmcgPSBHQVN0YXRlLmZvcm1hdFN0cmluZyhiYXNlTWVzc2FnZSwgW2tleSwgdmFsdWVdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChlcnJvckNhbGxiYWNrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yQ2FsbGJhY2soYmFzZU1lc3NhZ2UsIG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMSBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAxIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDIgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDIoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMiBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAyKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAzIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAzKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDMgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMyhcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29uZmlndXJhdGlvblN0cmluZ1ZhbHVlKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTpzdHJpbmcpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0udG9TdHJpbmcoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGRlZmF1bHRWYWx1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29uZmlndXJhdGlvbkpzb25WYWx1ZShrZXk6c3RyaW5nLCBkZWZhdWx0VmFsdWU6YW55KTphbnlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZGVmYXVsdFZhbHVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1JlbW90ZUNvbmZpZ3NSZWFkeSgpOmJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzSXNSZWFkeTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKSA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluZGV4ID0gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIGlmKGluZGV4ID4gLTEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZygpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwb3B1bGF0ZUNvbmZpZ3VyYXRpb25zKHNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNvbmZpZ3VyYXRpb25zOmFueVtdID0gc2RrQ29uZmlnW1wiY29uZmlnc1wiXTtcblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudHJhY2tpbmdDb25maWd1cmF0aW9ucyA9IFtdXG5cbiAgICAgICAgICAgICAgICBpZihjb25maWd1cmF0aW9ucylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGNvbmZpZ3VyYXRpb25zLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbjp7W2tleTpzdHJpbmddOiBhbnl9ID0gY29uZmlndXJhdGlvbnNbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3VyYXRpb24pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBjb25maWd1cmF0aW9uW1wia2V5XCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZTphbnkgPSBjb25maWd1cmF0aW9uW1widmFsdWVcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHN0YXJ0X3RzOm51bWJlciA9IGNvbmZpZ3VyYXRpb25bXCJzdGFydF90c1wiXSA/IGNvbmZpZ3VyYXRpb25bXCJzdGFydF90c1wiXSA6IE51bWJlci5NSU5fVkFMVUU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGVuZF90czpudW1iZXIgPSBjb25maWd1cmF0aW9uW1wiZW5kX3RzXCJdID8gY29uZmlndXJhdGlvbltcImVuZF90c1wiXSA6IE51bWJlci5NQVhfVkFMVUU7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2xpZW50X3RzX2FkanVzdGVkOm51bWJlciA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoa2V5ICYmIHZhbHVlICYmIGNsaWVudF90c19hZGp1c3RlZCA+IHN0YXJ0X3RzICYmIGNsaWVudF90c19hZGp1c3RlZCA8IGVuZF90cylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiY29uZmlndXJhdGlvbiBhZGRlZDogXCIgKyBKU09OLnN0cmluZ2lmeShjb25maWd1cmF0aW9uKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHRyYWNrQ29uZmlnOmFueSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJhY2tDb25maWdbXCJrZXlcIl0gPSBjb25maWd1cmF0aW9uW1wia2V5XCJdXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJhY2tDb25maWdbXCJpZFwiXSA9IGNvbmZpZ3VyYXRpb25bXCJpZFwiXVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyYWNrQ29uZmlnW1widnNuXCJdID0gY29uZmlndXJhdGlvbltcInZzblwiXVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS50cmFja2luZ0NvbmZpZ3VyYXRpb25zLnB1c2godHJhY2tDb25maWcpXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzSXNSZWFkeSA9IHRydWU7XG5cbiAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXJzOkFycmF5PHsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0+ID0gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGxpc3RlbmVycy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGxpc3RlbmVyc1tpXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGlzdGVuZXJzW2ldLm9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyOiB7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYmVmb3JlVW5sb2FkTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpIDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYmVmb3JlVW5sb2FkTGlzdGVuZXJzLnB1c2gobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyOiB7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluZGV4ID0gR0FTdGF0ZS5pbnN0YW5jZS5iZWZvcmVVbmxvYWRMaXN0ZW5lcnMuaW5kZXhPZihsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgaWYgKGluZGV4ID4gLTEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJlZm9yZVVubG9hZExpc3RlbmVycy5zcGxpY2UoaW5kZXgsIDEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBub3RpZnlCZWZvcmVVbmxvYWRMaXN0ZW5lcnMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBsaXN0ZW5lcnM6IEFycmF5PHsgb25CZWZvcmVVbmxvYWQ6ICgpID0+IHZvaWQgfT4gPSBHQVN0YXRlLmluc3RhbmNlLmJlZm9yZVVubG9hZExpc3RlbmVycztcblxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGlzdGVuZXJzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGxpc3RlbmVyc1tpXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGlzdGVuZXJzW2ldLm9uQmVmb3JlVW5sb2FkKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGFza3NcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFNka0Vycm9yVGFza1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhDb3VudDpudW1iZXIgPSAxMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGNvdW50TWFwOntba2V5OnN0cmluZ106IG51bWJlcn0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IHRpbWVzdGFtcE1hcDp7W2tleTpzdHJpbmddOiBEYXRlfSA9IHt9O1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGV4ZWN1dGUodXJsOnN0cmluZywgdHlwZTpzdHJpbmcsIHBheWxvYWREYXRhOnN0cmluZywgc2VjcmV0S2V5OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbm93OkRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICAgICAgICAgICAgaWYoIVNka0Vycm9yVGFzay50aW1lc3RhbXBNYXBbdHlwZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2sudGltZXN0YW1wTWFwW3R5cGVdID0gbm93O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZighU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIGRpZmY6bnVtYmVyID0gbm93LmdldFRpbWUoKSAtIFNka0Vycm9yVGFzay50aW1lc3RhbXBNYXBbdHlwZV0uZ2V0VGltZSgpO1xuICAgICAgICAgICAgICAgIHZhciBkaWZmU2Vjb25kczpudW1iZXIgPSBkaWZmIC8gMTAwMDtcbiAgICAgICAgICAgICAgICBpZihkaWZmU2Vjb25kcyA+PSAzNjAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLnRpbWVzdGFtcE1hcFt0eXBlXSA9IG5vdztcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPj0gU2RrRXJyb3JUYXNrLk1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBoYXNoSG1hYzpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKHNlY3JldEtleSwgcGF5bG9hZERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudCA9IGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGkuZ2V0Q2xpZW50KCk7XG4gICAgICAgICAgICAgICAgaWYgKCFjbGllbnQpIHsgcmV0dXJuOyB9XG4gICAgICAgICAgICAgICAgY2xpZW50LnNlbmRSZXF1ZXN0KHVybCwgaGFzaEhtYWMsIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShwYXlsb2FkRGF0YSksIGZhbHNlKS50aGVuKChyZXNwb25zZSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdGV4dDpzdHJpbmcgPSByZXNwb25zZS5wYWNrZXQgJiYgcmVzcG9uc2UucGFja2V0Lmxlbmd0aCA/IG5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShyZXNwb25zZS5wYWNrZXQpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoIXRleHQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZGsgZXJyb3IgZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyAocmVzcG9uc2Uuc3RhdHVzVGV4dCB8fCBcIlwiKSArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByZXNwb25zZS5jb2RlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZihyZXNwb25zZS5jb2RlICE9IDIwMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNkayBlcnJvciBmYWlsZWQuIHJlc3BvbnNlIGNvZGUgbm90IDIwMC4gc3RhdHVzIGNvZGU6IFwiICsgcmVzcG9uc2UuY29kZSArIFwiLCBkZXNjcmlwdGlvbjogXCIgKyAocmVzcG9uc2Uuc3RhdHVzVGV4dCB8fCBcIlwiKSArIFwiLCBib2R5OiBcIiArIHRleHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSArIDE7XG4gICAgICAgICAgICAgICAgfSkuY2F0Y2goKGU6YW55KSA9PiB7IEdBTG9nZ2VyLmUoXCJzZGsgZXJyb3IgcmVxdWVzdCBmYWlsZWQ6IFwiICsgZSk7IH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBTZGtFcnJvclRhc2sgPSBnYW1lYW5hbHl0aWNzLnRhc2tzLlNka0Vycm9yVGFzaztcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yQ2F0ZWdvcnkgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckNhdGVnb3J5O1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBcmVhID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JBcmVhO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JBY3Rpb24gPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5FR0FTZGtFcnJvckFjdGlvbjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yUGFyYW1ldGVyID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuRUdBU2RrRXJyb3JQYXJhbWV0ZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBSFRUUEFwaVxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBSFRUUEFwaSA9IG5ldyBHQUhUVFBBcGkoKTtcbiAgICAgICAgICAgIHByaXZhdGUgcHJvdG9jb2w6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBob3N0TmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSByZW1vdGVDb25maWdzVmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGJhc2VVcmw6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSByZW1vdGVDb25maWdzQmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzVXJsUGF0aDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHVzZUd6aXA6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9FUlJPUl9NRVNTQUdFX0xFTkdUSDpudW1iZXIgPSAyNTY7XG5cbiAgICAgICAgICAgIC8vIEluamVjdGVkIGJ5IEdhbWVBbmFseXRpY3MuaW5pdCgpLiBJbi1mbGlnaHQgcmVxdWVzdHMgYXJlIHRyYWNrZWQgc29cbiAgICAgICAgICAgIC8vIG9uUXVpdCgpIGNhbiBhd2FpdCBkZWxpdmVyeTsgZWFjaCBwcm9taXNlIHdyYXBzIHRoZSByZXNwb25zZSBDQUxMQkFDSyxcbiAgICAgICAgICAgIC8vIG5vdCBqdXN0IHRoZSB0cmFuc3BvcnQsIGJlY2F1c2UgdGhlIGNhbGxiYWNrIG11dGF0ZXMgdGhlIHN0b3JlLlxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2xpZW50OklHQUh0dHBDbGllbnQgPSBudWxsO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5GbGlnaHQ6QXJyYXk8UHJvbWlzZTx2b2lkPj4gPSBbXTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDbGllbnQoY2xpZW50OklHQUh0dHBDbGllbnQpOiB2b2lkIHsgR0FIVFRQQXBpLmNsaWVudCA9IGNsaWVudDsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnQoKTogSUdBSHR0cENsaWVudCB7IHJldHVybiBHQUhUVFBBcGkuY2xpZW50OyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluRmxpZ2h0Q291bnQoKTogbnVtYmVyIHsgcmV0dXJuIEdBSFRUUEFwaS5pbkZsaWdodC5sZW5ndGg7IH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgd2hlbklkbGUoKTogUHJvbWlzZTx2b2lkPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQUhUVFBBcGkuaW5GbGlnaHQubGVuZ3RoID09PSAwKSB7IHJldHVybiBQcm9taXNlLnJlc29sdmUoKTsgfVxuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLmFsbChHQUhUVFBBcGkuaW5GbGlnaHQuc2xpY2UoKSkudGhlbigoKSA9PiBHQUhUVFBBcGkud2hlbklkbGUoKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyB0cmFjayhyZXF1ZXN0OlByb21pc2U8dm9pZD4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluRmxpZ2h0LnB1c2gocmVxdWVzdCk7XG4gICAgICAgICAgICAgICAgdmFyIGRvbmUgPSAoKSA9PiB7IEdBSFRUUEFwaS5pbkZsaWdodCA9IEdBSFRUUEFwaS5pbkZsaWdodC5maWx0ZXIoKG90aGVyKSA9PiBvdGhlciAhPT0gcmVxdWVzdCk7IH07XG4gICAgICAgICAgICAgICAgcmVxdWVzdC50aGVuKGRvbmUsIGRvbmUpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBiYXNlIHVybCBzZXR0aW5nc1xuICAgICAgICAgICAgICAgIHRoaXMucHJvdG9jb2wgPSBcImh0dHBzXCI7XG4gICAgICAgICAgICAgICAgdGhpcy5ob3N0TmFtZSA9IFwiYXBpLmdhbWVhbmFseXRpY3MuY29tXCI7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gXCJ2MlwiO1xuICAgICAgICAgICAgICAgIHRoaXMucmVtb3RlQ29uZmlnc1ZlcnNpb24gPSBcInYxXCI7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYmFzZSB1cmxcbiAgICAgICAgICAgICAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLnByb3RvY29sICsgXCI6Ly9cIiArIHRoaXMuaG9zdE5hbWUgKyBcIi9cIiArIHRoaXMudmVyc2lvbjtcbiAgICAgICAgICAgICAgICB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsID0gdGhpcy5wcm90b2NvbCArIFwiOi8vXCIgKyB0aGlzLmhvc3ROYW1lICsgXCIvcmVtb3RlX2NvbmZpZ3MvXCIgKyB0aGlzLnJlbW90ZUNvbmZpZ3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5pbml0aWFsaXplVXJsUGF0aCA9IFwiaW5pdFwiO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzVXJsUGF0aCA9IFwiZXZlbnRzXCI7XG5cbiAgICAgICAgICAgICAgICB0aGlzLnVzZUd6aXAgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHJlcXVlc3RJbml0KGNvbmZpZ3NIYXNoOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsICsgXCIvXCIgKyB0aGlzLmluaXRpYWxpemVVcmxQYXRoICsgXCI/Z2FtZV9rZXk9XCIgKyBnYW1lS2V5ICsgXCImaW50ZXJ2YWxfc2Vjb25kcz0wJmNvbmZpZ3NfaGFzaD1cIiArIGNvbmZpZ3NIYXNoICsgXCImY29uZmlnX3Zzbl9zdXBwb3J0ZWQ9M1wiO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdpbml0JyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0QW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0SW5pdEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAvLyBtYWtlIEpTT04gc3RyaW5nIGZyb20gZGF0YVxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGluaXRBbm5vdGF0aW9ucyk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YTpzdHJpbmcgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnNlbmRSZXF1ZXN0KHVybCwgcGF5bG9hZERhdGEsIGV4dHJhQXJncywgdGhpcy51c2VHemlwLCBHQUhUVFBBcGkuaW5pdFJlcXVlc3RDYWxsYmFjaywgY2FsbGJhY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZEV2ZW50c0luQXJyYXkoZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiwgcmVxdWVzdElkOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihldmVudEFycmF5Lmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRFdmVudHNJbkFycmF5IGNhbGxlZCB3aXRoIG1pc3NpbmcgZXZlbnRBcnJheVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnZXZlbnRzJyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBKU09OIGVuY29kaW5nIGZhaWxlZCBvZiBldmVudEFycmF5XCIpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCwgbnVsbCwgcmVxdWVzdElkLCBldmVudEFycmF5Lmxlbmd0aCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGEgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2gocmVxdWVzdElkKTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChldmVudEFycmF5Lmxlbmd0aC50b1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5zZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZW5kU2RrRXJyb3JFdmVudChjYXRlZ29yeTpFR0FTZGtFcnJvckNhdGVnb3J5LCBhcmVhOkVHQVNka0Vycm9yQXJlYSwgYWN0aW9uOkVHQVNka0Vycm9yQWN0aW9uLCBwYXJhbWV0ZXI6RUdBU2RrRXJyb3JQYXJhbWV0ZXIsIHJlYXNvbjpzdHJpbmcsIGdhbWVLZXk6c3RyaW5nLCBzZWNyZXRLZXk6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka0Vycm9yRXZlbnQoZ2FtZUtleSwgc2VjcmV0S2V5LCBjYXRlZ29yeSwgYXJlYSwgYWN0aW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5ldmVudHNVcmxQYXRoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdldmVudHMnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWRKU09OU3RyaW5nOnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGVycm9yVHlwZTpzdHJpbmcgPSBcIlwiXG5cbiAgICAgICAgICAgICAgICB2YXIganNvbjp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRTZGtFcnJvckV2ZW50QW5ub3RhdGlvbnMoKTtcblxuICAgICAgICAgICAgICAgIHZhciBjYXRlZ29yeVN0cmluZzpzdHJpbmcgPSBHQUhUVFBBcGkuc2RrRXJyb3JDYXRlZ29yeVN0cmluZyhjYXRlZ29yeSk7XG4gICAgICAgICAgICAgICAganNvbltcImVycm9yX2NhdGVnb3J5XCJdID0gY2F0ZWdvcnlTdHJpbmc7XG4gICAgICAgICAgICAgICAgZXJyb3JUeXBlICs9IGNhdGVnb3J5U3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgdmFyIGFyZWFTdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yQXJlYVN0cmluZyhhcmVhKTtcbiAgICAgICAgICAgICAgICBqc29uW1wiZXJyb3JfYXJlYVwiXSA9IGFyZWFTdHJpbmc7XG4gICAgICAgICAgICAgICAgZXJyb3JUeXBlICs9IFwiOlwiICsgYXJlYVN0cmluZztcblxuICAgICAgICAgICAgICAgIHZhciBhY3Rpb25TdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yQWN0aW9uU3RyaW5nKGFjdGlvbik7XG4gICAgICAgICAgICAgICAganNvbltcImVycm9yX2FjdGlvblwiXSA9IGFjdGlvblN0cmluZztcblxuICAgICAgICAgICAgICAgIHZhciBwYXJhbWV0ZXJTdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yUGFyYW1ldGVyU3RyaW5nKHBhcmFtZXRlcik7XG4gICAgICAgICAgICAgICAgaWYocGFyYW1ldGVyU3RyaW5nLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBqc29uW1wiZXJyb3JfcGFyYW1ldGVyXCJdID0gcGFyYW1ldGVyU3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHJlYXNvbi5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlYXNvblRyaW1tZWQgPSByZWFzb247XG4gICAgICAgICAgICAgICAgICAgIGlmKHJlYXNvbi5sZW5ndGggPiBHQUhUVFBBcGkuTUFYX0VSUk9SX01FU1NBR0VfTEVOR1RIKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVhc29uVHJpbW1lZCA9IHJlYXNvbi5zdWJzdHJpbmcoMCwgR0FIVFRQQXBpLk1BWF9FUlJPUl9NRVNTQUdFX0xFTkdUSCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAganNvbltcInJlYXNvblwiXSA9IHJlYXNvblRyaW1tZWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50QXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgICAgICBldmVudEFycmF5LnB1c2goanNvbik7XG4gICAgICAgICAgICAgICAgcGF5bG9hZEpTT05TdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldmVudEFycmF5KTtcblxuICAgICAgICAgICAgICAgIGlmKCFwYXlsb2FkSlNPTlN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJzZW5kU2RrRXJyb3JFdmVudDogSlNPTiBlbmNvZGluZyBmYWlsZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRTZGtFcnJvckV2ZW50IGpzb246IFwiICsgcGF5bG9hZEpTT05TdHJpbmcpO1xuICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5leGVjdXRlKHVybCwgZXJyb3JUeXBlLCBwYXlsb2FkSlNPTlN0cmluZywgc2VjcmV0S2V5KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2VuZEV2ZW50SW5BcnJheVJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OkdBSHR0cFJlc3BvbnNlTGlrZSwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZDpzdHJpbmcgPSBleHRyYVsyXTtcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRDb3VudDpudW1iZXIgPSBwYXJzZUludChleHRyYVszXSk7XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZXZlbnRzIHJlcXVlc3QgY29udGVudDogXCIgKyBib2R5KTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0UmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSA9IEdBSFRUUEFwaS5pbnN0YW5jZS5wcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZSwgcmVxdWVzdC5zdGF0dXNUZXh0LCBib2R5LCBcIkV2ZW50c1wiKTtcblxuICAgICAgICAgICAgICAgIC8vIGlmIG5vdCAyMDAgcmVzdWx0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBldmVudHMgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGRlY29kZSBKU09OXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcblxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RKc29uRGljdCA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvckNhdGVnb3J5Lkh0dHAsIEVHQVNka0Vycm9yQXJlYS5FdmVudHNIdHRwLCBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGUsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgYm9keSwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByaW50IHJlYXNvbiBpZiBiYWQgcmVxdWVzdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gPT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEV2ZW50cyBDYWxsLiBCYWQgcmVxdWVzdC4gUmVzcG9uc2U6IFwiICsgSlNPTi5zdHJpbmdpZnkocmVxdWVzdEpzb25EaWN0KSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmV0dXJuIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgcmVxdWVzdEpzb25EaWN0LCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZW5kUmVxdWVzdCh1cmw6c3RyaW5nLCBwYXlsb2FkRGF0YTpzdHJpbmcsIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+LCBnemlwOmJvb2xlYW4sIGNhbGxiYWNrOihyZXF1ZXN0OkdBSHR0cFJlc3BvbnNlTGlrZSwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPikgPT4gdm9pZCwgY2FsbGJhY2syOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQUhUVFBBcGkuY2xpZW50KSB7IEdBTG9nZ2VyLncoXCJObyBIVFRQIGNsaWVudCBjb25maWd1cmVkXCIpOyByZXR1cm47IH1cblxuICAgICAgICAgICAgICAgIC8vIGNyZWF0ZSBhdXRob3JpemF0aW9uIGhhc2hcbiAgICAgICAgICAgICAgICB2YXIga2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpO1xuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoa2V5LCBwYXlsb2FkRGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKGF1dGhvcml6YXRpb24pO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGV4dHJhQXJncylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFyZ3MucHVzaChleHRyYUFyZ3Nbc10pO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlByb21pc2U8dm9pZD4gPSBHQUhUVFBBcGkuY2xpZW50LnNlbmRSZXF1ZXN0KHVybCwgYXV0aG9yaXphdGlvbiwgbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHBheWxvYWREYXRhKSwgZ3ppcClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oKHJlc3BvbnNlOkdBSHR0cFJlc3BvbnNlKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBjb2RlIC0xIG1hcHMgdG8gc3RhdHVzIDAsIHdoaWNoIGlzIHdoYXQgWE1MSHR0cFJlcXVlc3QgcmVwb3J0ZWQgb24gYVxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gbmV0d29yayBmYWlsdXJlLCBzbyBwcm9jZXNzUmVxdWVzdFJlc3BvbnNlIGJlaGF2ZXMgZXhhY3RseSBhcyBiZWZvcmUuXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGlrZTpHQUh0dHBSZXNwb25zZUxpa2UgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdHVzOiByZXNwb25zZS5jb2RlIDwgMCA/IDAgOiByZXNwb25zZS5jb2RlLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXR1c1RleHQ6IHJlc3BvbnNlLnN0YXR1c1RleHQgfHwgXCJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZVRleHQ6IHJlc3BvbnNlLnBhY2tldCAmJiByZXNwb25zZS5wYWNrZXQubGVuZ3RoID8gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHJlc3BvbnNlLnBhY2tldCkgOiBcIlwiXG4gICAgICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2sobGlrZSwgdXJsLCBjYWxsYmFjazIsIGFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAuY2F0Y2goKGU6YW55KSA9PiB7IEdBTG9nZ2VyLmUoXCJIVFRQIGNhbGxiYWNrIGZhaWxlZDogXCIgKyAoZSAmJiBlLnN0YWNrID8gZS5zdGFjayA6IGUpKTsgfSk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnRyYWNrKHJlcXVlc3QpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBpbml0UmVxdWVzdENhbGxiYWNrKHJlcXVlc3Q6R0FIdHRwUmVzcG9uc2VMaWtlLCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+ID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBleHRyYVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYm9keTpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIGJvZHkgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgICAgICAgICAgICAgIC8vIHByb2Nlc3MgdGhlIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImluaXQgcmVxdWVzdCBjb250ZW50IDogXCIgKyBib2R5ICsgXCIsIEpTT05zdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdEpzb25EaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSBudWxsO1xuICAgICAgICAgICAgICAgIHRyeSB7IHJlcXVlc3RKc29uRGljdCA9IGJvZHkgPyBKU09OLnBhcnNlKGJvZHkpIDoge307IH0gY2F0Y2ggKGUpIHt9XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RSZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlID0gR0FIVFRQQXBpLmluc3RhbmNlLnByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlLCByZXF1ZXN0LnN0YXR1c1RleHQsIGJvZHksIFwiSW5pdFwiKTtcblxuICAgICAgICAgICAgICAgIC8vIGlmIG5vdCAyMDAgcmVzdWx0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdEpzb25EaWN0ID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gSnNvbiBkZWNvZGluZyBmYWlsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuSHR0cCwgRUdBU2RrRXJyb3JBcmVhLkluaXRIdHRwLCBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGUsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgYm9keSwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByaW50IHJlYXNvbiBpZiBiYWQgcmVxdWVzdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gcmV0dXJuIGJhZCByZXF1ZXN0IHJlc3VsdFxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIEluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkSW5pdFZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UocmVxdWVzdEpzb25EaWN0LCByZXF1ZXN0UmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCk7XG5cbiAgICAgICAgICAgICAgICBpZighdmFsaWRhdGVkSW5pdFZhbHVlcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXNwb25zZSwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBhbGwgb2tcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCB2YWxpZGF0ZWRJbml0VmFsdWVzLCBcIlwiLCAwKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjcmVhdGVQYXlsb2FkRGF0YShwYXlsb2FkOnN0cmluZywgZ3ppcDpib29sZWFuKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmKGd6aXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBwYXlsb2FkRGF0YSA9IEdBVXRpbGl0aWVzLkd6aXBDb21wcmVzcyhwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gR0FMb2dnZXIuRChcIkd6aXAgc3RhdHMuIFNpemU6IFwiICsgRW5jb2RpbmcuVVRGOC5HZXRCeXRlcyhwYXlsb2FkKS5MZW5ndGggKyBcIiwgQ29tcHJlc3NlZDogXCIgKyBwYXlsb2FkRGF0YS5MZW5ndGggKyBcIiwgQ29udGVudDogXCIgKyBwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwYXlsb2FkRGF0YSA9IHBheWxvYWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWREYXRhO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlOm51bWJlciwgcmVzcG9uc2VNZXNzYWdlOnN0cmluZywgYm9keTpzdHJpbmcsIHJlcXVlc3RJZDpzdHJpbmcpOiBFR0FIVFRQQXBpUmVzcG9uc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBpZiBubyByZXN1bHQgLSBvZnRlbiBubyBjb25uZWN0aW9uXG4gICAgICAgICAgICAgICAgaWYoIWJvZHkgfHwgL15cXHMqPC8udGVzdChib2R5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyByZXNwb25zZU1lc3NhZ2UgKyBcIiwgU3RhdHVzIGNvZGU6IFwiICsgcmVzcG9uc2VDb2RlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIG9rXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMjAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5PaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlZFxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDIwMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyA0MDEgY2FuIHJldHVybiAwIHN0YXR1c1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDAgfHwgcmVzcG9uc2VDb2RlID09PSA0MDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMSAtIFVuYXV0aG9yaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDQwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAwIC0gQmFkIFJlcXVlc3QuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3Q7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNTAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA1MDAgLSBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3IuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLkludGVybmFsU2VydmVyRXJyb3I7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Vbmtub3duUmVzcG9uc2VDb2RlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckNhdGVnb3J5U3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQ2F0ZWdvcnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkV2ZW50VmFsaWRhdGlvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50X3ZhbGlkYXRpb25cIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkRhdGFiYXNlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckNhdGVnb3J5LkluaXQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JDYXRlZ29yeS5IdHRwOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQ2F0ZWdvcnkuSnNvbjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25cIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JBcmVhU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yQXJlYSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5CdXNpbmVzc0V2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuUmVzb3VyY2VFdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlc291cmNlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2dyZXNzaW9uRXZlbnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5EZXNpZ25FdmVudDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImRlc2lnblwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5FcnJvckV2ZW50OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuSW5pdEh0dHA6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbml0X2h0dHBcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFyZWEuRXZlbnRzSHR0cDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImV2ZW50c19odHRwXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBcmVhLlByb2Nlc3NFdmVudHM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9jZXNzX2V2ZW50c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQXJlYS5BZGRFdmVudHNUb1N0b3JlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiYWRkX2V2ZW50c190b19zdG9yZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZGtFcnJvckFjdGlvblN0cmluZyh2YWx1ZTpFR0FTZGtFcnJvckFjdGlvbik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCAodmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRDdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfY3VycmVuY3lcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkU2hvcnRTdHJpbmc6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Nob3J0X3N0cmluZ1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudFBhcnRMZW5ndGg6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfbGVuZ3RoXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uSW52YWxpZEV2ZW50UGFydENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X3BhcnRfY2hhcmFjdGVyc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc3RvcmVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Zsb3dfdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLlN0cmluZ0VtcHR5T3JOdWxsOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic3RyaW5nX2VtcHR5X29yX251bGxcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Ob3RGb3VuZEluQXZhaWxhYmxlQ3VycmVuY2llczpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm5vdF9mb3VuZF9pbl9hdmFpbGFibGVfY3VycmVuY2llc1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRBbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2Ftb3VudFwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLk5vdEZvdW5kSW5BdmFpbGFibGVJdGVtVHlwZXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJub3RfZm91bmRfaW5fYXZhaWxhYmxlX2l0ZW1fdHlwZXNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5Xcm9uZ1Byb2dyZXNzaW9uT3JkZXI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3cm9uZ19wcm9ncmVzc2lvbl9vcmRlclwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRFdmVudElkTGVuZ3RoOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW52YWxpZF9ldmVudF9pZF9sZW5ndGhcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkRXZlbnRJZENoYXJhY3RlcnM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX2V2ZW50X2lkX2NoYXJhY3RlcnNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkUHJvZ3Jlc3Npb25TdGF0dXM6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3Byb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkludmFsaWRTZXZlcml0eTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfc2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5JbnZhbGlkTG9uZ1N0cmluZzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImludmFsaWRfbG9uZ19zdHJpbmdcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5EYXRhYmFzZVRvb0xhcmdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGJfdG9vX2xhcmdlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JBY3Rpb24uRGF0YWJhc2VPcGVuT3JDcmVhdGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkYl9vcGVuX29yX2NyZWF0ZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yQWN0aW9uLkpzb25FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImpzb25fZXJyb3JcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25EZWNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9kZWNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvckFjdGlvbi5GYWlsSHR0cEpzb25FbmNvZGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWlsX2h0dHBfanNvbl9lbmNvZGVcIjtcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JQYXJhbWV0ZXJTdHJpbmcodmFsdWU6RUdBU2RrRXJyb3JQYXJhbWV0ZXIpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2ggKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5DdXJyZW5jeTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImN1cnJlbmN5XCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuQ2FydFR5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjYXJ0X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5JdGVtVHlwZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1fdHlwZVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLkl0ZW1JZDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIml0ZW1faWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5TdG9yZTpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInN0b3JlXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuRmxvd1R5cGU6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmbG93X3R5cGVcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5BbW91bnQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJhbW91bnRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvbjAxOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicHJvZ3Jlc3Npb24wMVwiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlByb2dyZXNzaW9uMDI6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwcm9ncmVzc2lvbjAyXCI7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuUHJvZ3Jlc3Npb24wMzpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uMDNcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5FdmVudElkOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXZlbnRfaWRcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5Qcm9ncmVzc2lvblN0YXR1czpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInByb2dyZXNzaW9uX3N0YXR1c1wiO1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVNka0Vycm9yUGFyYW1ldGVyLlNldmVyaXR5OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwic2V2ZXJpdHlcIjtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclBhcmFtZXRlci5NZXNzYWdlOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwibWVzc2FnZVwiO1xuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGhlYWx0aFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBIZWFsdGhTbmFwc2hvdFxuICAgICAgICB7XG4gICAgICAgICAgICBtZW1vcnlfdXNlZF9tYjogbnVtYmVyO1xuICAgICAgICAgICAgaGFyZHdhcmVfY29uY3VycmVuY3k6IG51bWJlcjtcbiAgICAgICAgICAgIHNjcmVlbl93aWR0aDogbnVtYmVyO1xuICAgICAgICAgICAgc2NyZWVuX2hlaWdodDogbnVtYmVyO1xuICAgICAgICAgICAgY3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBoYXJkd2FyZTogc3RyaW5nO1xuICAgICAgICAgICAgZ3B1X21vZGVsOiBzdHJpbmc7XG4gICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogc3RyaW5nO1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBSGVhbHRoXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEZQU19NQVg6IG51bWJlciA9IDEyMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1FTV9JTlRFUlZBTDogbnVtYmVyID0gNTAwMDtcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX2VuYWJsZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJhZklkOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbGFzdEZyYW1lVGltZTogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc0J1Y2tldHM6IG51bWJlcltdID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBmcmFtZUFjY3VtOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZnJhbWVDb3VudDogbnVtYmVyID0gMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZwc1RpbWVyOiBudW1iZXIgPSAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtVGltZXI6IG51bWJlciA9IDA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBtZW1TeXNCdWNrZXRzOiBudW1iZXJbXSA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWVtQXBwQnVja2V0czogbnVtYmVyW10gPSBbXTtcblxuICAgICAgICAgICAgLy8gSW5qZWN0ZWQgYnkgR2FtZUFuYWx5dGljcy5pbml0KCksIG1pcnJvcmluZyBHQUhlYWx0aChHQVBsYXRmb3JtKikgaW4gQysrLlxuICAgICAgICAgICAgLy8gVGhlIGZpdmUgdmFsdWVzIEMrKyByZWFkcyBpbiBpdHMgY29uc3RydWN0b3IgYXJlIGNhY2hlZCBvbmNlIGhlcmU7XG4gICAgICAgICAgICAvLyBnZXRCb290VGltZS9nZXRBcHBNZW1vcnlVc2FnZS9nZXRTeXNNZW1vcnlVc2FnZSBzdGF5IGxpdmUgY2FsbHMuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwbGF0Zm9ybTogZ2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtID0gbnVsbDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIF9jcHVNb2RlbDogc3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIF9udW1Db3JlczogbnVtYmVyID0gLTE7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfaGFyZHdhcmU6IHN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfZ3B1TW9kZWw6IHN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBfdG90YWxNZW1vcnk6IG51bWJlciA9IC0xO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgX3NjcmVlblJlc29sdXRpb246IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFBsYXRmb3JtKHA6IGdhbWVhbmFseXRpY3MucGxhdGZvcm0uR0FQbGF0Zm9ybSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5wbGF0Zm9ybSA9IHA7XG4gICAgICAgICAgICAgICAgaWYgKHApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5fY3B1TW9kZWwgICAgPSBwLmdldENwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLl9udW1Db3JlcyAgICA9IHAuZ2V0TnVtQ3B1Q29yZXMoKTtcbiAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguX2hhcmR3YXJlICAgID0gcC5nZXREZXZpY2VNb2RlbCgpO1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5fZ3B1TW9kZWwgICAgPSBwLmdldEdwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLl90b3RhbE1lbW9yeSA9IHAuZ2V0VG90YWxEZXZpY2VNZW1vcnkoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKSB7fVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZXNldCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVBY2N1bSA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCA9IDA7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgPSAwO1xuICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyID0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2FtcGxlTWVtb3J5KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBSGVhbHRoLnBsYXRmb3JtKSB7IHJldHVybjsgfVxuICAgICAgICAgICAgICAgIHZhciB0b3RhbDogbnVtYmVyID0gR0FIZWFsdGguX3RvdGFsTWVtb3J5O1xuICAgICAgICAgICAgICAgIHZhciBhcHA6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtLmdldEFwcE1lbW9yeVVzYWdlKCk7XG4gICAgICAgICAgICAgICAgdmFyIHN5czogbnVtYmVyID0gR0FIZWFsdGgucGxhdGZvcm0uZ2V0U3lzTWVtb3J5VXNhZ2UoKTtcbiAgICAgICAgICAgICAgICBpZiAodG90YWwgPiAwICYmIHN5cyA+PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGgubWVtU3lzQnVja2V0c1tNYXRoLm1pbigxMDAsIE1hdGgubWF4KDAsIE1hdGgucm91bmQoc3lzIC8gdG90YWwgKiAxMDApKSldKys7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICh0b3RhbCA+IDAgJiYgYXBwID49IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzW01hdGgubWluKDEwMCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChhcHAgLyB0b3RhbCAqIDEwMCkpKV0rKztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEdwdU1vZGVsKCk6IHN0cmluZyB7IHJldHVybiBHQUhlYWx0aC5fZ3B1TW9kZWw7IH1cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEhhcmR3YXJlKCk6IHN0cmluZyB7IHJldHVybiBHQUhlYWx0aC5faGFyZHdhcmU7IH1cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldERldmljZU1lbW9yeUJ5dGVzKCk6IG51bWJlciB7IHJldHVybiBHQUhlYWx0aC5fdG90YWxNZW1vcnk7IH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0U2NyZWVuUmVzb2x1dGlvbigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGguX3NjcmVlblJlc29sdXRpb24gIT09IG51bGwpIHsgcmV0dXJuIEdBSGVhbHRoLl9zY3JlZW5SZXNvbHV0aW9uOyB9XG4gICAgICAgICAgICAgICAgdmFyIHc6IG51bWJlciA9ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4ud2lkdGggOiAtMTtcbiAgICAgICAgICAgICAgICB2YXIgaDogbnVtYmVyID0gKHR5cGVvZiBzY3JlZW4gIT09ICd1bmRlZmluZWQnKSA/IHNjcmVlbi5oZWlnaHQgOiAtMTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbiA9IHcgKyAneCcgKyBoO1xuICAgICAgICAgICAgICAgIHJldHVybiBHQUhlYWx0aC5fc2NyZWVuUmVzb2x1dGlvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmUoZW5hYmxlZDogYm9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5fZW5hYmxlZCA9IGVuYWJsZWQ7XG4gICAgICAgICAgICAgICAgaWYgKGVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5zdGFydFRyYWNraW5nKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnN0b3BUcmFja2luZygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnRUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiByZXF1ZXN0QW5pbWF0aW9uRnJhbWUgPT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJlc2V0KCk7XG4gICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzQnVja2V0cyA9IG5ldyBBcnJheShHQUhlYWx0aC5GUFNfTUFYICsgMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1TeXNCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1BcHBCdWNrZXRzID0gbmV3IEFycmF5KDEwMSkuZmlsbCgwKTtcbiAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gKHR5cGVvZiBwZXJmb3JtYW5jZSAhPT0gJ3VuZGVmaW5lZCcpID8gcGVyZm9ybWFuY2Uubm93KCkgOiBEYXRlLm5vdygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpY2sgPSBmdW5jdGlvbihub3c6IG51bWJlcik6IHZvaWRcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FIZWFsdGguX2VuYWJsZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB2YXIgZGVsdGE6IG51bWJlciA9IG5vdyAtIEdBSGVhbHRoLmxhc3RGcmFtZVRpbWU7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkZWx0YSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLmZyYW1lQWNjdW0gKz0gMTAwMCAvIGRlbHRhO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnJhbWVDb3VudCsrO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIZWFsdGguZnBzVGltZXIgKz0gZGVsdGE7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5tZW1UaW1lciArPSBkZWx0YTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKEdBSGVhbHRoLmZwc1RpbWVyID49IDEwMDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGF2Z0ZwczogbnVtYmVyID0gTWF0aC5taW4oR0FIZWFsdGguRlBTX01BWCwgTWF0aC5tYXgoMCwgTWF0aC5yb3VuZChHQUhlYWx0aC5mcmFtZUFjY3VtIC8gR0FIZWFsdGguZnJhbWVDb3VudCkpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNCdWNrZXRzW2F2Z0Zwc10rKztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUFjY3VtID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcmFtZUNvdW50ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5mcHNUaW1lciAtPSAxMDAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoR0FIZWFsdGgubWVtVGltZXIgPj0gR0FIZWFsdGguTUVNX0lOVEVSVkFMKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnNhbXBsZU1lbW9yeSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLm1lbVRpbWVyIC09IEdBSGVhbHRoLk1FTV9JTlRFUlZBTDtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5sYXN0RnJhbWVUaW1lID0gbm93O1xuICAgICAgICAgICAgICAgICAgICBHQUhlYWx0aC5yYWZJZCA9IHJlcXVlc3RBbmltYXRpb25GcmFtZSh0aWNrKTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgR0FIZWFsdGgucmFmSWQgPSByZXF1ZXN0QW5pbWF0aW9uRnJhbWUodGljayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3BUcmFja2luZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBjYW5jZWxBbmltYXRpb25GcmFtZSAhPT0gJ3VuZGVmaW5lZCcgJiYgR0FIZWFsdGgucmFmSWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYW5jZWxBbmltYXRpb25GcmFtZShHQUhlYWx0aC5yYWZJZCk7XG4gICAgICAgICAgICAgICAgICAgIEdBSGVhbHRoLnJhZklkID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U25hcHNob3QoKTogSGVhbHRoU25hcHNob3RcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXBwQnl0ZXM6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtID8gR0FIZWFsdGgucGxhdGZvcm0uZ2V0QXBwTWVtb3J5VXNhZ2UoKSA6IC0xO1xuICAgICAgICAgICAgICAgIHZhciBtZW1NYjogbnVtYmVyID0gYXBwQnl0ZXMgPj0gMCA/IE1hdGgucm91bmQoYXBwQnl0ZXMgLyAxMDQ4NTc2KSA6IC0xO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICAgICAgbWVtb3J5X3VzZWRfbWI6IG1lbU1iLFxuICAgICAgICAgICAgICAgICAgICBoYXJkd2FyZV9jb25jdXJyZW5jeTogR0FIZWFsdGguX251bUNvcmVzLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fd2lkdGg6ICh0eXBlb2Ygc2NyZWVuICE9PSAndW5kZWZpbmVkJykgPyBzY3JlZW4ud2lkdGggOiAtMSxcbiAgICAgICAgICAgICAgICAgICAgc2NyZWVuX2hlaWdodDogKHR5cGVvZiBzY3JlZW4gIT09ICd1bmRlZmluZWQnKSA/IHNjcmVlbi5oZWlnaHQgOiAtMSxcbiAgICAgICAgICAgICAgICAgICAgY3B1X21vZGVsOiBHQUhlYWx0aC5fY3B1TW9kZWwgfHwgJ3Vua25vd24nLFxuICAgICAgICAgICAgICAgICAgICBoYXJkd2FyZTogR0FIZWFsdGguZ2V0SGFyZHdhcmUoKSxcbiAgICAgICAgICAgICAgICAgICAgZ3B1X21vZGVsOiBHQUhlYWx0aC5nZXRHcHVNb2RlbCgpLFxuICAgICAgICAgICAgICAgICAgICBzY3JlZW5fcmVzb2x1dGlvbjogR0FIZWFsdGguZ2V0U2NyZWVuUmVzb2x1dGlvbigpXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRIZWFsdGhBbm5vdGF0aW9ucyhvdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG91dFsnY3B1X21vZGVsJ10gPSBHQUhlYWx0aC5fY3B1TW9kZWwgfHwgJ3Vua25vd24nO1xuXG4gICAgICAgICAgICAgICAgb3V0WydoYXJkd2FyZSddID0gR0FIZWFsdGguZ2V0SGFyZHdhcmUoKSB8fCAndW5rbm93bic7XG5cbiAgICAgICAgICAgICAgICB2YXIgZ3B1TW9kZWw6IHN0cmluZyA9IEdBSGVhbHRoLmdldEdwdU1vZGVsKCk7XG4gICAgICAgICAgICAgICAgaWYgKGdwdU1vZGVsKSB7IG91dFsnZ3B1X21vZGVsJ10gPSBncHVNb2RlbDsgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG51bUNvcmVzOiBudW1iZXIgPSBHQUhlYWx0aC5fbnVtQ29yZXM7XG4gICAgICAgICAgICAgICAgaWYgKG51bUNvcmVzID4gMCkgeyBvdXRbJ2NwdV9udW1fY29yZXMnXSA9IG51bUNvcmVzOyB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUGVyZm9ybWFuY2VEYXRhKG91dDoge1trZXk6IHN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgb3V0WydmcHNfZGF0YV90YWJsZSddID0gR0FIZWFsdGguZnBzQnVja2V0cy5zbGljZSgpO1xuXG4gICAgICAgICAgICAgICAgaWYgKEdBSGVhbHRoLmdldERldmljZU1lbW9yeUJ5dGVzKCkgPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgb3V0WydtZW1vcnlfc3lzX2RhdGFfdGFibGUnXSA9IEdBSGVhbHRoLm1lbVN5c0J1Y2tldHMuc2xpY2UoKTtcbiAgICAgICAgICAgICAgICAgICAgb3V0WydtZW1vcnlfYXBwX2RhdGFfdGFibGUnXSA9IEdBSGVhbHRoLm1lbUFwcEJ1Y2tldHMuc2xpY2UoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU0RLSW5pdERhdGEob3V0OiB7W2tleTogc3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYm9vdFRpbWU6IG51bWJlciA9IEdBSGVhbHRoLnBsYXRmb3JtID8gR0FIZWFsdGgucGxhdGZvcm0uZ2V0Qm9vdFRpbWUoKSA6IC0xO1xuICAgICAgICAgICAgICAgIGlmIChib290VGltZSA+IDApIHsgb3V0WydhcHBfYm9vdF90aW1lJ10gPSBib290VGltZTsgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBSGVhbHRoLl9lbmFibGVkO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGV2ZW50c1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgRUdBSFRUUEFwaVJlc3BvbnNlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcbiAgICAgICAgaW1wb3J0IEdBSFRUUEFwaSA9IGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGk7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IFZhbGlkYXRpb25SZXN1bHQgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuVmFsaWRhdGlvblJlc3VsdDtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FFdmVudHNcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ6c3RyaW5nID0gXCJ1c2VyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNlc3Npb25FbmQ6c3RyaW5nID0gXCJzZXNzaW9uX2VuZFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlEZXNpZ246c3RyaW5nID0gXCJkZXNpZ25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QnVzaW5lc3M6c3RyaW5nID0gXCJidXNpbmVzc1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlQcm9ncmVzc2lvbjpzdHJpbmcgPSBcInByb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVJlc291cmNlOnN0cmluZyA9IFwicmVzb3VyY2VcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RXJyb3I6c3RyaW5nID0gXCJlcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlBZHM6c3RyaW5nID0gXCJhZHNcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U0RLSW5pdDpzdHJpbmcgPSBcInNka19pbml0XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUhlYWx0aDpzdHJpbmcgPSBcImhlYWx0aFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4RXZlbnRDb3VudDpudW1iZXIgPSA1MDA7XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9FUlJPUl9DT1VOVDpudW1iZXIgPSAxMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGNvdW50TWFwOiB7IFtrZXk6IHN0cmluZ106IG51bWJlciB9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSB0aW1lc3RhbXBNYXA6IHsgW2tleTogc3RyaW5nXTogRGF0ZSB9ID0ge307XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHdhc1NES0luaXRFdmVudFNlbnQ6IGJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG5cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKGJhc2VNZXNzYWdlOnN0cmluZywgbWVzc2FnZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbm93OiBEYXRlID0gbmV3IERhdGUoKTtcblxuICAgICAgICAgICAgICAgIGlmICghR0FFdmVudHMudGltZXN0YW1wTWFwW2Jhc2VNZXNzYWdlXSkge1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy50aW1lc3RhbXBNYXBbYmFzZU1lc3NhZ2VdID0gbm93O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBRXZlbnRzLmNvdW50TWFwW2Jhc2VNZXNzYWdlXSkge1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgZGlmZjogbnVtYmVyID0gbm93LmdldFRpbWUoKSAtIEdBRXZlbnRzLnRpbWVzdGFtcE1hcFtiYXNlTWVzc2FnZV0uZ2V0VGltZSgpO1xuICAgICAgICAgICAgICAgIHZhciBkaWZmU2Vjb25kczogbnVtYmVyID0gZGlmZiAvIDEwMDA7XG4gICAgICAgICAgICAgICAgaWYgKGRpZmZTZWNvbmRzID49IDM2MDApIHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudGltZXN0YW1wTWFwW2Jhc2VNZXNzYWdlXSA9IG5vdztcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FFdmVudHMuY291bnRNYXBbYmFzZU1lc3NhZ2VdID49IEdBRXZlbnRzLk1BWF9FUlJPUl9DT1VOVCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXJyb3JFdmVudChFR0FFcnJvclNldmVyaXR5Lldhcm5pbmcsIG1lc3NhZ2UsIG51bGwsIHRydWUpO1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gPSBHQUV2ZW50cy5jb3VudE1hcFtiYXNlTWVzc2FnZV0gKyAxO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25TdGFydEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydDtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBzZXNzaW9uIG51bWJlciAgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuU2Vzc2lvbk51bUtleSwgR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcztcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFNFU1NJT04gU1RBUlQgZXZlbnRcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIGV2ZW50IHJpZ2h0IGF3YXlcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0LCBmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU2Vzc2lvbkVuZEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbl9zdGFydF90czpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25MZW5ndGg6bnVtYmVyID0gY2xpZW50X3RzX2FkanVzdGVkIC0gc2Vzc2lvbl9zdGFydF90cztcblxuICAgICAgICAgICAgICAgIGlmKHNlc3Npb25MZW5ndGggPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gU2hvdWxkIG5ldmVyIGhhcHBlbi5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ291bGQgYmUgYmVjYXVzZSBvZiBlZGdlIGNhc2VzIHJlZ2FyZGluZyB0aW1lIGFsdGVyaW5nIG9uIGRldmljZS5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNlc3Npb24gbGVuZ3RoIHdhcyBjYWxjdWxhdGVkIHRvIGJlIGxlc3MgdGhlbiAwLiBTaG91bGQgbm90IGJlIHBvc3NpYmxlLiBSZXNldHRpbmcgdG8gMC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25MZW5ndGggPSAwO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEV2ZW50IHNwZWNpZmljIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvbkVuZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJsZW5ndGhcIl0gPSBzZXNzaW9uTGVuZ3RoO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM7XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBTRVNTSU9OIEVORCBldmVudC5cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIGFsbCBldmVudCByaWdodCBhd2F5XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCBmYWxzZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU0RLSW5pdEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguaXNFbmFibGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRXZlbnRzLndhc1NES0luaXRFdmVudFNlbnQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHNkayBpbml0IG5lZWRzIHRvIGJlIHNlbnQgb25seSBvbmNlIG9uIGFwcCBvcGVuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLndhc1NES0luaXRFdmVudFNlbnQgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U0RLSW5pdDtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbk51bTpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiaXNfZmlyc3Rfc2RrX2luaXRcIl0gPSBzZXNzaW9uTnVtID09PSAxO1xuXG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZEhlYWx0aEFubm90YXRpb25zKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoLmFkZFNES0luaXREYXRhKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkZWQgc2RrIGluaXQgZXZlbnRcIik7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiYWRkU0RLSW5pdEV2ZW50IC0gRXhjZXB0aW9uIHRocm93bjogXCIgKyBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkSGVhbHRoRXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFnYW1lYW5hbHl0aWNzLmhlYWx0aC5HQUhlYWx0aC5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlIZWFsdGg7XG5cbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguYWRkSGVhbHRoQW5ub3RhdGlvbnMoZXZlbnREaWN0KTtcbiAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguYWRkUGVyZm9ybWFuY2VEYXRhKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkZWQgaGVhbHRoIGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZEhlYWx0aEV2ZW50IC0gRXhjZXB0aW9uIHRocm93bjogXCIgKyBlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZywgY2FydFR5cGU6c3RyaW5nID0gbnVsbCwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGNhcnRUeXBlLCBpdGVtVHlwZSwgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCB0cmFuc2FjdGlvbiBudW1iZXIgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5LCBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBSZXF1aXJlZFxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QnVzaW5lc3M7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY3VycmVuY3lcIl0gPSBjdXJyZW5jeTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhbW91bnRcIl0gPSBhbW91bnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W0dBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXldID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gT3B0aW9uYWxcbiAgICAgICAgICAgICAgICBpZiAoY2FydFR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXJ0X3R5cGVcIl0gPSBjYXJ0VHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZihmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEJVU0lORVNTIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIiwgY2FydFR5cGU6XCIgKyBjYXJ0VHlwZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBtZXJnZUZpZWxkczpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0aW9uUmVzdWx0OlZhbGlkYXRpb25SZXN1bHQgPSBHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGUsIGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMoKSk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBJZiBmbG93IHR5cGUgaXMgc2luayByZXZlcnNlIGFtb3VudFxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50ICo9IC0xO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBldmVudCBzcGVjaWZpYyB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgZmxvd1R5cGVTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKGZsb3dUeXBlKTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGZsb3dUeXBlU3RyaW5nICsgXCI6XCIgKyBjdXJyZW5jeSArIFwiOlwiICsgaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UmVzb3VyY2U7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgaWYgKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIGZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKG1lcmdlRmllbGRzICYmIGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWZpZWxkc1RvVXNlW2tleV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBSRVNPVVJDRSBldmVudDoge2N1cnJlbmN5OlwiICsgY3VycmVuY3kgKyBcIiwgYW1vdW50OlwiICsgYW1vdW50ICsgXCIsIGl0ZW1UeXBlOlwiICsgaXRlbVR5cGUgKyBcIiwgaXRlbUlkOlwiICsgaXRlbUlkICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXM6RUdBUHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDE6c3RyaW5nLCBwcm9ncmVzc2lvbjAyOnN0cmluZywgcHJvZ3Jlc3Npb24wMzpzdHJpbmcsIHNjb3JlOm51bWJlciwgc2VuZFNjb3JlOmJvb2xlYW4sIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0sIG1lcmdlRmllbGRzOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHByb2dyZXNzaW9uU3RhdHVzU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLnByb2dyZXNzaW9uU3RhdHVzVG9TdHJpbmcocHJvZ3Jlc3Npb25TdGF0dXMpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRpb25SZXN1bHQ6VmFsaWRhdGlvblJlc3VsdCA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgaWYgKHZhbGlkYXRpb25SZXN1bHQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudCh2YWxpZGF0aW9uUmVzdWx0LmNhdGVnb3J5LCB2YWxpZGF0aW9uUmVzdWx0LmFyZWEsIHZhbGlkYXRpb25SZXN1bHQuYWN0aW9uLCB2YWxpZGF0aW9uUmVzdWx0LnBhcmFtZXRlciwgdmFsaWRhdGlvblJlc3VsdC5yZWFzb24sIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBQcm9ncmVzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgdmFyIHByb2dyZXNzaW9uSWRlbnRpZmllcjpzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBpZiAoIXByb2dyZXNzaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghcHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDEgKyBcIjpcIiArIHByb2dyZXNzaW9uMDI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDEgKyBcIjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIjpcIiArIHByb2dyZXNzaW9uMDM7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlQcm9ncmVzc2lvbjtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IHByb2dyZXNzaW9uU3RhdHVzU3RyaW5nICsgXCI6XCIgKyBwcm9ncmVzc2lvbklkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBBdHRlbXB0XG4gICAgICAgICAgICAgICAgdmFyIGF0dGVtcHRfbnVtOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgc2NvcmUgaWYgc3BlY2lmaWVkIGFuZCBzdGF0dXMgaXMgbm90IHN0YXJ0XG4gICAgICAgICAgICAgICAgaWYgKHNlbmRTY29yZSAmJiBwcm9ncmVzc2lvblN0YXR1cyAhPSBFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcInNjb3JlXCJdID0gTWF0aC5yb3VuZChzY29yZSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ291bnQgYXR0ZW1wdHMgb24gZWFjaCBwcm9ncmVzc2lvbiBmYWlsIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluY3JlbWVudCBhbmQgYWRkIGF0dGVtcHRfbnVtIG9uIGNvbXBsZXRlIGFuZCBkZWxldGUgcGVyc2lzdGVkXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uU3RhdHVzID09PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5Db21wbGV0ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBhdHRlbXB0IG51bWJlclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gZXZlbnRcbiAgICAgICAgICAgICAgICAgICAgYXR0ZW1wdF9udW0gPSBHQVN0YXRlLmdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYXR0ZW1wdF9udW1cIl0gPSBhdHRlbXB0X251bTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDbGVhclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmNsZWFyUHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZXJnZUZpZWxkcyAmJiBmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGljdCwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUFJPR1JFU1NJT04gZXZlbnQ6IHtzdGF0dXM6XCIgKyBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiLCBwcm9ncmVzc2lvbjAxOlwiICsgcHJvZ3Jlc3Npb24wMSArIFwiLCBwcm9ncmVzc2lvbjAyOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiLCBwcm9ncmVzc2lvbjAzOlwiICsgcHJvZ3Jlc3Npb24wMyArIFwiLCBzY29yZTpcIiArIHNjb3JlICsgXCIsIGF0dGVtcHQ6XCIgKyBhdHRlbXB0X251bSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyLCBzZW5kVmFsdWU6Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0aW9uUmVzdWx0OlZhbGlkYXRpb25SZXN1bHQgPSBHQVZhbGlkYXRvci52YWxpZGF0ZURlc2lnbkV2ZW50KGV2ZW50SWQpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlEZXNpZ247XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiZXZlbnRfaWRcIl0gPSBldmVudElkO1xuXG4gICAgICAgICAgICAgICAgaWYoc2VuZFZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1widmFsdWVcIl0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gZmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZmllbGRzVG9Vc2Vba2V5XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERhdGEsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHNUb1VzZSwgR0FFdmVudHMuY3VzdG9tRXZlbnRGaWVsZHNFcnJvckNhbGxiYWNrKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIERFU0lHTiBldmVudDoge2V2ZW50SWQ6XCIgKyBldmVudElkICsgXCIsIHZhbHVlOlwiICsgdmFsdWUgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5LCBtZXNzYWdlOnN0cmluZywgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSwgbWVyZ2VGaWVsZHM6Ym9vbGVhbiwgc2tpcEFkZGluZ0ZpZWxkczpib29sZWFuPWZhbHNlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBzZXZlcml0eVN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5lcnJvclNldmVyaXR5VG9TdHJpbmcoc2V2ZXJpdHkpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBpZiAodmFsaWRhdGlvblJlc3VsdCAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KHZhbGlkYXRpb25SZXN1bHQuY2F0ZWdvcnksIHZhbGlkYXRpb25SZXN1bHQuYXJlYSwgdmFsaWRhdGlvblJlc3VsdC5hY3Rpb24sIHZhbGlkYXRpb25SZXN1bHQucGFyYW1ldGVyLCB2YWxpZGF0aW9uUmVzdWx0LnJlYXNvbiwgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5RXJyb3I7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wic2V2ZXJpdHlcIl0gPSBzZXZlcml0eVN0cmluZztcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJtZXNzYWdlXCJdID0gbWVzc2FnZTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICBpZighc2tpcEFkZGluZ0ZpZWxkcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaWVsZHNUb1VzZTogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBrZXkgaW4gZmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IGZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZiAobWVyZ2VGaWVsZHMgJiYgZmllbGRzICYmIE9iamVjdC5rZXlzKGZpZWxkcykubGVuZ3RoID4gMCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkc1trZXldO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEN1c3RvbUZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgRVJST1IgZXZlbnQ6IHtzZXZlcml0eTpcIiArIHNldmVyaXR5U3RyaW5nICsgXCIsIG1lc3NhZ2U6XCIgKyBtZXNzYWdlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEFkRXZlbnQoYWRBY3Rpb246RUdBQWRBY3Rpb24sIGFkVHlwZTpFR0FBZFR5cGUsIGFkU2RrTmFtZTpzdHJpbmcsIGFkUGxhY2VtZW50OnN0cmluZywgbm9BZFJlYXNvbjpFR0FBZEVycm9yLCBkdXJhdGlvbjpudW1iZXIsIHNlbmREdXJhdGlvbjpib29sZWFuLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9LCBtZXJnZUZpZWxkczpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBhZEFjdGlvblN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5hZEFjdGlvblRvU3RyaW5nKGFkQWN0aW9uKTtcbiAgICAgICAgICAgICAgICB2YXIgYWRUeXBlU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmFkVHlwZVRvU3RyaW5nKGFkVHlwZSk7XG4gICAgICAgICAgICAgICAgdmFyIG5vQWRSZWFzb25TdHJpbmc6c3RyaW5nID0gR0FFdmVudHMuYWRFcnJvclRvU3RyaW5nKG5vQWRSZWFzb24pO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGlvblJlc3VsdDpWYWxpZGF0aW9uUmVzdWx0ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQpO1xuICAgICAgICAgICAgICAgIGlmICh2YWxpZGF0aW9uUmVzdWx0ICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQodmFsaWRhdGlvblJlc3VsdC5jYXRlZ29yeSwgdmFsaWRhdGlvblJlc3VsdC5hcmVhLCB2YWxpZGF0aW9uUmVzdWx0LmFjdGlvbiwgdmFsaWRhdGlvblJlc3VsdC5wYXJhbWV0ZXIsIHZhbGlkYXRpb25SZXN1bHQucmVhc29uLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlBZHM7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfc2RrX25hbWVcIl0gPSBhZFNka05hbWU7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfcGxhY2VtZW50XCJdID0gYWRQbGFjZW1lbnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfdHlwZVwiXSA9IGFkVHlwZVN0cmluZztcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJhZF9hY3Rpb25cIl0gPSBhZEFjdGlvblN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmKGFkQWN0aW9uID09IEVHQUFkQWN0aW9uLkZhaWxlZFNob3cgJiYgbm9BZFJlYXNvblN0cmluZy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiYWRfZmFpbF9zaG93X3JlYXNvblwiXSA9IG5vQWRSZWFzb25TdHJpbmc7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoc2VuZER1cmF0aW9uICYmIChhZFR5cGUgPT0gRUdBQWRUeXBlLlJld2FyZGVkVmlkZW8gfHwgYWRUeXBlID09IEVHQUFkVHlwZS5WaWRlbykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJhZF9kdXJhdGlvblwiXSA9IGR1cmF0aW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgZmllbGRzVG9Vc2U6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBmaWVsZHMpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpZWxkc1RvVXNlW2tleV0gPSBmaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQga2V5IGluIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaWVsZHNUb1VzZVtrZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHNba2V5XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChtZXJnZUZpZWxkcyAmJiBmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGtleSBpbiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFmaWVsZHNUb1VzZVtrZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmllbGRzVG9Vc2Vba2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzW2tleV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2ZW50RGF0YSwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkc1RvVXNlLCBHQUV2ZW50cy5jdXN0b21FdmVudEZpZWxkc0Vycm9yQ2FsbGJhY2spKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgQUQgZXZlbnQ6IHthZF9zZGtfbmFtZTpcIiArIGFkU2RrTmFtZSArIFwiLCBhZF9wbGFjZW1lbnQ6XCIgKyBhZFBsYWNlbWVudCArIFwiLCBhZF90eXBlOlwiICsgYWRUeXBlU3RyaW5nICsgXCIsIGFkX2FjdGlvbjpcIiArIGFkQWN0aW9uU3RyaW5nICsgKChhZEFjdGlvbiA9PSBFR0FBZEFjdGlvbi5GYWlsZWRTaG93ICYmIG5vQWRSZWFzb25TdHJpbmcubGVuZ3RoID4gMCkgPyAoXCIsIGFkX2ZhaWxfc2hvd19yZWFzb246XCIgKyBub0FkUmVhc29uU3RyaW5nKSA6IFwiXCIpICsgKChzZW5kRHVyYXRpb24gJiYgKGFkVHlwZSA9PSBFR0FBZFR5cGUuUmV3YXJkZWRWaWRlbyB8fCBhZFR5cGUgPT0gRUdBQWRUeXBlLlZpZGVvKSkgPyAoXCIsIGFkX2R1cmF0aW9uOlwiICsgZHVyYXRpb24pIDogXCJcIikgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcHJvY2Vzc0V2ZW50cyhjYXRlZ29yeTpzdHJpbmcsIHBlcmZvcm1DbGVhblVwOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdGhyb3cgbmV3IEVycm9yKFwicHJvY2Vzc0V2ZW50cyBub3QgaW1wbGVtZW50ZWRcIik7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkZW50aWZpZXI6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFudXBcbiAgICAgICAgICAgICAgICAgICAgaWYocGVyZm9ybUNsZWFuVXApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmNsZWFudXBFdmVudHMoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBQcmVwYXJlIFNRTFxuICAgICAgICAgICAgICAgICAgICB2YXIgc2VsZWN0QXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuICAgICAgICAgICAgICAgICAgICBpZihjYXRlZ29yeSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlU2V0QXJnczpBcnJheTxbc3RyaW5nLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVTZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIHJlcXVlc3RJZGVudGlmaWVyXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gR2V0IGV2ZW50cyB0byBwcm9jZXNzXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudHM6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGZvciBlcnJvcnMgb3IgZW1wdHlcbiAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cyB8fCBldmVudHMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogTm8gZXZlbnRzIHRvIHNlbmRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy51cGRhdGVTZXNzaW9uU3RvcmUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIG51bWJlciBvZiBldmVudHMgYW5kIHRha2Ugc29tZSBhY3Rpb24gaWYgdGhlcmUgYXJlIHRvbyBtYW55P1xuICAgICAgICAgICAgICAgICAgICBpZihldmVudHMubGVuZ3RoID4gR0FFdmVudHMuTWF4RXZlbnRDb3VudClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWFrZSBhIGxpbWl0IHJlcXVlc3RcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2ZW50cyA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncywgdHJ1ZSwgR0FFdmVudHMuTWF4RXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZighZXZlbnRzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gR2V0IGxhc3QgdGltZXN0YW1wXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdEl0ZW06e1trZXk6c3RyaW5nXTogYW55fSA9IGV2ZW50c1tldmVudHMubGVuZ3RoIC0gMV07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdFRpbWVzdGFtcDpzdHJpbmcgPSBsYXN0SXRlbVtcImNsaWVudF90c1wiXSBhcyBzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJjbGllbnRfdHNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWwsIGxhc3RUaW1lc3RhbXBdKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gU2VsZWN0IGFnYWluXG4gICAgICAgICAgICAgICAgICAgICAgICBldmVudHMgPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFldmVudHMpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJjbGllbnRfdHNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWwsIGxhc3RUaW1lc3RhbXBdKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IFNlbmRpbmcgXCIgKyBldmVudHMubGVuZ3RoICsgXCIgZXZlbnRzLlwiKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBTZXQgc3RhdHVzIG9mIGV2ZW50cyB0byAnc2VuZGluZycgKGFsc28gY2hlY2sgZm9yIGVycm9yKVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgdXBkYXRlU2V0QXJncywgdXBkYXRlV2hlcmVBcmdzKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIHBheWxvYWQgZGF0YSBmcm9tIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgaTpudW1iZXIgPSAwOyBpIDwgZXZlbnRzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IGV2ZW50c1tpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldmVudERpY3QgPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KGV2W1wiZXZlbnRcIl0pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFdhcyBgZXZlbnREaWN0Lmxlbmd0aCAhPSAwYCwgd2hpY2ggb24gYSBzZXNzaW9uX2VuZCBldmVudCByZWFkXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBpdHMgb3duIGBsZW5ndGhgIChzZXNzaW9uIHNlY29uZHMpIGFuZCBzaWxlbnRseSBkcm9wcGVkIGFueVxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2Vzc2lvbiBzaG9ydGVyIHRoYW4gYSBzZWNvbmQg4oCUIHRoZSBjb21tb24gY2FzZSBoZWFkbGVzcy5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChldmVudERpY3QgJiYgdHlwZW9mIGV2ZW50RGljdCA9PT0gXCJvYmplY3RcIilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6IG51bWJlciA9IGV2ZW50RGljdFtcImNsaWVudF90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGNsaWVudFRzICYmICFHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzKSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBldmVudERpY3RbXCJjbGllbnRfdHNcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBheWxvYWRBcnJheS5wdXNoKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZEV2ZW50c0luQXJyYXkocGF5bG9hZEFycmF5LCByZXF1ZXN0SWRlbnRpZmllciwgR0FFdmVudHMucHJvY2Vzc0V2ZW50c0NhbGxiYWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3IgZHVyaW5nIFByb2Nlc3NFdmVudHMoKTogXCIgKyBlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuSnNvbiwgRUdBU2RrRXJyb3JBcmVhLlByb2Nlc3NFdmVudHMsIEVHQVNka0Vycm9yQWN0aW9uLkpzb25FcnJvciwgRUdBU2RrRXJyb3JQYXJhbWV0ZXIuVW5kZWZpbmVkLCBlLnN0YWNrLCBHQVN0YXRlLmdldEdhbWVLZXkoKSwgR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcHJvY2Vzc0V2ZW50c0NhbGxiYWNrKHJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UsIGRhdGFEaWN0Ontba2V5OnN0cmluZ106IGFueX0sICByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkV2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgIHJlcXVlc3RJZFdoZXJlQXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgcmVxdWVzdElkXSk7XG5cbiAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5PaylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuRXZlbnRzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IFwiICsgZXZlbnRDb3VudCArIFwiIGV2ZW50cyBzZW50LlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gUHV0IGV2ZW50cyBiYWNrIChPbmx5IGluIGNhc2Ugb2Ygbm8gcmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2UpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzOkFycmF5PFtzdHJpbmcsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIFwibmV3XCJdKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMgdG8gY29sbGVjdG9yIC0gUmV0cnlpbmcgbmV4dCB0aW1lXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS51cGRhdGUoRUdBU3RvcmUuRXZlbnRzLCBzZXRBcmdzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gRGVsZXRlIGV2ZW50cyAoV2hlbiBnZXR0aW5nIHNvbWUgYW53c2VyIGJhY2sgYWx3YXlzIGFzc3VtZSBldmVudHMgYXJlIHByb2Nlc3NlZClcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGRhdGFEaWN0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBqc29uOmFueTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogaW4gZGF0YURpY3QpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBqc29uID0gZGF0YURpY3Rbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0ICYmIGpzb24uY29uc3RydWN0b3IgPT09IEFycmF5KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC4gXCIgKyBjb3VudCArIFwiIGV2ZW50cyBmYWlsZWQgR0Egc2VydmVyIHZhbGlkYXRpb24uXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuRXZlbnRzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjbGVhbnVwRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIFtbXCJzdGF0dXNcIiAsIFwibmV3XCJdXSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBHZXQgYWxsIHNlc3Npb25zIHRoYXQgYXJlIG5vdCBjdXJyZW50XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKFtcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWwsIEdBU3RhdGUuZ2V0U2Vzc2lvbklkKCldKTtcblxuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uczpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLlNlc3Npb25zLCBhcmdzKTtcblxuICAgICAgICAgICAgICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShzZXNzaW9ucy5sZW5ndGggKyBcIiBzZXNzaW9uKHMpIGxvY2F0ZWQgd2l0aCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50LlwiKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50c1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgc2Vzc2lvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkVuZEV2ZW50Ontba2V5OnN0cmluZ106IGFueX0gPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KHNlc3Npb25zW2ldW1wiZXZlbnRcIl0gYXMgc3RyaW5nKSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudF90czpudW1iZXIgPSBzZXNzaW9uRW5kRXZlbnRbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gc2Vzc2lvbnNbaV1bXCJ0aW1lc3RhbXBcIl0gYXMgbnVtYmVyO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBsZW5ndGg6bnVtYmVyID0gZXZlbnRfdHMgLSBzdGFydF90cztcbiAgICAgICAgICAgICAgICAgICAgbGVuZ3RoID0gTWF0aC5tYXgoMCwgbGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgICAgICBpZihsZW5ndGggPT09IG51bGwpXG4gICAgICAgICAgICAgICAgICAgICAgICBsZW5ndGggPSAwO1xuICAgICAgICAgICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzIGxlbmd0aCBjYWxjdWxhdGVkOiBcIiArIGxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkVuZEV2ZW50W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImxlbmd0aFwiXSA9IGxlbmd0aDtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKHNlc3Npb25FbmRFdmVudCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgd2UgYXJlIGluaXRpYWxpemVkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3QgYWRkIGV2ZW50OiBTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBkYiBzaXplIGxpbWl0cyAoMTBtYilcbiAgICAgICAgICAgICAgICAgICAgLy8gSWYgZGF0YWJhc2UgaXMgdG9vIGxhcmdlIGJsb2NrIGFsbCBleGNlcHQgdXNlciwgc2Vzc2lvbiBhbmQgYnVzaW5lc3NcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBU3RvcmUuaXNTdG9yZVRvb0xhcmdlRm9yRXZlbnRzKCkgJiYgIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdIGFzIHN0cmluZywgL14odXNlcnxzZXNzaW9uX2VuZHxidXNpbmVzcykkLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJEYXRhYmFzZSB0b28gbGFyZ2UuIEV2ZW50IGhhcyBiZWVuIGJsb2NrZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yQ2F0ZWdvcnkuRGF0YWJhc2UsIEVHQVNka0Vycm9yQXJlYS5BZGRFdmVudHNUb1N0b3JlLCBFR0FTZGtFcnJvckFjdGlvbi5EYXRhYmFzZVRvb0xhcmdlLCBFR0FTZGtFcnJvclBhcmFtZXRlci5VbmRlZmluZWQsIFwiXCIsIEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZGVmYXVsdCBhbm5vdGF0aW9uc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIE1lcmdlIHdpdGggZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgZSBpbiBldmVudERhdGEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2W2VdID0gZXZlbnREYXRhW2VdO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gc3RyaW5nIHJlcHJlc2VudGF0aW9uXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2KTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBvdXRwdXQgaWYgVkVSQk9TRSBMT0cgZW5hYmxlZFxuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmlpKFwiRXZlbnQgYWRkZWQgdG8gcXVldWU6IFwiICsganNvbik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzdGF0dXNcIl0gPSBcIm5ld1wiO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjYXRlZ29yeVwiXSA9IGV2W1wiY2F0ZWdvcnlcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNsaWVudF90c1wiXSA9IGV2W1wiY2xpZW50X3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGV2KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuRXZlbnRzLCB2YWx1ZXMpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzZXNzaW9uIHN0b3JlIGlmIG5vdCBsYXN0XG4gICAgICAgICAgICAgICAgICAgIGlmIChldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9PSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlNlc3Npb25zLCBbW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgZXZbXCJzZXNzaW9uX2lkXCJdIGFzIHN0cmluZ11dKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLnVwZGF0ZVNlc3Npb25TdG9yZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zYXZlKEdBU3RhdGUuZ2V0R2FtZUtleSgpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRFdmVudFRvU3RvcmU6IGVycm9yXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JDYXRlZ29yeS5EYXRhYmFzZSwgRUdBU2RrRXJyb3JBcmVhLkFkZEV2ZW50c1RvU3RvcmUsIEVHQVNka0Vycm9yQWN0aW9uLkRhdGFiYXNlVG9vTGFyZ2UsIEVHQVNka0Vycm9yUGFyYW1ldGVyLlVuZGVmaW5lZCwgZS5zdGFjaywgR0FTdGF0ZS5nZXRHYW1lS2V5KCksIEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHVwZGF0ZVNlc3Npb25TdG9yZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0aW1lc3RhbXBcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBldjogeyBba2V5OiBzdHJpbmddOiBhbnkgfSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldik7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpZWxkc1RvVXNlOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRHbG9iYWxDdXN0b21FdmVudEZpZWxkcztcblxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRDdXN0b21GaWVsZHNUb0V2ZW50KGV2LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzVG9Vc2UsIEdBRXZlbnRzLmN1c3RvbUV2ZW50RmllbGRzRXJyb3JDYWxsYmFjaykpO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuU2Vzc2lvbnMsIHZhbHVlcywgdHJ1ZSwgXCJzZXNzaW9uX2lkXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZShHQVN0YXRlLmdldEdhbWVLZXkoKSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBhZGQgdG8gZGljdCAoaWYgbm90IG5pbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMVwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAyXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDNcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkQ3VzdG9tRmllbGRzVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSwgZmllbGRzOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fZmllbGRzXCJdID0gZmllbGRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU291cmNlIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5Tb3VyY2VdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU291cmNlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNpbmtcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0IHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlN0YXJ0XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29tcGxldGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiRmFpbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGVycm9yU2V2ZXJpdHlUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkRlYnVnIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5EZWJ1Z10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkZWJ1Z1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuSW5mbyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuSW5mb10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbmZvXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndhcm5pbmdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkVycm9yIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5FcnJvcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJlcnJvclwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuQ3JpdGljYWwgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImNyaXRpY2FsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRBY3Rpb25Ub1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FBZEFjdGlvbi5DbGlja2VkIHx8IHZhbHVlID09IEVHQUFkQWN0aW9uW0VHQUFkQWN0aW9uLkNsaWNrZWRdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiY2xpY2tlZFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkQWN0aW9uLlNob3cgfHwgdmFsdWUgPT0gRUdBQWRBY3Rpb25bRUdBQWRBY3Rpb24uU2hvd10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJzaG93XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRBY3Rpb24uRmFpbGVkU2hvdyB8fCB2YWx1ZSA9PSBFR0FBZEFjdGlvbltFR0FBZEFjdGlvbi5GYWlsZWRTaG93XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImZhaWxlZF9zaG93XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRBY3Rpb24uUmV3YXJkUmVjZWl2ZWQgfHwgdmFsdWUgPT0gRUdBQWRBY3Rpb25bRUdBQWRBY3Rpb24uUmV3YXJkUmVjZWl2ZWRdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmV3YXJkX3JlY2VpdmVkXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRFcnJvclRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQUFkRXJyb3IuVW5rbm93biB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuVW5rbm93bl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ1bmtub3duXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRFcnJvci5PZmZsaW5lIHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5PZmZsaW5lXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm9mZmxpbmVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLk5vRmlsbCB8fCB2YWx1ZSA9PSBFR0FBZEVycm9yW0VHQUFkRXJyb3IuTm9GaWxsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIm5vX2ZpbGxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLkludGVybmFsRXJyb3IgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLkludGVybmFsRXJyb3JdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW50ZXJuYWxfZXJyb3JcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLkludmFsaWRSZXF1ZXN0IHx8IHZhbHVlID09IEVHQUFkRXJyb3JbRUdBQWRFcnJvci5JbnZhbGlkUmVxdWVzdF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbnZhbGlkX3JlcXVlc3RcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZEVycm9yLlVuYWJsZVRvUHJlY2FjaGUgfHwgdmFsdWUgPT0gRUdBQWRFcnJvcltFR0FBZEVycm9yLlVuYWJsZVRvUHJlY2FjaGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwidW5hYmxlX3RvX3ByZWNhY2hlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRUeXBlVG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBQWRUeXBlLlZpZGVvIHx8IHZhbHVlID09IEVHQUFkVHlwZVtFR0FBZFR5cGUuVmlkZW9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwidmlkZW9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuUmV3YXJkZWRWaWRlbyB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLlJld2FyZGVkVmlkZW9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmV3YXJkZWRfdmlkZW9cIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FBZFR5cGUuUGxheWFibGUgfHwgdmFsdWUgPT0gRUdBQWRUeXBlW0VHQUFkVHlwZS5QbGF5YWJsZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJwbGF5YWJsZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUFkVHlwZS5JbnRlcnN0aXRpYWwgfHwgdmFsdWUgPT0gRUdBQWRUeXBlW0VHQUFkVHlwZS5JbnRlcnN0aXRpYWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW50ZXJzdGl0aWFsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRUeXBlLk9mZmVyV2FsbCB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLk9mZmVyV2FsbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJvZmZlcl93YWxsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBQWRUeXBlLkJhbm5lciB8fCB2YWx1ZSA9PSBFR0FBZFR5cGVbRUdBQWRUeXBlLkJhbm5lcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJiYW5uZXJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVGhyZWFkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBVGhyZWFkaW5nID0gbmV3IEdBVGhyZWFkaW5nKCk7XG4gICAgICAgICAgICBwcml2YXRlIHJlYWRvbmx5IHRhc2tRdWV1ZTpBcnJheTwoKSA9PiB2b2lkPiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZXZlbnRJbnRlcnZhbElkOlJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHB1bXBJZDpSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGhlbGQ6Ym9vbGVhbiA9IGZhbHNlO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdG9wcGVkOmJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgLy8gSW4gTm9kZSwgYW4gYWN0aXZlIGludGVydmFsIGtlZXBzIHRoZSBwcm9jZXNzIGFsaXZlOyB1bnJlZigpIGxldHMgaXQgZXhpdFxuICAgICAgICAgICAgLy8gbmF0dXJhbGx5IG9uY2UgdGhlIGFwcGxpY2F0aW9uIGlzIGRvbmUuIE5vLW9wIGluIHRoZSBicm93c2VyLlxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgdW5yZWYodGltZXI6YW55KTogdm9pZCB7IGlmICh0aW1lciAmJiB0eXBlb2YgdGltZXIudW5yZWYgPT09ICdmdW5jdGlvbicpIHsgdGltZXIudW5yZWYoKTsgfSB9XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBQcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyID0gOC4wO1xuICAgICAgICAgICAgcHJpdmF0ZSBpc1J1bm5pbmc6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wdW1wSWQgPSBzZXRJbnRlcnZhbChHQVRocmVhZGluZy5ydW4sIDEwMCk7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcudW5yZWYoR0FUaHJlYWRpbmcucHVtcElkKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gUnVuIGV2ZXJ5IHF1ZXVlZCB0YXNrIG5vdy4gb25RdWl0KCkgdXNlcyB0aGlzIGluc3RlYWQgb2Ygd2FpdGluZyBmb3IgdGhlXG4gICAgICAgICAgICAvLyAxMDAgbXMgdGljazsgdGhlIEMrKyBidXN5LXdhaXQgY2Fubm90IGJlIHBvcnRlZCAoc3BlYywgXCJub3QgaXRzIHNwaW5cIikuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGZsdXNoKCk6IHZvaWQgeyBHQVRocmVhZGluZy5ydW4oKTsgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZW5kaW5nVGFza0NvdW50KCk6IG51bWJlciB7IHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS50YXNrUXVldWUubGVuZ3RoOyB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0b3BQdW1wKCk6IHZvaWQgeyBjbGVhckludGVydmFsKEdBVGhyZWFkaW5nLnB1bXBJZCk7IEdBVGhyZWFkaW5nLnN0b3BwZWQgPSB0cnVlOyB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRhc2tPbkdBVGhyZWFkKHRhc2tCbG9jazooKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLnRhc2tRdWV1ZS5wdXNoKHRhc2tCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5ldmVudEludGVydmFsSWQgPSBzZXRJbnRlcnZhbChcbiAgICAgICAgICAgICAgICAgICAgICAgICgpID0+IEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZChHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSksXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMgKiAxMDAwXG4gICAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnVucmVmKEdBVGhyZWFkaW5nLmV2ZW50SW50ZXJ2YWxJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFbmRpbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0b3BFdmVudFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRIZWFsdGhFdmVudCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvbkVuZEV2ZW50KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IDA7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RvcEV2ZW50UXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGNsZWFySW50ZXJ2YWwoR0FUaHJlYWRpbmcuZXZlbnRJbnRlcnZhbElkKTtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGludGVydmFsID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcyA9IGludGVydmFsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB3aGlsZSAoIUdBVGhyZWFkaW5nLmhlbGQgJiYgR0FUaHJlYWRpbmcuaW5zdGFuY2UudGFza1F1ZXVlLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zdCB0YXNrID0gR0FUaHJlYWRpbmcuaW5zdGFuY2UudGFza1F1ZXVlLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0YXNrKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0cnkgeyB0YXNrKCk7IH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGNhdGNoIChlOiBhbnkpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIG9uIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGkuaW5GbGlnaHRDb3VudCgpID4gMCkgeyByZXR1cm47IH1cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiUHJvY2Vzc2luZyBldmVudCBxdWV1ZS4uLlwiKTtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIHRydWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBpbXBvcnQgR0FUaHJlYWRpbmcgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5HQVRocmVhZGluZztcbiAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgaW1wb3J0IEdBSFRUUEFwaSA9IGdhbWVhbmFseXRpY3MuaHR0cC5HQUhUVFBBcGk7XG4gICAgaW1wb3J0IEdBRGV2aWNlID0gZ2FtZWFuYWx5dGljcy5kZXZpY2UuR0FEZXZpY2U7XG4gICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgIGltcG9ydCBFR0FIVFRQQXBpUmVzcG9uc2UgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBSFRUUEFwaVJlc3BvbnNlO1xuICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgIGltcG9ydCBHQUV2ZW50cyA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkdBRXZlbnRzO1xuICAgIGltcG9ydCBHQUhlYWx0aCA9IGdhbWVhbmFseXRpY3MuaGVhbHRoLkdBSGVhbHRoO1xuXG4gICAgZXhwb3J0IGNsYXNzIEdhbWVBbmFseXRpY3NcbiAgICB7XG5wdWJsaWMgc3RhdGljIG1ldGhvZE1hcDp7W2lkOnN0cmluZ106ICguLi5hcmdzOiBhbnlbXSkgPT4gdm9pZH0gPSB7fTtcblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRHbG9iYWxPYmplY3QoKTogYW55XG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgZ2xvYmFsVGhpcyAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIGdsb2JhbFRoaXM7IH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygc2VsZiAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIHNlbGY7IH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJykgeyByZXR1cm4gd2luZG93OyB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIGdsb2JhbCAhPT0gJ3VuZGVmaW5lZCcpIHsgcmV0dXJuIGdsb2JhbDsgfVxuICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgaW5pdCgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIEJ1aWxkLXRpbWUgcGxhdGZvcm0gc2VsZWN0aW9uLCB0aGUgSlMgYW5hbG9ndWUgb2YgQysrIE1ha2VQbGF0Zm9ybSgpLlxuICAgICAgICAgICAgLy8gR0FEZXZpY2Ugb3ducyBpdDsgR0FIZWFsdGggY2FjaGVzIGl0cyBmaXZlIGNvbnN0cnVjdG9yLXRpbWUgcmVhZHMuXG4gICAgICAgICAgICB2YXIgcGxhdGZvcm06Z2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5HQVBsYXRmb3JtID0gZ2FtZWFuYWx5dGljcy5wbGF0Zm9ybS5tYWtlUGxhdGZvcm0oKTtcbiAgICAgICAgICAgIEdBRGV2aWNlLnNldFBsYXRmb3JtKHBsYXRmb3JtKTtcbiAgICAgICAgICAgIEdBSGVhbHRoLnNldFBsYXRmb3JtKHBsYXRmb3JtKTtcbiAgICAgICAgICAgIEdBU3RvcmUuc2V0U3RvcmFnZShnYW1lYW5hbHl0aWNzLnN0b3JhZ2UubWFrZVN0b3JhZ2UoKSk7XG4gICAgICAgICAgICBHQUhUVFBBcGkuc2V0Q2xpZW50KGdhbWVhbmFseXRpY3MuaHR0cC5tYWtlSHR0cENsaWVudCgpKTtcbiAgICAgICAgICAgIEdBRGV2aWNlLnRvdWNoKCk7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDInXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVCdWlsZCddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVCdWlsZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVVc2VySWQnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlVXNlcklkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2dldFVzZXJJZCddID0gR2FtZUFuYWx5dGljcy5nZXRVc2VySWQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXh0VXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLnNldEV4dFVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRFeHRVc2VySWQnXSA9IEdhbWVBbmFseXRpY3MuZ2V0RXh0VXNlcklkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2luaXRpYWxpemUnXSA9IEdhbWVBbmFseXRpY3MuaW5pdGlhbGl6ZTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRCdXNpbmVzc0V2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEJ1c2luZXNzRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkUmVzb3VyY2VFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRSZXNvdXJjZUV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFByb2dyZXNzaW9uRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkUHJvZ3Jlc3Npb25FdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGREZXNpZ25FdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGREZXNpZ25FdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRFcnJvckV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEVycm9yRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkQWRFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRBZEV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRJbmZvTG9nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRJbmZvTG9nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRWZXJib3NlTG9nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRWZXJib3NlTG9nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZW5hYmxlSGVhbHRoRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuZW5hYmxlSGVhbHRoRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDEnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDInXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDMnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMnXSA9IEdhbWVBbmFseXRpY3Muc2V0R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwnXSA9IEdhbWVBbmFseXRpY3Muc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWw7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc3RhcnRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnN0YXJ0U2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydlbmRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmVuZFNlc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnb25TdG9wJ10gPSBHYW1lQW5hbHl0aWNzLm9uU3RvcDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblJlc3VtZSddID0gR2FtZUFuYWx5dGljcy5vblJlc3VtZTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRSZW1vdGVDb25maWdzTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MuYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3JlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5yZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmcnXSA9IEdhbWVBbmFseXRpY3MuZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNKU09OJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzSlNPTjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpc1JlbW90ZUNvbmZpZ3NSZWFkeSddID0gR2FtZUFuYWx5dGljcy5pc1JlbW90ZUNvbmZpZ3NSZWFkeTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5hZGRPbkJlZm9yZVVubG9hZExpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3JlbW92ZU9uQmVmb3JlVW5sb2FkTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MucmVtb3ZlT25CZWZvcmVVbmxvYWRMaXN0ZW5lcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkRXJyb3JSZXBvcnRpbmcnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZEVycm9yUmVwb3J0aW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZVdyaXRhYmxlUGF0aCddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVXcml0YWJsZVBhdGg7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlTG9nSGFuZGxlciddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVMb2dIYW5kbGVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ29uUXVpdCddID0gR2FtZUFuYWx5dGljcy5vblF1aXQ7XG4gICAgICAgICAgICBcblxuICAgICAgICAgICAgaWYgKHR5cGVvZiBHYW1lQW5hbHl0aWNzLmdldEdsb2JhbE9iamVjdCgpICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2YgR2FtZUFuYWx5dGljcy5nZXRHbG9iYWxPYmplY3QoKVsnR2FtZUFuYWx5dGljcyddWydxJ10gIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBxOiBhbnlbXSA9IEdhbWVBbmFseXRpY3MuZ2V0R2xvYmFsT2JqZWN0KClbJ0dhbWVBbmFseXRpY3MnXVsncSddO1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgaW4gcSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuZ2FDb21tYW5kLmFwcGx5KG51bGwsIHFbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuXG4gICAgICAgICAgICAvLyBQbGF0Zm9ybSBob29rczogYmVmb3JldW5sb2FkIGluIHRoZSBicm93c2VyLCBiZWZvcmVFeGl0ICsgdGhlXG4gICAgICAgICAgICAvLyB1bmNhdWdodC1leGNlcHRpb24gbW9uaXRvciBpbiBOb2RlLiBCb3RoIGxpdmUgaW4gdGhlIHBsYXRmb3JtIG5vdy5cbiAgICAgICAgICAgIHBsYXRmb3JtLm9uSW5pdCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnYUNvbW1hbmQoLi4uYXJnczogYW55W10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKGFyZ3MubGVuZ3RoID4gMClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihhcmdzWzBdIGluIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihhcmdzLmxlbmd0aCA+IDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbYXJnc1swXV0uYXBwbHkobnVsbCwgQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJncywgMSkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFthcmdzWzBdXSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIHJlc291cmNlIGl0ZW0gdHlwZXMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVCdWlsZChidWlsZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJCdWlsZCB2ZXJzaW9uIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdWlsZChidWlsZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGJ1aWxkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgMzIgbGVuZ3RoLiBTdHJpbmc6IFwiICsgYnVpbGQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QnVpbGQoYnVpbGQpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVdyaXRhYmxlUGF0aChwYXRoOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIldyaXRhYmxlIHBhdGggbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2Uud3JpdGFibGVQYXRoID0gcGF0aDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVMb2dIYW5kbGVyKGhhbmRsZXI6KG1lc3NhZ2U6c3RyaW5nLCBsZXZlbDpzdHJpbmcpID0+IHZvaWQgPSBudWxsKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQUxvZ2dlci5zZXRIYW5kbGVyKGhhbmRsZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbihzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgc2RrIHZlcnNpb246IFNkayB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBzZGtHYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24gPSBzZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUVuZ2luZVZlcnNpb24oZ2FtZUVuZ2luZVZlcnNpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBnYW1lIGVuZ2luZSB2ZXJzaW9uOiBHYW1lIGVuZ2luZSB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBnYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24gPSBnYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVVc2VySWQodUlkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkEgY3VzdG9tIHVzZXIgaWQgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVVzZXJJZCh1SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSB1c2VyX2lkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgNjQgbGVuZ3RoLiBXaWxsIHVzZSBkZWZhdWx0IHVzZXJfaWQgbWV0aG9kLiBVc2VkIHN0cmluZzogXCIgKyB1SWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRVc2VySWQodUlkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFeHRVc2VySWQodUlkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RXh0VXNlcklkKHVJZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXh0VXNlcklkKCk6IHN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRFeHRVc2VySWQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VXNlcklkKCkgOiBzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0aWFsaXplKGdhbWVLZXk6c3RyaW5nID0gXCJcIiwgZ2FtZVNlY3JldDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTREsgYWxyZWFkeSBpbml0aWFsaXplZC4gQ2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVLZXlzKGdhbWVLZXksIGdhbWVTZWNyZXQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNESyBmYWlsZWQgaW5pdGlhbGl6ZS4gR2FtZSBrZXkgb3Igc2VjcmV0IGtleSBpcyBpbnZhbGlkLiBDYW4gb25seSBjb250YWluIGNoYXJhY3RlcnMgQS16IDAtOSwgZ2FtZUtleSBpcyAzMiBsZW5ndGgsIGdhbWVTZWNyZXQgaXMgNDAgbGVuZ3RoLiBGYWlsZWQga2V5cyAtIGdhbWVLZXk6IFwiICsgZ2FtZUtleSArIFwiLCBzZWNyZXRLZXk6IFwiICsgZ2FtZVNlY3JldCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCk7XG5cbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmludGVybmFsSW5pdGlhbGl6ZSgpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiLCBjYXJ0VHlwZTpzdHJpbmcgPSBcIlwiLCBjdXN0b21GaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30sIG1lcmdlRmllbGRzOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGJ1c2luZXNzIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBjYXJ0VHlwZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGJ1c2luZXNzIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlID0gRUdBUmVzb3VyY2VGbG93VHlwZS5VbmRlZmluZWQsIGN1cnJlbmN5OnN0cmluZyA9IFwiXCIsIGFtb3VudDpudW1iZXIgPSAwLCBpdGVtVHlwZTpzdHJpbmcgPSBcIlwiLCBpdGVtSWQ6c3RyaW5nID0gXCJcIiwgY3VzdG9tRmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9LCBtZXJnZUZpZWxkczpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgcmVzb3VyY2UgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGUsIGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXM6IEVHQVByb2dyZXNzaW9uU3RhdHVzID0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxOiBzdHJpbmcgPSBcIlwiLCBwcm9ncmVzc2lvbjAyOiBzdHJpbmcgPSBcIlwiLCBwcm9ncmVzc2lvbjAzOiBzdHJpbmcgPSBcIlwiLCBzY29yZT86IG51bWJlciwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBwcm9ncmVzc2lvbiBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlbmRTY29yZTogYm9vbGVhbiA9IHR5cGVvZiBzY29yZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMywgc2VuZFNjb3JlID8gc2NvcmUgOiAwLCBzZW5kU2NvcmUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBwcm9ncmVzc2lvbiBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOiBib29sZWFuID0gdHlwZW9mIHNjb3JlID09PSBcIm51bWJlclwiO1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZFByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDEsIHByb2dyZXNzaW9uMDIsIHByb2dyZXNzaW9uMDMsIHNlbmRTY29yZSA/IHNjb3JlIDogMCwgc2VuZFNjb3JlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDogc3RyaW5nLCB2YWx1ZT86IG51bWJlciwgY3VzdG9tRmllbGRzOiB7IFtpZDogc3RyaW5nXTogYW55IH0gPSB7fSwgbWVyZ2VGaWVsZHM6IGJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmlzVW5sb2FkaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBkZXNpZ24gZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB2YXIgc2VuZFZhbHVlOiBib29sZWFuID0gdHlwZW9mIHZhbHVlID09PSBcIm51bWJlclwiO1xuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREZXNpZ25FdmVudChldmVudElkLCBzZW5kVmFsdWUgPyB2YWx1ZSA6IDAsIHNlbmRWYWx1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBzZW5kVmFsdWU6IGJvb2xlYW4gPSB0eXBlb2YgdmFsdWUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGVzaWduRXZlbnQoZXZlbnRJZCwgc2VuZFZhbHVlID8gdmFsdWUgOiAwLCBzZW5kVmFsdWUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRFcnJvckV2ZW50KHNldmVyaXR5OiBFR0FFcnJvclNldmVyaXR5ID0gRUdBRXJyb3JTZXZlcml0eS5VbmRlZmluZWQsIG1lc3NhZ2U6IHN0cmluZyA9IFwiXCIsIGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30sIG1lcmdlRmllbGRzOiBib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgZXJyb3IgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgZXJyb3IgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQWRFdmVudFdpdGhOb0FkUmVhc29uKGFkQWN0aW9uOiBFR0FBZEFjdGlvbiA9IEVHQUFkQWN0aW9uLlVuZGVmaW5lZCwgYWRUeXBlOiBFR0FBZFR5cGUgPSBFR0FBZFR5cGUuVW5kZWZpbmVkLCBhZFNka05hbWU6IHN0cmluZyA9IFwiXCIsIGFkUGxhY2VtZW50OiBzdHJpbmcgPSBcIlwiLCBub0FkUmVhc29uOiBFR0FBZEVycm9yID0gRUdBQWRFcnJvci5VbmRlZmluZWQsIGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30sIG1lcmdlRmllbGRzOiBib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIG5vQWRSZWFzb24sIDAsIGZhbHNlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIG5vQWRSZWFzb24sIDAsIGZhbHNlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQWRFdmVudFdpdGhEdXJhdGlvbihhZEFjdGlvbjogRUdBQWRBY3Rpb24gPSBFR0FBZEFjdGlvbi5VbmRlZmluZWQsIGFkVHlwZTogRUdBQWRUeXBlID0gRUdBQWRUeXBlLlVuZGVmaW5lZCwgYWRTZGtOYW1lOiBzdHJpbmcgPSBcIlwiLCBhZFBsYWNlbWVudDogc3RyaW5nID0gXCJcIiwgZHVyYXRpb246IG51bWJlciA9IDAsIGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30sIG1lcmdlRmllbGRzOiBib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pc1VubG9hZGluZylcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYWQgZXZlbnRcIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRBZEV2ZW50KGFkQWN0aW9uLCBhZFR5cGUsIGFkU2RrTmFtZSwgYWRQbGFjZW1lbnQsIEVHQUFkRXJyb3IuVW5kZWZpbmVkLCBkdXJhdGlvbiwgdHJ1ZSwgY3VzdG9tRmllbGRzLCBtZXJnZUZpZWxkcyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGFkIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQWRFdmVudChhZEFjdGlvbiwgYWRUeXBlLCBhZFNka05hbWUsIGFkUGxhY2VtZW50LCBFR0FBZEVycm9yLlVuZGVmaW5lZCwgZHVyYXRpb24sIHRydWUsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRBZEV2ZW50KGFkQWN0aW9uOiBFR0FBZEFjdGlvbiA9IEVHQUFkQWN0aW9uLlVuZGVmaW5lZCwgYWRUeXBlOiBFR0FBZFR5cGUgPSBFR0FBZFR5cGUuVW5kZWZpbmVkLCBhZFNka05hbWU6IHN0cmluZyA9IFwiXCIsIGFkUGxhY2VtZW50OiBzdHJpbmcgPSBcIlwiLCBjdXN0b21GaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBhbnkgfSA9IHt9LCBtZXJnZUZpZWxkczogYm9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaXNVbmxvYWRpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGFkIGV2ZW50XCIpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQWRFdmVudChhZEFjdGlvbiwgYWRUeXBlLCBhZFNka05hbWUsIGFkUGxhY2VtZW50LCBFR0FBZEVycm9yLlVuZGVmaW5lZCwgMCwgZmFsc2UsIGN1c3RvbUZpZWxkcywgbWVyZ2VGaWVsZHMpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBhZCBldmVudFwiKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEFkRXZlbnQoYWRBY3Rpb24sIGFkVHlwZSwgYWRTZGtOYW1lLCBhZFBsYWNlbWVudCwgRUdBQWRFcnJvci5VbmRlZmluZWQsIDAsIGZhbHNlLCBjdXN0b21GaWVsZHMsIG1lcmdlRmllbGRzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEluZm9Mb2coZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5mbyBsb2dnaW5nIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRJbmZvTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkVmVyYm9zZUxvZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRWZXJib3NlTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmVyYm9zZSBsb2dnaW5nIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0TWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWcpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgc3VibWlzc2lvbiBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgc3VibWlzc2lvbiBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBlbmFibGVIZWFsdGhFdmVudChmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5oZWFsdGguR0FIZWFsdGguY29uZmlndXJlKGZsYWcpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAzKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEdsb2JhbEN1c3RvbUV2ZW50RmllbGRzKGN1c3RvbUZpZWxkczogeyBbaWQ6IHN0cmluZ106IGFueSB9ID0ge30pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgZ2xvYmFsIGN1c3RvbSBldmVudCBmaWVsZHM6IFwiICsgSlNPTi5zdHJpbmdpZnkoY3VzdG9tRmllbGRzKSk7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50R2xvYmFsQ3VzdG9tRXZlbnRGaWVsZHMgPSBjdXN0b21GaWVsZHM7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbEluU2Vjb25kcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc3RhcnRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy9pZihHQVN0YXRlLmdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaXNFbmFibGVkKCkgJiYgR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm9uU3RvcCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKEV4Y2VwdGlvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICAvKipcbiAgICAgICAgICogUG9ydCBvZiBHYW1lQW5hbHl0aWNzOjpzZXRFbmFibGVkRXJyb3JSZXBvcnRpbmcgKEdhbWVBbmFseXRpY3MuaDoxMDUpLlxuICAgICAgICAgKiBPZmYgYnkgZGVmYXVsdCAoc3BlYywgZGl2ZXJnZW5jZSA0KS4gU2V0IHN5bmNocm9ub3VzbHkgcmF0aGVyIHRoYW4gb24gdGhlXG4gICAgICAgICAqIHRhc2sgcXVldWUgc28gYSBjcmFzaCB0aGF0IGZvbGxvd3MgaW1tZWRpYXRlbHkgaXMgc3RpbGwgcmVwb3J0ZWQuXG4gICAgICAgICAqL1xuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRFcnJvclJlcG9ydGluZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5zZXRFbmFibGVFcnJvclJlcG9ydGluZyhmbGFnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8qKlxuICAgICAgICAgKiBQb3J0IG9mIEdhbWVBbmFseXRpY3M6Om9uUXVpdCAoR2FtZUFuYWx5dGljcy5oOjE0OSkg4oCUIFJFUVVJUkVEIGluIGhlYWRsZXNzXG4gICAgICAgICAqIGJlZm9yZSB0aGUgcHJvY2VzcyBleGl0cy4gUmVzb2x2ZXMgb25jZSB0aGUgcXVldWUgaGFzIGRyYWluZWQgYW5kIHRoZVxuICAgICAgICAgKiBzZXNzaW9uIGNhY2hlIGZpbGUgaXMgZGVsZXRlZC4gTmV2ZXIgYnVzeS13YWl0czogdGhlcmUgaXMgb25lIHRocmVhZC5cbiAgICAgICAgICpcbiAgICAgICAgICogT3JkZXIgbWF0dGVyczogYSBxdWV1ZWQgaW5pdGlhbGl6ZSgpIHN0YXJ0cyBpdHMgc2Vzc2lvbiBvbmx5IGluc2lkZSB0aGVcbiAgICAgICAgICogYXN5bmMgaW5pdCBjYWxsYmFjaywgc28gc2V0dGxlIHRoYXQgZmlyc3QsIHRoZW4gZW5kIHRoZSBzZXNzaW9uLCB0aGVuXG4gICAgICAgICAqIHNldHRsZSB0aGUgc2Vzc2lvbl9lbmQgc2VuZC5cbiAgICAgICAgICovXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHF1aXRQcm9taXNlOlByb21pc2U8dm9pZD4gPSBudWxsO1xuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgb25RdWl0KHRpbWVvdXRNcz86bnVtYmVyKTogUHJvbWlzZTx2b2lkPlxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBPbmUtc2hvdCwgbGlrZSBDKysncyBgaWYoX2VuZFRocmVhZCkgcmV0dXJuO2A6IGFuIGV4cGxpY2l0IGNhbGwgYW5kIHRoZVxuICAgICAgICAgICAgLy8gcGxhdGZvcm0ncyBiZWZvcmVFeGl0IGhhbmRsZXIgbXVzdCBub3QgZHJhaW4gdHdpY2UuXG4gICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5xdWl0UHJvbWlzZSkgeyByZXR1cm4gR2FtZUFuYWx5dGljcy5xdWl0UHJvbWlzZTsgfVxuICAgICAgICAgICAgdmFyIGRlYWRsaW5lOmFueSA9IHR5cGVvZiB0aW1lb3V0TXMgPT09IFwibnVtYmVyXCIgPyBzZXRUaW1lb3V0KCgpID0+IEdBSFRUUEFwaS5nZXRDbGllbnQoKS5jbGVhbnVwKCksIHRpbWVvdXRNcykgOiBudWxsO1xuICAgICAgICAgICAgcmV0dXJuIEdhbWVBbmFseXRpY3MucXVpdFByb21pc2UgPSBHYW1lQW5hbHl0aWNzLnNldHRsZSgxMClcbiAgICAgICAgICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFRoZSA4IHMgdGljayBpcyB0aGUgb25seSBjYWxsZXIgb2YgcHJvY2Vzc0V2ZW50cyB3aXRoIGNsZWFudXAsIHdoaWNoXG4gICAgICAgICAgICAgICAgICAgIC8vIGlzIHdoYXQgc3ludGhlc2lzZXMgc2Vzc2lvbl9lbmQgZm9yIGFkb3B0ZWQgb3JwaGFuIHNlc3Npb25zLiBBXG4gICAgICAgICAgICAgICAgICAgIC8vIHByb2Nlc3MgdGhhdCBleGl0cyBpbiBhIHNlY29uZCBuZXZlciByZWFjaGVzIGl0LCBzbyBkbyBvbmUgcGFzcyBoZXJlLlxuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT4geyBpZiAoR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpIHsgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCB0cnVlKTsgfSB9KTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+IHsgR0FUaHJlYWRpbmcuZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOyB9KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdhbWVBbmFseXRpY3Muc2V0dGxlKDEwKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgLy8gU3BlYzogdGhlIGNhY2hlIGlzIGRlbGV0ZWQgYWZ0ZXIgYSBTVUNDRVNTRlVMIGRyYWluLiBPbiBhXG4gICAgICAgICAgICAgICAgICAgIC8vIE5vUmVzcG9uc2UgdGhlIGV2ZW50cyB3ZXJlIHB1dCBiYWNrIGFzICduZXcnIGFuZCBtdXN0IHN1cnZpdmVcbiAgICAgICAgICAgICAgICAgICAgLy8gZm9yIHRoZSBuZXh0IHJ1bidzIHN3ZWVwOyBkZWxldGluZyBoZXJlIHdvdWxkIGxvc2UgdGhlbS5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGxlZnQgPSBHQVN0b3JlLnNlbGVjdChnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlLkV2ZW50cyk7XG4gICAgICAgICAgICAgICAgICAgIGlmICghbGVmdCB8fCBsZWZ0Lmxlbmd0aCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGVTZXNzaW9uQ2FjaGUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJvblF1aXQ6IFwiICsgbGVmdC5sZW5ndGggKyBcIiBldmVudChzKSBjb3VsZCBub3QgYmUgZGVsaXZlcmVkOyBzZXNzaW9uIGNhY2hlIGtlcHQgZm9yIHRoZSBuZXh0IHJ1blwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjbGVhclRpbWVvdXQoZGVhZGxpbmUpO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wUHVtcCgpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2V0dGxlKG1heFJvdW5kczpudW1iZXIpOiBQcm9taXNlPHZvaWQ+XG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLmZsdXNoKCk7XG4gICAgICAgICAgICBpZiAobWF4Um91bmRzIDw9IDAgfHwgKEdBSFRUUEFwaS5pbkZsaWdodENvdW50KCkgPT09IDAgJiYgR0FUaHJlYWRpbmcucGVuZGluZ1Rhc2tDb3VudCgpID09PSAwKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gR0FIVFRQQXBpLndoZW5JZGxlKCkudGhlbigoKSA9PiBHYW1lQW5hbHl0aWNzLnNldHRsZShtYXhSb3VuZHMgLSAxKSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5yZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbW90ZUNvbmZpZ3NWYWx1ZUFzU3RyaW5nKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTpzdHJpbmcgPSBudWxsKTpzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0Q29uZmlndXJhdGlvblN0cmluZ1ZhbHVlKGtleSwgZGVmYXVsdFZhbHVlKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNKU09OKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTphbnkgPSBudWxsKTphbnlcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0Q29uZmlndXJhdGlvbkpzb25WYWx1ZShrZXksIGRlZmF1bHRWYWx1ZSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGlzUmVtb3RlQ29uZmlnc1JlYWR5KCk6Ym9vbGVhblxuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pc1JlbW90ZUNvbmZpZ3NSZWFkeSgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmFkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUucmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZygpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ0lkKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldEFCVGVzdGluZ0lkKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ1ZhcmlhbnRJZCgpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRBQlRlc3RpbmdWYXJpYW50SWQoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcjogeyBvbkJlZm9yZVVubG9hZDogKCkgPT4gdm9pZCB9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmFkZE9uQmVmb3JlVW5sb2FkTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVPbkJlZm9yZVVubG9hZExpc3RlbmVyKGxpc3RlbmVyOiB7IG9uQmVmb3JlVW5sb2FkOiAoKSA9PiB2b2lkIH0pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUucmVtb3ZlT25CZWZvcmVVbmxvYWRMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbnRlcm5hbEluaXRpYWxpemUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmVuc3VyZVBlcnNpc3RlZFN0YXRlcygpO1xuICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXksIEdBU3RhdGUuZ2V0RGVmYXVsdElkKCkpO1xuICAgICAgICAgICAgR0FTdG9yZS5zYXZlKEdBU3RhdGUuZ2V0R2FtZUtleSgpKTtcblxuICAgICAgICAgICAgR0FTdGF0ZS5zZXRJbml0aWFsaXplZCh0cnVlKTtcblxuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5uZXdTZXNzaW9uKCk7XG5cbiAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIG5ld1Nlc3Npb24oKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiU3RhcnRpbmcgYSBuZXcgc2Vzc2lvbi5cIik7XG5cbiAgICAgICAgICAgIC8vIG1ha2Ugc3VyZSB0aGUgY3VycmVudCBjdXN0b20gZGltZW5zaW9ucyBhcmUgdmFsaWRcbiAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5oZWxkID0gdHJ1ZTtcbiAgICAgICAgICAgIHRyeSB7IEdBSFRUUEFwaS5pbnN0YW5jZS5yZXF1ZXN0SW5pdChHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3NIYXNoLCBHYW1lQW5hbHl0aWNzLnN0YXJ0TmV3U2Vzc2lvbkNhbGxiYWNrKTsgfVxuICAgICAgICAgICAgY2F0Y2ggKGUpIHsgR0FUaHJlYWRpbmcuaGVsZCA9IGZhbHNlOyB0aHJvdyBlOyB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBzdGFydE5ld1Nlc3Npb25DYWxsYmFjayhpbml0UmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBpbml0UmVzcG9uc2VEaWN0Ontba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLmhlbGQgPSBmYWxzZTtcbiAgICAgICAgICAgIC8vIGluaXQgaXMgb2tcbiAgICAgICAgICAgIGlmKChpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5PayB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkKSAmJiBpbml0UmVzcG9uc2VEaWN0KVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHNldCB0aGUgdGltZSBvZmZzZXQgLSBob3cgbWFueSBzZWNvbmRzIHRoZSBsb2NhbCB0aW1lIGlzIGRpZmZlcmVudCBmcm9tIHNlcnZlcnRpbWVcbiAgICAgICAgICAgICAgICB2YXIgdGltZU9mZnNldFNlY29uZHM6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICBpZihpbml0UmVzcG9uc2VEaWN0W1wic2VydmVyX3RzXCJdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlcnZlclRzOm51bWJlciA9IGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB0aW1lT2Zmc2V0U2Vjb25kcyA9IEdBU3RhdGUuY2FsY3VsYXRlU2VydmVyVGltZU9mZnNldChzZXJ2ZXJUcyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJ0aW1lX29mZnNldFwiXSA9IHRpbWVPZmZzZXRTZWNvbmRzO1xuXG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlICE9IEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIHVzZSBjYWNoZWQgaWYgbm90IENyZWF0ZWRcbiAgICAgICAgICAgICAgICAgICAgaWYoY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NcIl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NcIl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYoY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImNvbmZpZ3NfaGFzaFwiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYoY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiYWJfaWRcIl0gPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYoY3VycmVudFNka0NvbmZpZ1tcImFiX3ZhcmlhbnRfaWRcIl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJhYl92YXJpYW50X2lkXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImFiX3ZhcmlhbnRfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3NIYXNoID0gaW5pdFJlc3BvbnNlRGljdFtcImNvbmZpZ3NfaGFzaFwiXSA/IGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzX2hhc2hcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYWJJZCA9IGluaXRSZXNwb25zZURpY3RbXCJhYl9pZFwiXSA/IGluaXRSZXNwb25zZURpY3RbXCJhYl9pZFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZCA9IGluaXRSZXNwb25zZURpY3RbXCJhYl92YXJpYW50X2lkXCJdID8gaW5pdFJlc3BvbnNlRGljdFtcImFiX3ZhcmlhbnRfaWRcIl0gOiBcIlwiO1xuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IG5ldyBjb25maWcgaW4gc3FsIGxpdGUgY3Jvc3Mgc2Vzc2lvbiBzdG9yYWdlXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuZ2V0R2FtZUtleSgpLCBHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSwgR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoaW5pdFJlc3BvbnNlRGljdCkpKTtcblxuICAgICAgICAgICAgICAgIC8vIHNldCBuZXcgY29uZmlnIGFuZCBjYWNoZSBpbiBtZW1vcnlcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCA9IGluaXRSZXNwb25zZURpY3Q7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBpbml0UmVzcG9uc2VEaWN0O1xuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJJbml0aWFsaXplIFNESyBmYWlsZWQgLSBVbmF1dGhvcml6ZWRcIik7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGxvZyB0aGUgc3RhdHVzIGlmIG5vIGNvbm5lY3Rpb25cbiAgICAgICAgICAgICAgICBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLlJlcXVlc3RUaW1lb3V0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gbm8gcmVzcG9uc2UuIENvdWxkIGJlIG9mZmxpbmUgb3IgdGltZW91dC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gYmFkIHJlc3BvbnNlLiBDb3VsZCBiZSBiYWQgcmVzcG9uc2UgZnJvbSBwcm94eSBvciBHQSBzZXJ2ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0IHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLlVua25vd25SZXNwb25zZUNvZGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVxdWVzdCBvciB1bmtub3duIHJlc3BvbnNlLlwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBpbml0IGNhbGwgZmFpbGVkIChwZXJoYXBzIG9mZmxpbmUpXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkICE9IG51bGwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGNhY2hlZCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzZXQgbGFzdCBjcm9zcyBzZXNzaW9uIHN0b3JlZCBjb25maWcgaW5pdCB2YWx1ZXNcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBkZWZhdWx0IGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IGluaXQgdmFsdWVzXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnRGVmYXVsdDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gc2V0IG9mZnNldCBpbiBzdGF0ZSAobWVtb3J5KSBmcm9tIGN1cnJlbnQgY29uZmlnIChjb25maWcgY291bGQgYmUgZnJvbSBjYWNoZSBldGMuKVxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0ID0gR0FTdGF0ZS5nZXRTZGtDb25maWcoKVtcInRpbWVfb2Zmc2V0XCJdID8gR0FTdGF0ZS5nZXRTZGtDb25maWcoKVtcInRpbWVfb2Zmc2V0XCJdIGFzIG51bWJlciA6IDA7XG5cbiAgICAgICAgICAgIC8vIHBvcHVsYXRlIGNvbmZpZ3VyYXRpb25zXG4gICAgICAgICAgICBHQVN0YXRlLnBvcHVsYXRlQ29uZmlndXJhdGlvbnMoR0FTdGF0ZS5nZXRTZGtDb25maWcoKSk7XG5cbiAgICAgICAgICAgIC8vIGlmIFNESyBpcyBkaXNhYmxlZCBpbiBjb25maWdcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc3RhcnQgc2Vzc2lvbjogU0RLIGlzIGRpc2FibGVkLlwiKTtcbiAgICAgICAgICAgICAgICAvLyBzdG9wIGV2ZW50IHF1ZXVlXG4gICAgICAgICAgICAgICAgLy8gKyBtYWtlIHN1cmUgaXQncyBhYmxlIHRvIHJlc3RhcnQgaWYgYW5vdGhlciBzZXNzaW9uIGRldGVjdHMgaXQncyBlbmFibGVkIGFnYWluXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBnZW5lcmF0ZSB0aGUgbmV3IHNlc3Npb25cbiAgICAgICAgICAgIHZhciBuZXdTZXNzaW9uSWQ6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAvLyBTZXQgc2Vzc2lvbiBpZFxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQgPSBuZXdTZXNzaW9uSWQ7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIHN0YXJ0XG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuXG4gICAgICAgICAgICAvLyBBZGQgc2Vzc2lvbiBzdGFydCBldmVudFxuICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTtcblxuICAgICAgICAgICAgLy8gQWRkIHNkayBpbml0IGV2ZW50IGlmIGVuYWJsZWRcbiAgICAgICAgICAgIEdBRXZlbnRzLmFkZFNES0luaXRFdmVudCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBpZighR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgR0FMb2dnZXIuaShcIlJlc3VtaW5nIHNlc3Npb24uXCIpO1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaXNTZGtSZWFkeShuZWVkc0luaXRpYWxpemVkOmJvb2xlYW4sIHdhcm46Ym9vbGVhbiA9IHRydWUsIG1lc3NhZ2U6c3RyaW5nID0gXCJcIik6IGJvb2xlYW5cbiAgICAgICAge1xuICAgICAgICAgICAgaWYobWVzc2FnZSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBtZXNzYWdlID0gbWVzc2FnZSArIFwiOiBcIjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gSXMgU0RLIGluaXRpYWxpemVkXG4gICAgICAgICAgICBpZiAobmVlZHNJbml0aWFsaXplZCAmJiAhR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNESyBpcyBub3QgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIElzIFNESyBlbmFibGVkXG4gICAgICAgICAgICBpZiAobmVlZHNJbml0aWFsaXplZCAmJiAhR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAod2FybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU0RLIGlzIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBJcyBzZXNzaW9uIHN0YXJ0ZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAod2FybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU2Vzc2lvbiBoYXMgbm90IHN0YXJ0ZWQgeWV0XCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgIH1cbn1cbmdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5pbml0KCk7XG52YXIgR2FtZUFuYWx5dGljcyA9IGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5nYUNvbW1hbmQ7XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmFnZVxuICAgIHtcbiAgICAgICAgLy8gS2V5L3ZhbHVlIHN0b3JhZ2UsIHRoZSBzaGFwZSBvZiBsb2NhbFN0b3JhZ2UuIERpdmVyZ2VuY2UgMSBpbiB0aGUgc3BlYzpcbiAgICAgICAgLy8gQysrIG1vZGVscyBwZXJzaXN0ZW5jZSBhcyBhIHBhdGggYmVjYXVzZSBldmVyeSBwbGF0Zm9ybSBoYXMgYVxuICAgICAgICAvLyBmaWxlc3lzdGVtOyB0aGUgYnJvd3NlciBkb2VzIG5vdCwgc28gdGhlIGFic3RyYWN0aW9uIGlzIHRoaXMgaW50ZXJmYWNlLlxuICAgICAgICAvL1xuICAgICAgICAvLyBUd28gSlMtcG9ydCBleHRlbnNpb25zIGJleW9uZCB0aGUgc3BlYydzIGZvdXIgbWV0aG9kczpcbiAgICAgICAgLy8gIC0gZ2V0U2l6ZUJ5dGVzKCk6IHRoZSBzcGVjIGRlY2lkZXMgTm9kZSBtZWFzdXJlcyB0aGUgc3RvcmUgaW4gYnl0ZXMgYW5kXG4gICAgICAgIC8vICAgIHRoZSBicm93c2VyIGluIGVudHJpZXM7IEdBU3RvcmUgaGFzIHRvIGJlIGFibGUgdG8gYXNrLiAtMSA9IGNhbm5vdFxuICAgICAgICAvLyAgICBtZWFzdXJlIChicm93c2VyKSwgYW5kIEdBU3RvcmUgZmFsbHMgYmFjayB0byB0aGUgZW50cnkgY291bnQuXG4gICAgICAgIC8vICAtIGRlbGV0ZVNlc3Npb25DYWNoZSgpOiB0aGUgc3BlYyBwdXRzIHRoZSBwZXItc2Vzc2lvbiB0bXAgY2FjaGUgaW5zaWRlXG4gICAgICAgIC8vICAgIElHQVN0b3JhZ2UgYW5kIGhhcyBvblF1aXQoKSBkZWxldGUgaXQgYWZ0ZXIgYSBzdWNjZXNzZnVsIGRyYWluLlxuICAgICAgICBleHBvcnQgaW50ZXJmYWNlIElHQVN0b3JhZ2VcbiAgICAgICAge1xuICAgICAgICAgICAgZ2V0SXRlbShrZXk6c3RyaW5nKTogc3RyaW5nIHwgbnVsbDtcbiAgICAgICAgICAgIHNldEl0ZW0oa2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZDtcbiAgICAgICAgICAgIHJlbW92ZUl0ZW0oa2V5OnN0cmluZyk6IHZvaWQ7XG4gICAgICAgICAgICBpc0F2YWlsYWJsZSgpOiBib29sZWFuO1xuICAgICAgICAgICAgZ2V0U2l6ZUJ5dGVzKCk6IG51bWJlcjtcbiAgICAgICAgICAgIGRlbGV0ZVNlc3Npb25DYWNoZSgpOiB2b2lkO1xuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIC8vIFBvcnQgb2YgaW5jbHVkZS9HYW1lQW5hbHl0aWNzL0dBSHR0cENsaWVudC5oLiBEaXZlcmdlbmNlIDI6IEMrKyByZXR1cm5zIHRoZVxuICAgICAgICAvLyBSZXNwb25zZSBzeW5jaHJvbm91c2x5OyBKUyByZXR1cm5zIGEgcHJvbWlzZS4gY29kZSA9IC0xIGlzIHRoZSBmYWlsdXJlXG4gICAgICAgIC8vIHNlbnRpbmVsLiBzdGF0dXNUZXh0IGlzIGEgSlMgYWRkaXRpb24gdXNlZCBvbmx5IGZvciBsb2cgbGluZXMuXG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgR0FIdHRwUmVzcG9uc2VcbiAgICAgICAge1xuICAgICAgICAgICAgY29kZTpudW1iZXI7XG4gICAgICAgICAgICBwYWNrZXQ6VWludDhBcnJheTtcbiAgICAgICAgICAgIHN0YXR1c1RleHQ/OnN0cmluZztcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgSUdBSHR0cENsaWVudFxuICAgICAgICB7XG4gICAgICAgICAgICBpbml0aWFsaXplKCk6IHZvaWQ7XG4gICAgICAgICAgICBjbGVhbnVwKCk6IHZvaWQ7XG4gICAgICAgICAgICBzZW5kUmVxdWVzdCh1cmw6c3RyaW5nLCBhdXRoOnN0cmluZywgcGF5bG9hZDpVaW50OEFycmF5LCB1c2VHemlwOmJvb2xlYW4pOiBQcm9taXNlPEdBSHR0cFJlc3BvbnNlPjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFdoYXQgdGhlIGV4aXN0aW5nIHJlc3BvbnNlIGNhbGxiYWNrcyByZWFkLiBYTUxIdHRwUmVxdWVzdCBzYXRpc2ZpZXMgaXQuXG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgR0FIdHRwUmVzcG9uc2VMaWtlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHN0YXR1czpudW1iZXI7XG4gICAgICAgICAgICBzdGF0dXNUZXh0OnN0cmluZztcbiAgICAgICAgICAgIHJlc3BvbnNlVGV4dDpzdHJpbmc7XG4gICAgICAgIH1cbiAgICB9XG59XG4iXX0=

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
