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
    var EGAGender;
    (function (EGAGender) {
        EGAGender[EGAGender["Undefined"] = 0] = "Undefined";
        EGAGender[EGAGender["Male"] = 1] = "Male";
        EGAGender[EGAGender["Female"] = 2] = "Female";
    })(EGAGender = gameanalytics.EGAGender || (gameanalytics.EGAGender = {}));
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
    var http;
    (function (http) {
        var EGASdkErrorType;
        (function (EGASdkErrorType) {
            EGASdkErrorType[EGASdkErrorType["Undefined"] = 0] = "Undefined";
            EGASdkErrorType[EGASdkErrorType["Rejected"] = 1] = "Rejected";
        })(EGASdkErrorType = http.EGASdkErrorType || (http.EGASdkErrorType = {}));
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
})(gameanalytics || (gameanalytics = {}));
var EGAErrorSeverity = gameanalytics.EGAErrorSeverity;
var EGAGender = gameanalytics.EGAGender;
var EGAProgressionStatus = gameanalytics.EGAProgressionStatus;
var EGAResourceFlowType = gameanalytics.EGAResourceFlowType;
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
                return (GAUtilities.s4() + GAUtilities.s4() + "-" + GAUtilities.s4() + "-4" + GAUtilities.s4().substr(0, 3) + "-" + GAUtilities.s4() + "-" + GAUtilities.s4() + GAUtilities.s4() + GAUtilities.s4()).toLowerCase();
            };
            GAUtilities.s4 = function () {
                return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
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
        var EGASdkErrorType = gameanalytics.http.EGASdkErrorType;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GAValidator = (function () {
            function GAValidator() {
            }
            GAValidator.validateBusinessEvent = function (currency, amount, cartType, itemType, itemId) {
                if (!GAValidator.validateCurrency(currency)) {
                    GALogger.w("Validation fail - business event - currency: Cannot be (null) and need to be A-Z, 3 characters and in the standard at openexchangerates.org. Failed currency: " + currency);
                    return false;
                }
                if (amount < 0) {
                    GALogger.w("Validation fail - business event - amount. Cannot be less than 0. Failed amount: " + amount);
                    return false;
                }
                if (!GAValidator.validateShortString(cartType, true)) {
                    GALogger.w("Validation fail - business event - cartType. Cannot be above 32 length. String: " + cartType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - business event - itemId. Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - business event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateResourceEvent = function (flowType, currency, amount, itemType, itemId, availableCurrencies, availableItemTypes) {
                if (flowType == gameanalytics.EGAResourceFlowType.Undefined) {
                    GALogger.w("Validation fail - resource event - flowType: Invalid flow type.");
                    return false;
                }
                if (!currency) {
                    GALogger.w("Validation fail - resource event - currency: Cannot be (null)");
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableCurrencies, currency)) {
                    GALogger.w("Validation fail - resource event - currency: Not found in list of pre-defined available resource currencies. String: " + currency);
                    return false;
                }
                if (!(amount > 0)) {
                    GALogger.w("Validation fail - resource event - amount: Float amount cannot be 0 or negative. Value: " + amount);
                    return false;
                }
                if (!itemType) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null)");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableItemTypes, itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Not found in list of pre-defined available resource itemTypes. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateProgressionEvent = function (progressionStatus, progression01, progression02, progression03) {
                if (progressionStatus == gameanalytics.EGAProgressionStatus.Undefined) {
                    GALogger.w("Validation fail - progression event: Invalid progression status.");
                    return false;
                }
                if (progression03 && !(progression02 || !progression01)) {
                    GALogger.w("Validation fail - progression event: 03 found but 01+02 are invalid. Progression must be set as either 01, 01+02 or 01+02+03.");
                    return false;
                }
                else if (progression02 && !progression01) {
                    GALogger.w("Validation fail - progression event: 02 found but not 01. Progression must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                else if (!progression01) {
                    GALogger.w("Validation fail - progression event: progression01 not valid. Progressions must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(progression01, false)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot be (null), empty or above 64 characters. String: " + progression01);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(progression01)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression01);
                    return false;
                }
                if (progression02) {
                    if (!GAValidator.validateEventPartLength(progression02, true)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot be empty or above 64 characters. String: " + progression02);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression02)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression02);
                        return false;
                    }
                }
                if (progression03) {
                    if (!GAValidator.validateEventPartLength(progression03, true)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot be empty or above 64 characters. String: " + progression03);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression03)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression03);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateDesignEvent = function (eventId, value) {
                if (!GAValidator.validateEventIdLength(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Cannot be (null) or empty. Only 5 event parts allowed seperated by :. Each part need to be 32 characters or less. String: " + eventId);
                    return false;
                }
                if (!GAValidator.validateEventIdCharacters(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Non valid characters. Only allowed A-z, 0-9, -_., ()!?. String: " + eventId);
                    return false;
                }
                return true;
            };
            GAValidator.validateErrorEvent = function (severity, message) {
                if (severity == gameanalytics.EGAErrorSeverity.Undefined) {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return false;
                }
                if (!GAValidator.validateLongString(message, true)) {
                    GALogger.w("Validation fail - error event - message: Message cannot be above 8192 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateSdkErrorEvent = function (gameKey, gameSecret, type) {
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    return false;
                }
                if (type === EGASdkErrorType.Undefined) {
                    GALogger.w("Validation fail - sdk error event - type: Type was unsupported value.");
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
                if (!GAUtilities.stringMatch(wrapperVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEngineVersion = function (engineVersion) {
                if (!engineVersion || !GAUtilities.stringMatch(engineVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
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
            GAValidator.validateFacebookId = function (facebookId) {
                if (!GAValidator.validateString(facebookId, false)) {
                    GALogger.w("Validation fail - facebook id: id cannot be (null), empty or above 64 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateGender = function (gender) {
                if (isNaN(Number(gameanalytics.EGAGender[gender]))) {
                    if (gender == gameanalytics.EGAGender.Undefined || !(gender == gameanalytics.EGAGender.Male || gender == gameanalytics.EGAGender.Female)) {
                        GALogger.w("Validation fail - gender: Has to be 'male' or 'female'. Was: " + gender);
                        return false;
                    }
                }
                else {
                    if (gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Undefined] || !(gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Male] || gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Female])) {
                        GALogger.w("Validation fail - gender: Has to be 'male' or 'female'. Was: " + gender);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateBirthyear = function (birthYear) {
                if (birthYear < 0 || birthYear > 9999) {
                    GALogger.w("Validation fail - birthYear: Cannot be (null) or invalid range.");
                    return false;
                }
                return true;
            };
            GAValidator.validateClientTs = function (clientTs) {
                if (clientTs < (-4294967295 + 1) || clientTs > (4294967295 - 1)) {
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
            GADevice.sdkWrapperVersion = "javascript 3.1.2";
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
                new NameValueVersion("linux", "Linux", "rv")
            ]);
            GADevice.buildPlatform = GADevice.runtimePlatformToString();
            GADevice.deviceModel = GADevice.getDeviceModel();
            GADevice.deviceManufacturer = GADevice.getDeviceManufacturer();
            GADevice.osVersion = GADevice.getOSVersionString();
            GADevice.browserVersion = GADevice.getBrowserVersionString();
            GADevice.maxSafeInteger = Math.pow(2, 53) - 1;
            return GADevice;
        }());
        device.GADevice = GADevice;
    })(device = gameanalytics.device || (gameanalytics.device = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var TimedBlock = (function () {
            function TimedBlock(deadline) {
                this.deadline = deadline;
                this.ignore = false;
                this.async = false;
                this.running = false;
                this.id = ++TimedBlock.idCounter;
            }
            TimedBlock.idCounter = 0;
            return TimedBlock;
        }());
        threading.TimedBlock = TimedBlock;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var PriorityQueue = (function () {
            function PriorityQueue(priorityComparer) {
                this.comparer = priorityComparer;
                this._subQueues = {};
                this._sortedKeys = [];
            }
            PriorityQueue.prototype.enqueue = function (priority, item) {
                if (this._sortedKeys.indexOf(priority) === -1) {
                    this.addQueueOfPriority(priority);
                }
                this._subQueues[priority].push(item);
            };
            PriorityQueue.prototype.addQueueOfPriority = function (priority) {
                var _this = this;
                this._sortedKeys.push(priority);
                this._sortedKeys.sort(function (x, y) { return _this.comparer.compare(x, y); });
                this._subQueues[priority] = [];
            };
            PriorityQueue.prototype.peek = function () {
                if (this.hasItems()) {
                    return this._subQueues[this._sortedKeys[0]][0];
                }
                else {
                    throw new Error("The queue is empty");
                }
            };
            PriorityQueue.prototype.hasItems = function () {
                return this._sortedKeys.length > 0;
            };
            PriorityQueue.prototype.dequeue = function () {
                if (this.hasItems()) {
                    return this.dequeueFromHighPriorityQueue();
                }
                else {
                    throw new Error("The queue is empty");
                }
            };
            PriorityQueue.prototype.dequeueFromHighPriorityQueue = function () {
                var firstKey = this._sortedKeys[0];
                var nextItem = this._subQueues[firstKey].shift();
                if (this._subQueues[firstKey].length === 0) {
                    this._sortedKeys.shift();
                    delete this._subQueues[firstKey];
                }
                return nextItem;
            };
            return PriorityQueue;
        }());
        threading.PriorityQueue = PriorityQueue;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
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
            GAStore.save = function () {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot save.");
                    return;
                }
                localStorage.setItem(GAStore.KeyPrefix + GAStore.EventsStoreKey, JSON.stringify(GAStore.instance.eventsStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.SessionsStoreKey, JSON.stringify(GAStore.instance.sessionsStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.ProgressionStoreKey, JSON.stringify(GAStore.instance.progressionStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.ItemsStoreKey, JSON.stringify(GAStore.instance.storeItems));
            };
            GAStore.load = function () {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot load.");
                    return;
                }
                try {
                    GAStore.instance.eventsStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.EventsStoreKey));
                    if (!GAStore.instance.eventsStore) {
                        GAStore.instance.eventsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'events' store. Using empty store.");
                    GAStore.instance.eventsStore = [];
                }
                try {
                    GAStore.instance.sessionsStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.SessionsStoreKey));
                    if (!GAStore.instance.sessionsStore) {
                        GAStore.instance.sessionsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'sessions' store. Using empty store.");
                    GAStore.instance.sessionsStore = [];
                }
                try {
                    GAStore.instance.progressionStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.ProgressionStoreKey));
                    if (!GAStore.instance.progressionStore) {
                        GAStore.instance.progressionStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'progression' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
                try {
                    GAStore.instance.storeItems = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.ItemsStoreKey));
                    if (!GAStore.instance.storeItems) {
                        GAStore.instance.storeItems = {};
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'items' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
            };
            GAStore.setItem = function (key, value) {
                var keyWithPrefix = GAStore.KeyPrefix + key;
                if (!value) {
                    if (keyWithPrefix in GAStore.instance.storeItems) {
                        delete GAStore.instance.storeItems[keyWithPrefix];
                    }
                }
                else {
                    GAStore.instance.storeItems[keyWithPrefix] = value;
                }
            };
            GAStore.getItem = function (key) {
                var keyWithPrefix = GAStore.KeyPrefix + key;
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
            GAStore.KeyPrefix = "GA::";
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
                this.availableResourceCurrencies = [];
                this.availableResourceItemTypes = [];
                this.configurations = {};
                this.commandCenterListeners = [];
                this.sdkConfigDefault = {};
                this.sdkConfig = {};
                this.progressionTries = {};
                this._isEventSubmissionEnabled = true;
            }
            GAState.setUserId = function (userId) {
                GAState.instance.userId = userId;
                GAState.cacheIdentifier();
            };
            GAState.getIdentifier = function () {
                return GAState.instance.identifier;
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
                GAStore.setItem(GAState.Dimension01Key, dimension);
                GALogger.i("Set custom01 dimension value: " + dimension);
            };
            GAState.setCustomDimension02 = function (dimension) {
                GAState.instance.currentCustomDimension02 = dimension;
                GAStore.setItem(GAState.Dimension02Key, dimension);
                GALogger.i("Set custom02 dimension value: " + dimension);
            };
            GAState.setCustomDimension03 = function (dimension) {
                GAState.instance.currentCustomDimension03 = dimension;
                GAStore.setItem(GAState.Dimension03Key, dimension);
                GALogger.i("Set custom03 dimension value: " + dimension);
            };
            GAState.setFacebookId = function (facebookId) {
                GAState.instance.facebookId = facebookId;
                GAStore.setItem(GAState.FacebookIdKey, facebookId);
                GALogger.i("Set facebook id: " + facebookId);
            };
            GAState.setGender = function (gender) {
                GAState.instance.gender = isNaN(Number(gameanalytics.EGAGender[gender])) ? gameanalytics.EGAGender[gender].toString().toLowerCase() : gameanalytics.EGAGender[gameanalytics.EGAGender[gender]].toString().toLowerCase();
                GAStore.setItem(GAState.GenderKey, GAState.instance.gender);
                GALogger.i("Set gender: " + GAState.instance.gender);
            };
            GAState.setBirthYear = function (birthYear) {
                GAState.instance.birthYear = birthYear;
                GAStore.setItem(GAState.BirthYearKey, birthYear.toString());
                GALogger.i("Set birth year: " + birthYear);
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
                annotations["user_id"] = GAState.instance.identifier;
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
                if (GAState.instance.build) {
                    annotations["build"] = GAState.instance.build;
                }
                if (GAState.instance.facebookId) {
                    annotations[GAState.FacebookIdKey] = GAState.instance.facebookId;
                }
                if (GAState.instance.gender) {
                    annotations[GAState.GenderKey] = GAState.instance.gender;
                }
                if (GAState.instance.birthYear != 0) {
                    annotations[GAState.BirthYearKey] = GAState.instance.birthYear;
                }
                return annotations;
            };
            GAState.getSdkErrorEventAnnotations = function () {
                var annotations = {};
                annotations["v"] = 2;
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
                initAnnotations["user_id"] = GAState.getIdentifier();
                initAnnotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                initAnnotations["os_version"] = GADevice.osVersion;
                initAnnotations["platform"] = GADevice.buildPlatform;
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
                    GAStore.load();
                }
                var instance = GAState.instance;
                instance.setDefaultId(GAStore.getItem(GAState.DefaultUserIdKey) != null ? GAStore.getItem(GAState.DefaultUserIdKey) : GAUtilities.createGuid());
                instance.sessionNum = GAStore.getItem(GAState.SessionNumKey) != null ? Number(GAStore.getItem(GAState.SessionNumKey)) : 0.0;
                instance.transactionNum = GAStore.getItem(GAState.TransactionNumKey) != null ? Number(GAStore.getItem(GAState.TransactionNumKey)) : 0.0;
                if (instance.facebookId) {
                    GAStore.setItem(GAState.FacebookIdKey, instance.facebookId);
                }
                else {
                    instance.facebookId = GAStore.getItem(GAState.FacebookIdKey) != null ? GAStore.getItem(GAState.FacebookIdKey) : "";
                    if (instance.facebookId) {
                        GALogger.d("facebookid found in DB: " + instance.facebookId);
                    }
                }
                if (instance.gender) {
                    GAStore.setItem(GAState.GenderKey, instance.gender);
                }
                else {
                    instance.gender = GAStore.getItem(GAState.GenderKey) != null ? GAStore.getItem(GAState.GenderKey) : "";
                    if (instance.gender) {
                        GALogger.d("gender found in DB: " + instance.gender);
                    }
                }
                if (instance.birthYear && instance.birthYear != 0) {
                    GAStore.setItem(GAState.BirthYearKey, instance.birthYear.toString());
                }
                else {
                    instance.birthYear = GAStore.getItem(GAState.BirthYearKey) != null ? Number(GAStore.getItem(GAState.BirthYearKey)) : 0;
                    if (instance.birthYear != 0) {
                        GALogger.d("birthYear found in DB: " + instance.birthYear);
                    }
                }
                if (instance.currentCustomDimension01) {
                    GAStore.setItem(GAState.Dimension01Key, instance.currentCustomDimension01);
                }
                else {
                    instance.currentCustomDimension01 = GAStore.getItem(GAState.Dimension01Key) != null ? GAStore.getItem(GAState.Dimension01Key) : "";
                    if (instance.currentCustomDimension01) {
                        GALogger.d("Dimension01 found in cache: " + instance.currentCustomDimension01);
                    }
                }
                if (instance.currentCustomDimension02) {
                    GAStore.setItem(GAState.Dimension02Key, instance.currentCustomDimension02);
                }
                else {
                    instance.currentCustomDimension02 = GAStore.getItem(GAState.Dimension02Key) != null ? GAStore.getItem(GAState.Dimension02Key) : "";
                    if (instance.currentCustomDimension02) {
                        GALogger.d("Dimension02 found in cache: " + instance.currentCustomDimension02);
                    }
                }
                if (instance.currentCustomDimension03) {
                    GAStore.setItem(GAState.Dimension03Key, instance.currentCustomDimension03);
                }
                else {
                    instance.currentCustomDimension03 = GAStore.getItem(GAState.Dimension03Key) != null ? GAStore.getItem(GAState.Dimension03Key) : "";
                    if (instance.currentCustomDimension03) {
                        GALogger.d("Dimension03 found in cache: " + instance.currentCustomDimension03);
                    }
                }
                var sdkConfigCachedString = GAStore.getItem(GAState.SdkConfigCachedKey) != null ? GAStore.getItem(GAState.SdkConfigCachedKey) : "";
                if (sdkConfigCachedString) {
                    var sdkConfigCached = JSON.parse(GAUtilities.decode64(sdkConfigCachedString));
                    if (sdkConfigCached) {
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
            GAState.validateAndCleanCustomFields = function (fields) {
                var result = {};
                if (fields) {
                    var count = 0;
                    for (var key in fields) {
                        var value = fields[key];
                        if (!key || !value) {
                            GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value +
                                " has been omitted because its key or value is null");
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
                                        GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its value is an empty string or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH + ")");
                                    }
                                }
                                else if (type === "number" || value instanceof Number) {
                                    var valueAsNumber = value;
                                    result[key] = valueAsNumber;
                                    ++count;
                                }
                                else {
                                    GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its value is not a string or number");
                                }
                            }
                            else {
                                GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its key contains illegal character, is empty or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + ")");
                            }
                        }
                        else {
                            GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because it exceeds the max number of custom fields (" + GAState.MAX_CUSTOM_FIELDS_COUNT + ")");
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
            GAState.isCommandCenterReady = function () {
                return GAState.instance.commandCenterIsReady;
            };
            GAState.addCommandCenterListener = function (listener) {
                if (GAState.instance.commandCenterListeners.indexOf(listener) < 0) {
                    GAState.instance.commandCenterListeners.push(listener);
                }
            };
            GAState.removeCommandCenterListener = function (listener) {
                var index = GAState.instance.commandCenterListeners.indexOf(listener);
                if (index > -1) {
                    GAState.instance.commandCenterListeners.splice(index, 1);
                }
            };
            GAState.getConfigurationsContentAsString = function () {
                return JSON.stringify(GAState.instance.configurations);
            };
            GAState.populateConfigurations = function (sdkConfig) {
                var configurations = sdkConfig["configs"];
                if (configurations) {
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
                        }
                    }
                }
                GAState.instance.commandCenterIsReady = true;
                var listeners = GAState.instance.commandCenterListeners;
                for (var i = 0; i < listeners.length; ++i) {
                    if (listeners[i]) {
                        listeners[i].onCommandCenterUpdated();
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
            GAState.FacebookIdKey = "facebook_id";
            GAState.GenderKey = "gender";
            GAState.BirthYearKey = "birth_year";
            GAState.Dimension01Key = "dimension01";
            GAState.Dimension02Key = "dimension02";
            GAState.Dimension03Key = "dimension03";
            GAState.SdkConfigCachedKey = "sdk_config_cached";
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
                if (!SdkErrorTask.countMap[type]) {
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
        var GAHTTPApi = (function () {
            function GAHTTPApi() {
                this.protocol = "https";
                this.hostName = "api.integration.gameanalytics.com";
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
                var url = this.remoteConfigsBaseUrl + "/" + this.initializeUrlPath + "?game_key=" + gameKey + "&interval_seconds=0&configs_hash=" + configsHash;
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
            GAHTTPApi.prototype.sendSdkErrorEvent = function (type) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var gameKey = GAState.getGameKey();
                var secretKey = GAState.getGameSecret();
                if (!GAValidator.validateSdkErrorEvent(gameKey, secretKey, type)) {
                    return;
                }
                var url = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);
                var payloadJSONString = "";
                var json = GAState.getSdkErrorEventAnnotations();
                var typeString = GAHTTPApi.sdkErrorTypeToString(type);
                json["type"] = typeString;
                var eventArray = [];
                eventArray.push(json);
                payloadJSONString = JSON.stringify(eventArray);
                if (!payloadJSONString) {
                    GALogger.w("sendSdkErrorEvent: JSON encoding failed.");
                    return;
                }
                GALogger.d("sendSdkErrorEvent json: " + payloadJSONString);
                SdkErrorTask.execute(url, type, payloadJSONString, secretKey);
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
                request.setRequestHeader("Content-Type", "text/plain");
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
                GALogger.d("init request content : " + body);
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
            GAHTTPApi.sdkErrorTypeToString = function (value) {
                switch (value) {
                    case http.EGASdkErrorType.Rejected:
                        {
                            return "rejected";
                        }
                    default:
                        {
                            return "";
                        }
                }
            };
            GAHTTPApi.instance = new GAHTTPApi();
            return GAHTTPApi;
        }());
        http.GAHTTPApi = GAHTTPApi;
    })(http = gameanalytics.http || (gameanalytics.http = {}));
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
        var EGASdkErrorType = gameanalytics.http.EGASdkErrorType;
        var GAEvents = (function () {
            function GAEvents() {
            }
            GAEvents.addSessionStartEvent = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var eventDict = {};
                eventDict["category"] = GAEvents.CategorySessionStart;
                GAState.incrementSessionNum();
                GAStore.setItem(GAState.SessionNumKey, GAState.getSessionNum().toString());
                GAEvents.addDimensionsToEvent(eventDict);
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
                GAEvents.addEventToStore(eventDict);
                GALogger.i("Add SESSION END event.");
                GAEvents.processEvents("", false);
            };
            GAEvents.addBusinessEvent = function (currency, amount, itemType, itemId, cartType, fields) {
                if (cartType === void 0) { cartType = null; }
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateBusinessEvent(currency, amount, cartType, itemType, itemId)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventDict = {};
                GAState.incrementTransactionNum();
                GAStore.setItem(GAState.TransactionNumKey, GAState.getTransactionNum().toString());
                eventDict["event_id"] = itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryBusiness;
                eventDict["currency"] = currency;
                eventDict["amount"] = amount;
                eventDict[GAState.TransactionNumKey] = GAState.getTransactionNum();
                if (cartType) {
                    eventDict["cart_type"] = cartType;
                }
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addResourceEvent = function (flowType, currency, amount, itemType, itemId, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateResourceEvent(flowType, currency, amount, itemType, itemId, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes())) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
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
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score, sendScore, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var progressionStatusString = GAEvents.progressionStatusToString(progressionStatus);
                if (!GAValidator.validateProgressionEvent(progressionStatus, progression01, progression02, progression03)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
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
                    eventDict["score"] = score;
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
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addDesignEvent = function (eventId, value, sendValue, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateDesignEvent(eventId, value)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryDesign;
                eventData["event_id"] = eventId;
                if (sendValue) {
                    eventData["value"] = value;
                }
                GAEvents.addDimensionsToEvent(eventData);
                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.addErrorEvent = function (severity, message, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var severityString = GAEvents.errorSeverityToString(severity);
                if (!GAValidator.validateErrorEvent(severity, message)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryError;
                eventData["severity"] = severityString;
                eventData["message"] = message;
                GAEvents.addDimensionsToEvent(eventData);
                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add ERROR event: {severity:" + severityString + ", message:" + message + "}");
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
                            payloadArray.push(eventDict);
                        }
                    }
                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e) {
                    GALogger.e("Error during ProcessEvents(): " + e.stack);
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
                        return;
                    }
                    var ev = GAState.getEventAnnotations();
                    var jsonDefaults = GAUtilities.encode64(JSON.stringify(ev));
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
                        values = {};
                        values["session_id"] = ev["session_id"];
                        values["timestamp"] = GAState.getSessionStart();
                        values["event"] = jsonDefaults;
                        GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    }
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save();
                    }
                }
                catch (e) {
                    GALogger.e("addEventToStore: error");
                    GALogger.e(e.stack);
                }
            };
            GAEvents.updateSessionStore = function () {
                if (GAState.sessionIsStarted()) {
                    var values = {};
                    values["session_id"] = GAState.instance.sessionId;
                    values["timestamp"] = GAState.getSessionStart();
                    values["event"] = GAUtilities.encode64(JSON.stringify(GAState.getEventAnnotations()));
                    GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save();
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
            GAEvents.addFieldsToEvent = function (eventData, fields) {
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
            GAEvents.instance = new GAEvents();
            GAEvents.CategorySessionStart = "user";
            GAEvents.CategorySessionEnd = "session_end";
            GAEvents.CategoryDesign = "design";
            GAEvents.CategoryBusiness = "business";
            GAEvents.CategoryProgression = "progression";
            GAEvents.CategoryResource = "resource";
            GAEvents.CategoryError = "error";
            GAEvents.MaxEventCount = 500;
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
                this.blocks = new threading.PriorityQueue({
                    compare: function (x, y) {
                        return x - y;
                    }
                });
                this.id2TimedBlockMap = {};
                GALogger.d("Initializing GA thread...");
                GAThreading.startThread();
            }
            GAThreading.createTimedBlock = function (delayInSeconds) {
                if (delayInSeconds === void 0) { delayInSeconds = 0; }
                var time = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);
                var timedBlock = new threading.TimedBlock(time);
                return timedBlock;
            };
            GAThreading.performTaskOnGAThread = function (taskBlock, delayInSeconds) {
                if (delayInSeconds === void 0) { delayInSeconds = 0; }
                var time = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);
                var timedBlock = new threading.TimedBlock(time);
                timedBlock.block = taskBlock;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            };
            GAThreading.performTimedBlockOnGAThread = function (timedBlock) {
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            };
            GAThreading.scheduleTimer = function (interval, callback) {
                var time = new Date();
                time.setSeconds(time.getSeconds() + interval);
                var timedBlock = new threading.TimedBlock(time);
                timedBlock.block = callback;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
                return timedBlock.id;
            };
            GAThreading.getTimedBlockById = function (blockIdentifier) {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap) {
                    return GAThreading.instance.id2TimedBlockMap[blockIdentifier];
                }
                else {
                    return null;
                }
            };
            GAThreading.ensureEventQueueIsRunning = function () {
                GAThreading.instance.keepRunning = true;
                if (!GAThreading.instance.isRunning) {
                    GAThreading.instance.isRunning = true;
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
            };
            GAThreading.endSessionAndStopQueue = function () {
                if (GAState.isInitialized()) {
                    GALogger.i("Ending session.");
                    GAThreading.stopEventQueue();
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAEvents.addSessionEndEvent();
                        GAState.instance.sessionStart = 0;
                    }
                }
            };
            GAThreading.stopEventQueue = function () {
                GAThreading.instance.keepRunning = false;
            };
            GAThreading.ignoreTimer = function (blockIdentifier) {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap) {
                    GAThreading.instance.id2TimedBlockMap[blockIdentifier].ignore = true;
                }
            };
            GAThreading.setEventProcessInterval = function (interval) {
                if (interval > 0) {
                    GAThreading.ProcessEventsIntervalInSeconds = interval;
                }
            };
            GAThreading.prototype.addTimedBlock = function (timedBlock) {
                this.blocks.enqueue(timedBlock.deadline.getTime(), timedBlock);
            };
            GAThreading.run = function () {
                clearTimeout(GAThreading.runTimeoutId);
                try {
                    var timedBlock;
                    while ((timedBlock = GAThreading.getNextBlock())) {
                        if (!timedBlock.ignore) {
                            if (timedBlock.async) {
                                if (!timedBlock.running) {
                                    timedBlock.running = true;
                                    timedBlock.block();
                                    break;
                                }
                            }
                            else {
                                timedBlock.block();
                            }
                        }
                    }
                    GAThreading.runTimeoutId = setTimeout(GAThreading.run, GAThreading.ThreadWaitTimeInMs);
                    return;
                }
                catch (e) {
                    GALogger.e("Error on GA thread");
                    GALogger.e(e.stack);
                }
                GALogger.d("Ending GA thread");
            };
            GAThreading.startThread = function () {
                GALogger.d("Starting GA thread");
                GAThreading.runTimeoutId = setTimeout(GAThreading.run, 0);
            };
            GAThreading.getNextBlock = function () {
                var now = new Date();
                if (GAThreading.instance.blocks.hasItems() && GAThreading.instance.blocks.peek().deadline.getTime() <= now.getTime()) {
                    if (GAThreading.instance.blocks.peek().async) {
                        if (GAThreading.instance.blocks.peek().running) {
                            return GAThreading.instance.blocks.peek();
                        }
                        else {
                            return GAThreading.instance.blocks.dequeue();
                        }
                    }
                    else {
                        return GAThreading.instance.blocks.dequeue();
                    }
                }
                return null;
            };
            GAThreading.processEventQueue = function () {
                GAEvents.processEvents("", true);
                if (GAThreading.instance.keepRunning) {
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
                else {
                    GAThreading.instance.isRunning = false;
                }
            };
            GAThreading.instance = new GAThreading();
            GAThreading.ThreadWaitTimeInMs = 1000;
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
            GameAnalytics.methodMap['initialize'] = GameAnalytics.initialize;
            GameAnalytics.methodMap['addBusinessEvent'] = GameAnalytics.addBusinessEvent;
            GameAnalytics.methodMap['addResourceEvent'] = GameAnalytics.addResourceEvent;
            GameAnalytics.methodMap['addProgressionEvent'] = GameAnalytics.addProgressionEvent;
            GameAnalytics.methodMap['addDesignEvent'] = GameAnalytics.addDesignEvent;
            GameAnalytics.methodMap['addErrorEvent'] = GameAnalytics.addErrorEvent;
            GameAnalytics.methodMap['addErrorEvent'] = GameAnalytics.addErrorEvent;
            GameAnalytics.methodMap['setEnabledInfoLog'] = GameAnalytics.setEnabledInfoLog;
            GameAnalytics.methodMap['setEnabledVerboseLog'] = GameAnalytics.setEnabledVerboseLog;
            GameAnalytics.methodMap['setEnabledManualSessionHandling'] = GameAnalytics.setEnabledManualSessionHandling;
            GameAnalytics.methodMap['setEnabledEventSubmission'] = GameAnalytics.setEnabledEventSubmission;
            GameAnalytics.methodMap['setCustomDimension01'] = GameAnalytics.setCustomDimension01;
            GameAnalytics.methodMap['setCustomDimension02'] = GameAnalytics.setCustomDimension02;
            GameAnalytics.methodMap['setCustomDimension03'] = GameAnalytics.setCustomDimension03;
            GameAnalytics.methodMap['setFacebookId'] = GameAnalytics.setFacebookId;
            GameAnalytics.methodMap['setGender'] = GameAnalytics.setGender;
            GameAnalytics.methodMap['setBirthYear'] = GameAnalytics.setBirthYear;
            GameAnalytics.methodMap['setEventProcessInterval'] = GameAnalytics.setEventProcessInterval;
            GameAnalytics.methodMap['startSession'] = GameAnalytics.startSession;
            GameAnalytics.methodMap['endSession'] = GameAnalytics.endSession;
            GameAnalytics.methodMap['onStop'] = GameAnalytics.onStop;
            GameAnalytics.methodMap['onResume'] = GameAnalytics.onResume;
            GameAnalytics.methodMap['addCommandCenterListener'] = GameAnalytics.addCommandCenterListener;
            GameAnalytics.methodMap['removeCommandCenterListener'] = GameAnalytics.removeCommandCenterListener;
            GameAnalytics.methodMap['getCommandCenterValueAsString'] = GameAnalytics.getCommandCenterValueAsString;
            GameAnalytics.methodMap['isCommandCenterReady'] = GameAnalytics.isCommandCenterReady;
            GameAnalytics.methodMap['getConfigurationsContentAsString'] = GameAnalytics.getConfigurationsContentAsString;
            if (typeof window !== 'undefined' && typeof window['GameAnalytics'] !== 'undefined' && typeof window['GameAnalytics']['q'] !== 'undefined') {
                var q = window['GameAnalytics']['q'];
                for (var i in q) {
                    GameAnalytics.gaCommand.apply(null, q[i]);
                }
            }
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
        GameAnalytics.initialize = function (gameKey, gameSecret) {
            if (gameKey === void 0) { gameKey = ""; }
            if (gameSecret === void 0) { gameSecret = ""; }
            GADevice.updateConnectionType();
            var timedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = function () {
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
            };
            GAThreading.performTimedBlockOnGAThread(timedBlock);
        };
        GameAnalytics.addBusinessEvent = function (currency, amount, itemType, itemId, cartType) {
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            if (cartType === void 0) { cartType = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                    return;
                }
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, {});
            });
        };
        GameAnalytics.addResourceEvent = function (flowType, currency, amount, itemType, itemId) {
            if (flowType === void 0) { flowType = gameanalytics.EGAResourceFlowType.Undefined; }
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                    return;
                }
                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, {});
            });
        };
        GameAnalytics.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score) {
            if (progressionStatus === void 0) { progressionStatus = gameanalytics.EGAProgressionStatus.Undefined; }
            if (progression01 === void 0) { progression01 = ""; }
            if (progression02 === void 0) { progression02 = ""; }
            if (progression03 === void 0) { progression03 = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                    return;
                }
                var sendScore = typeof score === "number";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, {});
            });
        };
        GameAnalytics.addDesignEvent = function (eventId, value) {
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                    return;
                }
                var sendValue = typeof value === "number";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, {});
            });
        };
        GameAnalytics.addErrorEvent = function (severity, message) {
            if (severity === void 0) { severity = gameanalytics.EGAErrorSeverity.Undefined; }
            if (message === void 0) { message = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                    return;
                }
                GAEvents.addErrorEvent(severity, message, {});
            });
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
        GameAnalytics.setFacebookId = function (facebookId) {
            if (facebookId === void 0) { facebookId = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GAValidator.validateFacebookId(facebookId)) {
                    GAState.setFacebookId(facebookId);
                }
            });
        };
        GameAnalytics.setGender = function (gender) {
            if (gender === void 0) { gender = gameanalytics.EGAGender.Undefined; }
            GAThreading.performTaskOnGAThread(function () {
                if (GAValidator.validateGender(gender)) {
                    GAState.setGender(gender);
                }
            });
        };
        GameAnalytics.setBirthYear = function (birthYear) {
            if (birthYear === void 0) { birthYear = 0; }
            GAThreading.performTaskOnGAThread(function () {
                if (GAValidator.validateBirthyear(birthYear)) {
                    GAState.setBirthYear(birthYear);
                }
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
                var timedBlock = GAThreading.createTimedBlock();
                timedBlock.async = true;
                GameAnalytics.initTimedBlockId = timedBlock.id;
                timedBlock.block = function () {
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAThreading.endSessionAndStopQueue();
                    }
                    GameAnalytics.resumeSessionAndStartQueue();
                };
                GAThreading.performTimedBlockOnGAThread(timedBlock);
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
            var timedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = function () {
                GameAnalytics.resumeSessionAndStartQueue();
            };
            GAThreading.performTimedBlockOnGAThread(timedBlock);
        };
        GameAnalytics.getCommandCenterValueAsString = function (key, defaultValue) {
            if (defaultValue === void 0) { defaultValue = null; }
            return GAState.getConfigurationStringValue(key, defaultValue);
        };
        GameAnalytics.isCommandCenterReady = function () {
            return GAState.isCommandCenterReady();
        };
        GameAnalytics.addCommandCenterListener = function (listener) {
            GAState.addCommandCenterListener(listener);
        };
        GameAnalytics.removeCommandCenterListener = function (listener) {
            GAState.removeCommandCenterListener(listener);
        };
        GameAnalytics.getConfigurationsContentAsString = function () {
            return GAState.getConfigurationsContentAsString();
        };
        GameAnalytics.getABTestingId = function () {
            return GAState.getConfigurationsContentAsString();
        };
        GameAnalytics.internalInitialize = function () {
            GAState.ensurePersistedStates();
            GAStore.setItem(GAState.DefaultUserIdKey, GAState.getDefaultId());
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
                    if (currentSdkConfig["ab_id"]) {
                        initResponseDict["ab_id"] = currentSdkConfig["ab_id"];
                    }
                    if (currentSdkConfig["ab_variant_id"]) {
                        initResponseDict["ab_variant_id"] = currentSdkConfig["ab_variant_id"];
                    }
                }
                GAStore.setItem(GAState.SdkConfigCachedKey, GAUtilities.encode64(JSON.stringify(initResponseDict)));
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
            var timedBlock = GAThreading.getTimedBlockById(GameAnalytics.initTimedBlockId);
            if (timedBlock != null) {
                timedBlock.running = false;
            }
            GameAnalytics.initTimedBlockId = -1;
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
        GameAnalytics.initTimedBlockId = -1;
        GameAnalytics.methodMap = {};
        return GameAnalytics;
    }());
    gameanalytics.GameAnalytics = GameAnalytics;
})(gameanalytics || (gameanalytics = {}));
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy90aHJlYWRpbmcvVGltZWRCbG9jay50cyIsInNyYy90aHJlYWRpbmcvUHJpb3JpdHlRdWV1ZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2V2ZW50cy9HQUV2ZW50cy50cyIsInNyYy90aHJlYWRpbmcvR0FUaHJlYWRpbmcudHMiLCJzcmMvR2FtZUFuYWx5dGljcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFPLGFBQWEsQ0EyRG5CO0FBM0RELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQVFYO0lBUkQsV0FBWSxnQkFBZ0I7UUFFeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFSVyxnQkFBZ0IsR0FBaEIsOEJBQWdCLEtBQWhCLDhCQUFnQixRQVEzQjtJQUVELElBQVksU0FLWDtJQUxELFdBQVksU0FBUztRQUVqQixtREFBYSxDQUFBO1FBQ2IseUNBQVEsQ0FBQTtRQUNSLDZDQUFVLENBQUE7SUFDZCxDQUFDLEVBTFcsU0FBUyxHQUFULHVCQUFTLEtBQVQsdUJBQVMsUUFLcEI7SUFFRCxJQUFZLG9CQU1YO0lBTkQsV0FBWSxvQkFBb0I7UUFFNUIseUVBQWEsQ0FBQTtRQUNiLGlFQUFTLENBQUE7UUFDVCx1RUFBWSxDQUFBO1FBQ1osK0RBQVEsQ0FBQTtJQUNaLENBQUMsRUFOVyxvQkFBb0IsR0FBcEIsa0NBQW9C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LENBQUMsQ0FBQyxDQUFDO1FBQzlCLHVCQUFTLEdBQTJDLEVBQUUsQ0FBQztRQTZ1QnpFLG9CQUFDO0tBaHZCRCxBQWd2QkMsSUFBQTtJQWh2QlksMkJBQWEsZ0JBZ3ZCekIsQ0FBQTtBQUNMLENBQUMsRUEvdkJNLGFBQWEsS0FBYixhQUFhLFFBK3ZCbkI7QUFDRCxhQUFhLENBQUMsYUFBYSxDQUFDLElBQUksRUFBRSxDQUFDO0FBQ25DLElBQUksYUFBYSxHQUFHLGFBQWEsQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDIiwiZmlsZSI6ImRpc3QvR2FtZUFuYWx5dGljcy5kZWJ1Zy5qcyIsInNvdXJjZXNDb250ZW50IjpbIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IGVudW0gRUdBRXJyb3JTZXZlcml0eVxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgRGVidWcgPSAxLFxuICAgICAgICBJbmZvID0gMixcbiAgICAgICAgV2FybmluZyA9IDMsXG4gICAgICAgIEVycm9yID0gNCxcbiAgICAgICAgQ3JpdGljYWwgPSA1XG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBR2VuZGVyXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBNYWxlID0gMSxcbiAgICAgICAgRmVtYWxlID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVByb2dyZXNzaW9uU3RhdHVzXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTdGFydCA9IDEsXG4gICAgICAgIENvbXBsZXRlID0gMixcbiAgICAgICAgRmFpbCA9IDNcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU2RrRXJyb3JUeXBlXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBSZWplY3RlZCA9IDFcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBjbGllbnRcbiAgICAgICAgICAgIE5vUmVzcG9uc2UsXG4gICAgICAgICAgICBCYWRSZXNwb25zZSxcbiAgICAgICAgICAgIFJlcXVlc3RUaW1lb3V0LCAvLyA0MDhcbiAgICAgICAgICAgIEpzb25FbmNvZGVGYWlsZWQsXG4gICAgICAgICAgICBKc29uRGVjb2RlRmFpbGVkLFxuICAgICAgICAgICAgLy8gc2VydmVyXG4gICAgICAgICAgICBJbnRlcm5hbFNlcnZlckVycm9yLFxuICAgICAgICAgICAgQmFkUmVxdWVzdCwgLy8gNDAwXG4gICAgICAgICAgICBVbmF1dGhvcml6ZWQsIC8vIDQwMVxuICAgICAgICAgICAgVW5rbm93blJlc3BvbnNlQ29kZSxcbiAgICAgICAgICAgIE9rLFxuICAgICAgICAgICAgQ3JlYXRlZFxuICAgICAgICB9XG4gICAgfVxufVxudmFyIEVHQUVycm9yU2V2ZXJpdHkgPSBnYW1lYW5hbHl0aWNzLkVHQUVycm9yU2V2ZXJpdHk7XG52YXIgRUdBR2VuZGVyID0gZ2FtZWFuYWx5dGljcy5FR0FHZW5kZXI7XG52YXIgRUdBUHJvZ3Jlc3Npb25TdGF0dXMgPSBnYW1lYW5hbHl0aWNzLkVHQVByb2dyZXNzaW9uU3RhdHVzO1xudmFyIEVHQVJlc291cmNlRmxvd1R5cGUgPSBnYW1lYW5hbHl0aWNzLkVHQVJlc291cmNlRmxvd1R5cGU7XG4iLCIvL0dBTE9HR0VSX1NUQVJUXG5tb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xuICAgIHtcbiAgICAgICAgZW51bSBFR0FMb2dnZXJNZXNzYWdlVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBFcnJvciA9IDAsXG4gICAgICAgICAgICBXYXJuaW5nID0gMSxcbiAgICAgICAgICAgIEluZm8gPSAyLFxuICAgICAgICAgICAgRGVidWcgPSAzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FMb2dnZXJcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUxvZ2dlciA9IG5ldyBHQUxvZ2dlcigpO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nVmVyYm9zZUVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGRlYnVnRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xuXG4gICAgICAgICAgICAvLyBGaWVsZHMgYW5kIHByb3BlcnRpZXM6IEVORFxuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kZWJ1Z0VuYWJsZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBTVEFSVFxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluZm9Mb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFZlcmJvc2VMb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiSW5mby9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB3KGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJXYXJuaW5nL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGUoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkVycm9yL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkluZm8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGQoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRGVidWcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh0eXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmc6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlb2YgY29uc29sZS5kZWJ1ZyA9PT0gXCJmdW5jdGlvblwiKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ldGhvZHM6IEVORFxuICAgICAgICB9XG4gICAgfVxufVxuLy9HQUxPR0dFUl9FTkRcbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB1dGlsaXRpZXNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FVdGlsaXRpZXNcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRIbWFjKGtleTpzdHJpbmcsIGRhdGE6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGVuY3J5cHRlZE1lc3NhZ2UgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KGRhdGEsIGtleSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ01hdGNoKHM6c3RyaW5nLCBwYXR0ZXJuOlJlZ0V4cCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighcyB8fCAhcGF0dGVybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF0dGVybi50ZXN0KHMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGpvaW5TdHJpbmdBcnJheSh2OkFycmF5PHN0cmluZz4sIGRlbGltaXRlcjpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwiXCI7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMCwgaWwgPSB2Lmxlbmd0aDsgaSA8IGlsOyBpKyspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoaSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSBkZWxpbWl0ZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IHZbaV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhcnJheTpBcnJheTxzdHJpbmc+LCBzZWFyY2g6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhcnJheS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGFycmF5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJyYXlbc10gPT09IHNlYXJjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBrZXlTdHI6c3RyaW5nID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlucHV0ID0gZW5jb2RlVVJJKGlucHV0KTtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIyID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG5cbiAgICAgICAgICAgICAgICAgICBlbmMxID0gY2hyMSA+PiAyO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSAoKGNocjEgJiAzKSA8PCA0KSB8IChjaHIyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSAoKGNocjIgJiAxNSkgPDwgMikgfCAoY2hyMyA+PiA2KTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gY2hyMyAmIDYzO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGlzTmFOKGNocjIpKVxuICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICBlbmMzID0gZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChpc05hTihjaHIzKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMxKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMyKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMzKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmM0KTtcbiAgICAgICAgICAgICAgICAgICBjaHIxID0gY2hyMiA9IGNocjMgPSAwO1xuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBlbmMyID0gZW5jMyA9IGVuYzQgPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gb3V0cHV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBvdXRwdXQ6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgY2hyMTpudW1iZXIsIGNocjI6bnVtYmVyLCBjaHIzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGVuYzE6bnVtYmVyLCBlbmMyOm51bWJlciwgZW5jMzpudW1iZXIsIGVuYzQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgaSA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyByZW1vdmUgYWxsIGNoYXJhY3RlcnMgdGhhdCBhcmUgbm90IEEtWiwgYS16LCAwLTksICssIC8sIG9yID1cbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0dGVzdCA9IC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZztcbiAgICAgICAgICAgICAgICBpZiAoYmFzZTY0dGVzdC5leGVjKGlucHV0KSkge1xuICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJUaGVyZSB3ZXJlIGludmFsaWQgYmFzZTY0IGNoYXJhY3RlcnMgaW4gdGhlIGlucHV0IHRleHQuIFZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGFyZSBBLVosIGEteiwgMC05LCAnKycsICcvJyxhbmQgJz0nLiBFeHBlY3QgZXJyb3JzIGluIGRlY29kaW5nLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5wdXQgPSBpbnB1dC5yZXBsYWNlKC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZywgXCJcIik7XG5cbiAgICAgICAgICAgICAgICBkb1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jMyA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IChlbmMxIDw8IDIpIHwgKGVuYzIgPj4gNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9ICgoZW5jMiAmIDE1KSA8PCA0KSB8IChlbmMzID4+IDIpO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSAoKGVuYzMgJiAzKSA8PCA2KSB8IGVuYzQ7XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjEpO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzMgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjIpO1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBpZiAoZW5jNCAhPSA2NCkge1xuICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArIFN0cmluZy5mcm9tQ2hhckNvZGUoY2hyMyk7XG4gICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gZGVjb2RlVVJJKG91dHB1dCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdGltZUludGVydmFsU2luY2UxOTcwKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBkYXRlOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBNYXRoLnJvdW5kKGRhdGUuZ2V0VGltZSgpIC8gMTAwMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlR3VpZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItXCIgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItNFwiICsgR0FVdGlsaXRpZXMuczQoKS5zdWJzdHIoMCwzKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzNCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKCgoMStNYXRoLnJhbmRvbSgpKSoweDEwMDAwKXwwKS50b1N0cmluZygxNikuc3Vic3RyaW5nKDEpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHZhbGlkYXRvcnNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FTZGtFcnJvclR5cGU7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVZhbGlkYXRvclxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGNhcnRUeXBlOnN0cmluZywgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbmN5XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGN1cnJlbmN5OiBDYW5ub3QgYmUgKG51bGwpIGFuZCBuZWVkIHRvIGJlIEEtWiwgMyBjaGFyYWN0ZXJzIGFuZCBpbiB0aGUgc3RhbmRhcmQgYXQgb3BlbmV4Y2hhbmdlcmF0ZXMub3JnLiBGYWlsZWQgY3VycmVuY3k6IFwiICsgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGFtb3VudCA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBhbW91bnQuIENhbm5vdCBiZSBsZXNzIHRoYW4gMC4gRmFpbGVkIGFtb3VudDogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY2FydFR5cGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY2FydFR5cGUuIENhbm5vdCBiZSBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBjYXJ0VHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGNoYXJzXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbUlkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZC4gQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGF2YWlsYWJsZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiwgYXZhaWxhYmxlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsb3dUeXBlID09IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gZmxvd1R5cGU6IEludmFsaWQgZmxvdyB0eXBlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUN1cnJlbmNpZXMsIGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGN1cnJlbmN5OiBOb3QgZm91bmQgaW4gbGlzdCBvZiBwcmUtZGVmaW5lZCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcy4gU3RyaW5nOiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIShhbW91bnQgPiAwKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGFtb3VudDogRmxvYXQgYW1vdW50IGNhbm5vdCBiZSAwIG9yIG5lZ2F0aXZlLiBWYWx1ZTogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghaXRlbVR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUl0ZW1UeXBlcywgaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IE5vdCBmb3VuZCBpbiBsaXN0IG9mIHByZS1kZWZpbmVkIGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtVHlwZXMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiBJbnZhbGlkIHByb2dyZXNzaW9uIHN0YXR1cy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBNYWtlIHN1cmUgcHJvZ3Jlc3Npb25zIGFyZSBkZWZpbmVkIGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiAwMyBmb3VuZCBidXQgMDErMDIgYXJlIGludmFsaWQuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHByb2dyZXNzaW9uMDIgJiYgIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAyIGZvdW5kIGJ1dCBub3QgMDEuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDEgKHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAyXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDIsIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgYmUgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDIpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMywgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGRlc2lnbiBldmVudCAtIGV2ZW50SWQ6IENhbm5vdCBiZSAobnVsbCkgb3IgZW1wdHkuIE9ubHkgNSBldmVudCBwYXJ0cyBhbGxvd2VkIHNlcGVyYXRlZCBieSA6LiBFYWNoIHBhcnQgbmVlZCB0byBiZSAzMiBjaGFyYWN0ZXJzIG9yIGxlc3MuIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZGVzaWduIGV2ZW50IC0gZXZlbnRJZDogTm9uIHZhbGlkIGNoYXJhY3RlcnMuIE9ubHkgYWxsb3dlZCBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsdWU6IGFsbG93IDAsIG5lZ2F0aXZlIGFuZCBuaWwgKG5vdCByZXF1aXJlZClcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHNldmVyaXR5ID09IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGVycm9yIGV2ZW50IC0gc2V2ZXJpdHk6IFNldmVyaXR5IHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUxvbmdTdHJpbmcobWVzc2FnZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBtZXNzYWdlOiBNZXNzYWdlIGNhbm5vdCBiZSBhYm92ZSA4MTkyIGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHR5cGUgPT09IEVHQVNka0Vycm9yVHlwZS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogVHlwZSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlS2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVLZXksIC9eW0EtejAtOV17MzJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVTZWNyZXQsIC9eW0EtejAtOV17NDB9JC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFjdXJyZW5jeSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjdXJyZW5jeSwgL15bQS1aXXszfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoZXZlbnRQYXJ0OnN0cmluZywgYWxsb3dOdWxsOmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGFsbG93TnVsbCAmJiAhZXZlbnRQYXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50UGFydC5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGV2ZW50UGFydDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudFBhcnQsIC9eW0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRMZW5ndGgoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bXjpdezEsNjR9KD86OlteOl17MSw2NH0pezAsNH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0oOltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UoaW5pdFJlc3BvbnNlOntba2V5OnN0cmluZ106IGFueX0sIGNvbmZpZ3NDcmVhdGVkOmJvb2xlYW4pOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbWFrZSBzdXJlIHdlIGhhdmUgYSB2YWxpZCBkaWN0XG4gICAgICAgICAgICAgICAgaWYgKGluaXRSZXNwb25zZSA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBubyByZXNwb25zZSBkaWN0aW9uYXJ5LlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRlZERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgc2VydmVyX3RzXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyVHNOdW1iZXI6bnVtYmVyID0gaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyVHNOdW1iZXIgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wic2VydmVyX3RzXCJdID0gc2VydmVyVHNOdW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdmFsdWUgaW4gJ3NlcnZlcl90cycgZmllbGQuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnc2VydmVyX3RzJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoY29uZmlnc0NyZWF0ZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjb25maWdzIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbnM6YW55W10gPSBpbml0UmVzcG9uc2VbXCJjb25maWdzXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImNvbmZpZ3NcIl0gPSBjb25maWd1cmF0aW9ucztcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2NvbmZpZ3MnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJjb25maWdzXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX2lkIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYWJfaWQ6c3RyaW5nID0gaW5pdFJlc3BvbnNlW1wiYWJfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfaWRcIl0gPSBhYl9pZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2FiX2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl9pZFwiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImFiX2lkXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGFiX3ZhcmlhbnRfaWQgZmllbGRcbiAgICAgICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhYl92YXJpYW50X2lkOnN0cmluZyA9IGluaXRSZXNwb25zZVtcImFiX3ZhcmlhbnRfaWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGFiX3ZhcmlhbnRfaWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdhYl92YXJpYW50X2lkJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJhYl92YXJpYW50X2lkXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiYWJfdmFyaWFudF9pZFwiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cblxuICAgICAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZWREaWN0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVpbGQoYnVpbGQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhidWlsZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHdyYXBwZXJWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHdyYXBwZXJWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZCkgWzAtOV17MCw1fShcXC5bMC05XXswLDV9KXswLDJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVuZ2luZVZlcnNpb24oZW5naW5lVmVyc2lvbjpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFlbmdpbmVWZXJzaW9uIHx8ICFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChlbmdpbmVWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZCkgWzAtOV17MCw1fShcXC5bMC05XXswLDV9KXswLDJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVVzZXJJZCh1SWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcodUlkLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gdXNlciBpZDogaWQgY2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTaG9ydFN0cmluZyhzaG9ydFN0cmluZzpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eSBvciBuaWxcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhc2hvcnRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIXNob3J0U3RyaW5nIHx8IHNob3J0U3RyaW5nLmxlbmd0aCA+IDMyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVN0cmluZyhzOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5IG9yIG5pbFxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFzIHx8IHMubGVuZ3RoID4gNjQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlTG9uZ1N0cmluZyhsb25nU3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5XG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIWxvbmdTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIWxvbmdTdHJpbmcgfHwgbG9uZ1N0cmluZy5sZW5ndGggPiA4MTkyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25UeXBlOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goY29ubmVjdGlvblR5cGUsIC9eKHd3YW58d2lmaXxsYW58b2ZmbGluZSkkLyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgMzIsIGZhbHNlLCBcImN1c3RvbSBkaW1lbnNpb25zXCIsIGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgNjQsIGZhbHNlLCBcInJlc291cmNlIGN1cnJlbmNpZXNcIiwgcmVzb3VyY2VDdXJyZW5jaWVzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHN0cmluZyBmb3IgcmVnZXhcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc291cmNlQ3VycmVuY2llcy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2gocmVzb3VyY2VDdXJyZW5jaWVzW2ldLCAvXltBLVphLXpdKyQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInJlc291cmNlIGN1cnJlbmNpZXMgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgcmVzb3VyY2UgY3VycmVuY3kgY2FuIG9ubHkgYmUgQS1aLCBhLXouIFN0cmluZyB3YXM6IFwiICsgcmVzb3VyY2VDdXJyZW5jaWVzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwicmVzb3VyY2UgaXRlbSB0eXBlc1wiLCByZXNvdXJjZUl0ZW1UeXBlcykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCByZXNvdXJjZUl0ZW1UeXBlIGZvciBldmVudHBhcnQgdmFsaWRhdGlvblxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzb3VyY2VJdGVtVHlwZXMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhyZXNvdXJjZUl0ZW1UeXBlc1tpXSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJyZXNvdXJjZSBpdGVtIHR5cGVzIHZhbGlkYXRpb24gZmFpbGVkOiBhIHJlc291cmNlIGl0ZW0gdHlwZSBjYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUl0ZW1UeXBlc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24wMTpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDIoZGltZW5zaW9uMDI6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAzKGRpbWVuc2lvbjAzOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBcnJheU9mU3RyaW5ncyhtYXhDb3VudDpudW1iZXIsIG1heFN0cmluZ0xlbmd0aDpudW1iZXIsIGFsbG93Tm9WYWx1ZXM6Ym9vbGVhbiwgbG9nVGFnOnN0cmluZywgYXJyYXlPZlN0cmluZ3M6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXJyYXlUYWc6c3RyaW5nID0gbG9nVGFnO1xuXG4gICAgICAgICAgICAgICAgLy8gdXNlIGFycmF5VGFnIHRvIGFubm90YXRlIHdhcm5pbmcgbG9nXG4gICAgICAgICAgICAgICAgaWYgKCFhcnJheVRhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFycmF5VGFnID0gXCJBcnJheVwiO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKCFhcnJheU9mU3RyaW5ncylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIG51bGwuIFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGVtcHR5XG4gICAgICAgICAgICAgICAgaWYgKGFsbG93Tm9WYWx1ZXMgPT0gZmFsc2UgJiYgYXJyYXlPZlN0cmluZ3MubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBiZSBlbXB0eS4gXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZXhjZWVkaW5nIG1heCBjb3VudFxuICAgICAgICAgICAgICAgIGlmIChtYXhDb3VudCA+IDAgJiYgYXJyYXlPZlN0cmluZ3MubGVuZ3RoID4gbWF4Q291bnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBleGNlZWQgXCIgKyBtYXhDb3VudCArIFwiIHZhbHVlcy4gSXQgaGFzIFwiICsgYXJyYXlPZlN0cmluZ3MubGVuZ3RoICsgXCIgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBhcnJheU9mU3RyaW5ncy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdHJpbmdMZW5ndGg6bnVtYmVyID0gIWFycmF5T2ZTdHJpbmdzW2ldID8gMCA6IGFycmF5T2ZTdHJpbmdzW2ldLmxlbmd0aDtcbiAgICAgICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHkgKG5vdCBhbGxvd2VkKVxuICAgICAgICAgICAgICAgICAgICBpZiAoc3RyaW5nTGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGNvbnRhaW5lZCBhbiBlbXB0eSBzdHJpbmcuIEFycmF5PVwiICsgSlNPTi5zdHJpbmdpZnkoYXJyYXlPZlN0cmluZ3MpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggbGVuZ3RoXG4gICAgICAgICAgICAgICAgICAgIGlmIChtYXhTdHJpbmdMZW5ndGggPiAwICYmIHN0cmluZ0xlbmd0aCA+IG1heFN0cmluZ0xlbmd0aClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhIHN0cmluZyBleGNlZWRlZCBtYXggYWxsb3dlZCBsZW5ndGggKHdoaWNoIGlzOiBcIiArIG1heFN0cmluZ0xlbmd0aCArIFwiKS4gU3RyaW5nIHdhczogXCIgKyBhcnJheU9mU3RyaW5nc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVGYWNlYm9va0lkKGZhY2Vib29rSWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcoZmFjZWJvb2tJZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGZhY2Vib29rIGlkOiBpZCBjYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUdlbmRlcihnZW5kZXI6YW55KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGlzTmFOKE51bWJlcihFR0FHZW5kZXJbZ2VuZGVyXSkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGdlbmRlciA9PSBFR0FHZW5kZXIuVW5kZWZpbmVkIHx8ICEoZ2VuZGVyID09IEVHQUdlbmRlci5NYWxlIHx8IGdlbmRlciA9PSBFR0FHZW5kZXIuRmVtYWxlKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGdlbmRlcjogSGFzIHRvIGJlICdtYWxlJyBvciAnZmVtYWxlJy4gV2FzOiBcIiArIGdlbmRlcik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGdlbmRlciA9PSBFR0FHZW5kZXJbRUdBR2VuZGVyLlVuZGVmaW5lZF0gfHwgIShnZW5kZXIgPT0gRUdBR2VuZGVyW0VHQUdlbmRlci5NYWxlXSB8fCBnZW5kZXIgPT0gRUdBR2VuZGVyW0VHQUdlbmRlci5GZW1hbGVdKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGdlbmRlcjogSGFzIHRvIGJlICdtYWxlJyBvciAnZmVtYWxlJy4gV2FzOiBcIiArIGdlbmRlcik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCaXJ0aHllYXIoYmlydGhZZWFyOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmlydGhZZWFyIDwgMCB8fCBiaXJ0aFllYXIgPiA5OTk5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJpcnRoWWVhcjogQ2Fubm90IGJlIChudWxsKSBvciBpbnZhbGlkIHJhbmdlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoY2xpZW50VHMgPCAoLTQyOTQ5NjcyOTUrMSkgfHwgY2xpZW50VHMgPiAoNDI5NDk2NzI5NS0xKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgZGV2aWNlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIE5hbWVWYWx1ZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZhbHVlOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKG5hbWU6c3RyaW5nLCB2YWx1ZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQURldmljZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBzZGtXcmFwcGVyVmVyc2lvbjpzdHJpbmcgPSBcImphdmFzY3JpcHQgMy4xLjJcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IG9zVmVyc2lvblBhaXI6TmFtZVZlcnNpb24gPSBHQURldmljZS5tYXRjaEl0ZW0oW1xuICAgICAgICAgICAgICAgIG5hdmlnYXRvci5wbGF0Zm9ybSxcbiAgICAgICAgICAgICAgICBuYXZpZ2F0b3IudXNlckFnZW50LFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci5hcHBWZXJzaW9uLFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci52ZW5kb3JcbiAgICAgICAgICAgIF0uam9pbignICcpLCBbXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzX3Bob25lXCIsIFwiV2luZG93cyBQaG9uZVwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwid2luZG93c1wiLCBcIldpblwiLCBcIk5UXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBob25lXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGFkXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUG9kXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJhbmRyb2lkXCIsIFwiQW5kcm9pZFwiLCBcIkFuZHJvaWRcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJibGFja0JlcnJ5XCIsIFwiQmxhY2tCZXJyeVwiLCBcIi9cIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJtYWNfb3N4XCIsIFwiTWFjXCIsIFwiT1MgWFwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcInRpemVuXCIsIFwiVGl6ZW5cIiwgXCJUaXplblwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImxpbnV4XCIsIFwiTGludXhcIiwgXCJydlwiKVxuICAgICAgICAgICAgXSk7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgYnVpbGRQbGF0Zm9ybTpzdHJpbmcgPSBHQURldmljZS5ydW50aW1lUGxhdGZvcm1Ub1N0cmluZygpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBkZXZpY2VNb2RlbDpzdHJpbmcgPSBHQURldmljZS5nZXREZXZpY2VNb2RlbCgpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBkZXZpY2VNYW51ZmFjdHVyZXI6c3RyaW5nID0gR0FEZXZpY2UuZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IG9zVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRPU1ZlcnNpb25TdHJpbmcoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgYnJvd3NlclZlcnNpb246c3RyaW5nID0gR0FEZXZpY2UuZ2V0QnJvd3NlclZlcnNpb25TdHJpbmcoKTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdhbWVFbmdpbmVWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNvbm5lY3Rpb25UeXBlOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1heFNhZmVJbnRlZ2VyOm51bWJlciA9IE1hdGgucG93KDIsIDUzKSAtIDE7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdG91Y2goKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbGV2YW50U2RrVmVyc2lvbigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5zZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka1dyYXBwZXJWZXJzaW9uO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbm5lY3Rpb25UeXBlKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5jb25uZWN0aW9uVHlwZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGVDb25uZWN0aW9uVHlwZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYobmF2aWdhdG9yLm9uTGluZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiaW9zXCIgfHwgR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSA9PT0gXCJhbmRyb2lkXCIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gXCJ3d2FuXCI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwibGFuXCI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLy8gVE9ETzogRGV0ZWN0IHdpZmkgdXNhZ2VcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcIm9mZmxpbmVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldE9TVmVyc2lvblN0cmluZygpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSArIFwiIFwiICsgR0FEZXZpY2Uub3NWZXJzaW9uUGFpci52ZXJzaW9uO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBydW50aW1lUGxhdGZvcm1Ub1N0cmluZygpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uub3NWZXJzaW9uUGFpci5uYW1lO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRCcm93c2VyVmVyc2lvblN0cmluZygpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdWE6c3RyaW5nID0gbmF2aWdhdG9yLnVzZXJBZ2VudDtcbiAgICAgICAgICAgICAgICB2YXIgdGVtOlJlZ0V4cE1hdGNoQXJyYXk7XG4gICAgICAgICAgICAgICAgdmFyIE06UmVnRXhwTWF0Y2hBcnJheSA9IHVhLm1hdGNoKC8ob3BlcmF8Y2hyb21lfHNhZmFyaXxmaXJlZm94fHVicm93c2VyfG1zaWV8dHJpZGVudHxmYmF2KD89XFwvKSlcXC8/XFxzKihcXGQrKS9pKSB8fCBbXTtcblxuICAgICAgICAgICAgICAgIGlmKE0ubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQURldmljZS5idWlsZFBsYXRmb3JtID09PSBcImlvc1wiKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3ZWJraXRfXCIgKyBHQURldmljZS5vc1ZlcnNpb247XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZigvdHJpZGVudC9pLnRlc3QoTVsxXSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0ZW0gPSAvXFxicnZbIDpdKyhcXGQrKS9nLmV4ZWModWEpIHx8IFtdO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gJ0lFICcgKyAodGVtWzFdIHx8ICcnKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihNWzFdID09PSAnQ2hyb21lJylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IHVhLm1hdGNoKC9cXGIoT1BSfEVkZ2V8VUJyb3dzZXIpXFwvKFxcZCspLyk7XG4gICAgICAgICAgICAgICAgICAgIGlmKHRlbSE9IG51bGwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0ZW0uc2xpY2UoMSkuam9pbignICcpLnJlcGxhY2UoJ09QUicsICdPcGVyYScpLnJlcGxhY2UoJ1VCcm93c2VyJywgJ1VDJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0gJiYgTVsxXS50b0xvd2VyQ2FzZSgpID09PSAnZmJhdicpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBNWzFdID0gXCJmYWNlYm9va1wiO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKE1bMl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImZhY2Vib29rIFwiICsgTVsyXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBNU3RyaW5nOnN0cmluZ1tdID0gTVsyXT8gW01bMV0sIE1bMl1dOiBbbmF2aWdhdG9yLmFwcE5hbWUsIG5hdmlnYXRvci5hcHBWZXJzaW9uLCAnLT8nXTtcblxuICAgICAgICAgICAgICAgIGlmKCh0ZW0gPSB1YS5tYXRjaCgvdmVyc2lvblxcLyhcXGQrKS9pKSkgIT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIE1TdHJpbmcuc3BsaWNlKDEsIDEsIHRlbVsxXSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIE1TdHJpbmcuam9pbignICcpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldERldmljZU1vZGVsKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcInVua25vd25cIjtcblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldERldmljZU1hbnVmYWN0dXJlcigpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6c3RyaW5nID0gXCJ1bmtub3duXCI7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBtYXRjaEl0ZW0oYWdlbnQ6c3RyaW5nLCBkYXRhOkFycmF5PE5hbWVWYWx1ZVZlcnNpb24+KTpOYW1lVmVyc2lvblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6TmFtZVZlcnNpb24gPSBuZXcgTmFtZVZlcnNpb24oXCJ1bmtub3duXCIsIFwiMC4wLjBcIik7XG5cbiAgICAgICAgICAgICAgICB2YXIgaTpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBqOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIHJlZ2V4OlJlZ0V4cDtcbiAgICAgICAgICAgICAgICB2YXIgcmVnZXh2OlJlZ0V4cDtcbiAgICAgICAgICAgICAgICB2YXIgbWF0Y2g6Ym9vbGVhbjtcbiAgICAgICAgICAgICAgICB2YXIgbWF0Y2hlczpSZWdFeHBNYXRjaEFycmF5O1xuICAgICAgICAgICAgICAgIHZhciBtYXRoY2VzUmVzdWx0OnN0cmluZztcbiAgICAgICAgICAgICAgICB2YXIgdmVyc2lvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGkgPSAwOyBpIDwgZGF0YS5sZW5ndGg7IGkgKz0gMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlZ2V4ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZhbHVlLCAnaScpO1xuICAgICAgICAgICAgICAgICAgICBtYXRjaCA9IHJlZ2V4LnRlc3QoYWdlbnQpO1xuICAgICAgICAgICAgICAgICAgICBpZiAobWF0Y2gpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlZ2V4diA9IG5ldyBSZWdFeHAoZGF0YVtpXS52ZXJzaW9uICsgJ1stIC86O10oW1xcXFxkLl9dKyknLCAnaScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgbWF0Y2hlcyA9IGFnZW50Lm1hdGNoKHJlZ2V4dik7XG4gICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJyc7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0Y2hlcylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0Y2hlc1sxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hdGhjZXNSZXN1bHQgPSBtYXRjaGVzWzFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRoY2VzUmVzdWx0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBtYXRjaGVzQXJyYXk6c3RyaW5nW10gPSBtYXRoY2VzUmVzdWx0LnNwbGl0KC9bLl9dKy8pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoaiA9IDA7IGogPCBNYXRoLm1pbihtYXRjaGVzQXJyYXkubGVuZ3RoLCAzKTsgaiArPSAxKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyc2lvbiArPSBtYXRjaGVzQXJyYXlbal0gKyAoaiA8IE1hdGgubWluKG1hdGNoZXNBcnJheS5sZW5ndGgsIDMpIC0gMSA/ICcuJyA6ICcnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyc2lvbiA9ICcwLjAuMCc7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5uYW1lID0gZGF0YVtpXS5uYW1lO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnZlcnNpb24gPSB2ZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgwqDCoMKgwqDCoMKgwqDCoH1cbiAgICAgICAgICAgIMKgwqDCoMKgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0aHJlYWRpbmdcbiAgICB7XG4gICAgICAgIGV4cG9ydCBjbGFzcyBUaW1lZEJsb2NrXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBkZWFkbGluZTpEYXRlO1xuICAgICAgICAgICAgcHVibGljIGJsb2NrOigpID0+IHZvaWQ7XG4gICAgICAgICAgICBwdWJsaWMgcmVhZG9ubHkgaWQ6bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIGlnbm9yZTpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIGFzeW5jOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgcnVubmluZzpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaWRDb3VudGVyOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihkZWFkbGluZTpEYXRlKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuZGVhZGxpbmUgPSBkZWFkbGluZTtcbiAgICAgICAgICAgICAgICB0aGlzLmlnbm9yZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHRoaXMuYXN5bmMgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICB0aGlzLnJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICB0aGlzLmlkID0gKytUaW1lZEJsb2NrLmlkQ291bnRlcjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0aHJlYWRpbmdcbiAgICB7XG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgSUNvbXBhcmVyPFQ+XG4gICAgICAgIHtcbiAgICAgICAgICAgIGNvbXBhcmUoeDpULCB5OlQpOiBudW1iZXI7XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgUHJpb3JpdHlRdWV1ZTxUSXRlbT5cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIF9zdWJRdWV1ZXM6e1trZXk6bnVtYmVyXTogQXJyYXk8VEl0ZW0+fTtcbiAgICAgICAgICAgIHB1YmxpYyBfc29ydGVkS2V5czpBcnJheTxudW1iZXI+O1xuICAgICAgICAgICAgcHJpdmF0ZSBjb21wYXJlcjpJQ29tcGFyZXI8bnVtYmVyPjtcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKHByaW9yaXR5Q29tcGFyZXI6SUNvbXBhcmVyPG51bWJlcj4pXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5jb21wYXJlciA9IHByaW9yaXR5Q29tcGFyZXI7XG4gICAgICAgICAgICAgICAgdGhpcy5fc3ViUXVldWVzID0ge307XG4gICAgICAgICAgICAgICAgdGhpcy5fc29ydGVkS2V5cyA9IFtdO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZW5xdWV1ZShwcmlvcml0eTpudW1iZXIsIGl0ZW06VEl0ZW0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5fc29ydGVkS2V5cy5pbmRleE9mKHByaW9yaXR5KSA9PT0gLTEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLmFkZFF1ZXVlT2ZQcmlvcml0eShwcmlvcml0eSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdGhpcy5fc3ViUXVldWVzW3ByaW9yaXR5XS5wdXNoKGl0ZW0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGFkZFF1ZXVlT2ZQcmlvcml0eShwcmlvcml0eTpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5fc29ydGVkS2V5cy5wdXNoKHByaW9yaXR5KTtcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnNvcnQoKHg6bnVtYmVyLCB5Om51bWJlcikgPT4gdGhpcy5jb21wYXJlci5jb21wYXJlKHgsIHkpKTtcbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXNbcHJpb3JpdHldID0gW107XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBwZWVrKCk6IFRJdGVtXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5oYXNJdGVtcygpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3N1YlF1ZXVlc1t0aGlzLl9zb3J0ZWRLZXlzWzBdXVswXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVGhlIHF1ZXVlIGlzIGVtcHR5XCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGhhc0l0ZW1zKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5fc29ydGVkS2V5cy5sZW5ndGggPiAwO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgZGVxdWV1ZSgpOiBUSXRlbVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHRoaXMuaGFzSXRlbXMoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmRlcXVldWVGcm9tSGlnaFByaW9yaXR5UXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVGhlIHF1ZXVlIGlzIGVtcHR5XCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBkZXF1ZXVlRnJvbUhpZ2hQcmlvcml0eVF1ZXVlKCk6IFRJdGVtXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGZpcnN0S2V5Om51bWJlciA9IHRoaXMuX3NvcnRlZEtleXNbMF07XG4gICAgICAgICAgICAgICAgdmFyIG5leHRJdGVtOlRJdGVtID0gdGhpcy5fc3ViUXVldWVzW2ZpcnN0S2V5XS5zaGlmdCgpO1xuICAgICAgICAgICAgICAgIGlmKHRoaXMuX3N1YlF1ZXVlc1tmaXJzdEtleV0ubGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fc29ydGVkS2V5cy5zaGlmdCgpO1xuICAgICAgICAgICAgICAgICAgICBkZWxldGUgdGhpcy5fc3ViUXVldWVzW2ZpcnN0S2V5XTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gbmV4dEl0ZW07XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmVcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTdG9yZUFyZ3NPcGVyYXRvclxuICAgICAgICB7XG4gICAgICAgICAgICBFcXVhbCxcbiAgICAgICAgICAgIExlc3NPckVxdWFsLFxuICAgICAgICAgICAgTm90RXF1YWxcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVN0b3JlXG4gICAgICAgIHtcbiAgICAgICAgICAgIEV2ZW50cyA9IDAsXG4gICAgICAgICAgICBTZXNzaW9ucyA9IDEsXG4gICAgICAgICAgICBQcm9ncmVzc2lvbiA9IDJcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVN0b3JlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBU3RvcmUgPSBuZXcgR0FTdG9yZSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RvcmFnZUF2YWlsYWJsZTpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4TnVtYmVyT2ZFbnRyaWVzOm51bWJlciA9IDIwMDA7XG4gICAgICAgICAgICBwcml2YXRlIGV2ZW50c1N0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHNlc3Npb25zU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25TdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdG9yZUl0ZW1zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEtleVByZWZpeDpzdHJpbmcgPSBcIkdBOjpcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEV2ZW50c1N0b3JlS2V5OnN0cmluZyA9IFwiZ2FfZXZlbnRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFNlc3Npb25zU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9zZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBQcm9ncmVzc2lvblN0b3JlS2V5OnN0cmluZyA9IFwiZ2FfcHJvZ3Jlc3Npb25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEl0ZW1zU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9pdGVtc1wiO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgbG9jYWxTdG9yYWdlID09PSAnb2JqZWN0JylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Rlc3RpbmdMb2NhbFN0b3JhZ2UnLCAneWVzJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU3RvcmFnZSBpcyBhdmFpbGFibGU/OiBcIiArIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNTdG9yYWdlQXZhaWxhYmxlKCk6Ym9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNTdG9yZVRvb0xhcmdlRm9yRXZlbnRzKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZS5sZW5ndGggKyBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUubGVuZ3RoID4gR0FTdG9yZS5NYXhOdW1iZXJPZkVudHJpZXM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2VsZWN0KHN0b3JlOkVHQVN0b3JlLCBhcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldPiA9IFtdLCBzb3J0OmJvb2xlYW4gPSBmYWxzZSwgbWF4Q291bnQ6bnVtYmVyID0gMCk6IEFycmF5PHtba2V5OnN0cmluZ106IGFueX0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgYWRkOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgYXJncy5sZW5ndGg7ICsrailcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3NFbnRyeTpbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XSA9IGFyZ3Nbal07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWFkZClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGFkZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnB1c2goZW50cnkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoc29ydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdC5zb3J0KChhOntba2V5OnN0cmluZ106IGFueX0sIGI6e1trZXk6c3RyaW5nXTogYW55fSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChhW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcikgLSAoYltcImNsaWVudF90c1wiXSBhcyBudW1iZXIpXG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKG1heENvdW50ID4gMCAmJiByZXN1bHQubGVuZ3RoID4gbWF4Q291bnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXN1bHQgPSByZXN1bHQuc2xpY2UoMCwgbWF4Q291bnQgKyAxKVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdXBkYXRlKHN0b3JlOkVHQVN0b3JlLCBzZXRBcmdzOkFycmF5PFtzdHJpbmcsIGFueV0+LCB3aGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZTpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IHdoZXJlQXJncy5sZW5ndGg7ICsrailcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3NFbnRyeTpbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XSA9IHdoZXJlQXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighdXBkYXRlKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYodXBkYXRlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgc2V0QXJncy5sZW5ndGg7ICsrailcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc2V0QXJnc0VudHJ5OltzdHJpbmcsIGFueV0gPSBzZXRBcmdzW2pdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudHJ5W3NldEFyZ3NFbnRyeVswXV0gPSBzZXRBcmdzRW50cnlbMV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkZWxldGUoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBkZWw6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBhcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighZGVsKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZGVsKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUuc3BsaWNlKGksIDEpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLS1pO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluc2VydChzdG9yZTpFR0FTdG9yZSwgbmV3RW50cnk6e1trZXk6c3RyaW5nXTogYW55fSwgcmVwbGFjZTpib29sZWFuID0gZmFsc2UsIHJlcGxhY2VLZXk6c3RyaW5nID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHJlcGxhY2UpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZighcmVwbGFjZUtleSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcGxhY2VkOmJvb2xlYW4gPSBmYWxzZTtcblxuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbcmVwbGFjZUtleV0gPT0gbmV3RW50cnlbcmVwbGFjZUtleV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIG5ld0VudHJ5KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc10gPSBuZXdFbnRyeVtzXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVwbGFjZWQgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIXJlcGxhY2VkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnB1c2gobmV3RW50cnkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzYXZlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTdG9yYWdlIGlzIG5vdCBhdmFpbGFibGUsIGNhbm5vdCBzYXZlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5FdmVudHNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSkpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuUHJvZ3Jlc3Npb25TdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkl0ZW1zU3RvcmVLZXksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcykpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGxvYWQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlN0b3JhZ2UgaXMgbm90IGF2YWlsYWJsZSwgY2Fubm90IGxvYWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuRXZlbnRzU3RvcmVLZXkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdldmVudHMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlNlc3Npb25zU3RvcmVLZXkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnc2Vzc2lvbnMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuUHJvZ3Jlc3Npb25TdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdwcm9ncmVzc2lvbicgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5JdGVtc1N0b3JlS2V5KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0ge307XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2l0ZW1zJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0SXRlbShrZXk6c3RyaW5nLCB2YWx1ZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGtleVdpdGhQcmVmaXg6c3RyaW5nID0gR0FTdG9yZS5LZXlQcmVmaXggKyBrZXk7XG5cbiAgICAgICAgICAgICAgICBpZighdmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SXRlbShrZXk6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGtleVdpdGhQcmVmaXg6c3RyaW5nID0gR0FTdG9yZS5LZXlQcmVmaXggKyBrZXk7XG4gICAgICAgICAgICAgICAgaWYoa2V5V2l0aFByZWZpeCBpbiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdIGFzIHN0cmluZztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRTdG9yZShzdG9yZTpFR0FTdG9yZSk6IEFycmF5PHtba2V5OnN0cmluZ106IGFueX0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgc3dpdGNoKHN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5FdmVudHM6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5TZXNzaW9uczpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuUHJvZ3Jlc3Npb246XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiR0FTdG9yZS5nZXRTdG9yZSgpOiBDYW5ub3QgZmluZCBzdG9yZTogXCIgKyBzdG9yZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdGF0ZVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEdBRGV2aWNlID0gZ2FtZWFuYWx5dGljcy5kZXZpY2UuR0FEZXZpY2U7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RhdGVcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZGtFcnJvcjpzdHJpbmcgPSBcInNka19lcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQ6bnVtYmVyID0gNTA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIOm51bWJlciA9IDY0O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSDpudW1iZXIgPSAyNTY7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdGF0ZSA9IG5ldyBHQVN0YXRlKCk7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCA9IHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgdXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0VXNlcklkKHVzZXJJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQgPSB1c2VySWQ7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBpZGVudGlmaWVyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SWRlbnRpZmllcigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzSW5pdGlhbGl6ZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbml0aWFsaXplZCh2YWx1ZTpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25TdGFydDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25TdGFydCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB0cmFuc2FjdGlvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFRyYW5zYWN0aW9uTnVtKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvbklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbklkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAzOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lS2V5OnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZUtleSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVTZWNyZXQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lU2VjcmV0KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMzpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGJ1aWxkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QnVpbGQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEJ1aWxkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBidWlsZCB2ZXJzaW9uOiBcIiArIHZhbHVlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLl9pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZmFjZWJvb2tJZDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGdlbmRlcjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGJpcnRoWWVhcjpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnQ2FjaGVkOntba2V5OnN0cmluZ106IGFueX07XG4gICAgICAgICAgICBwcml2YXRlIGNvbmZpZ3VyYXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgY29tbWFuZENlbnRlcklzUmVhZHk6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgY29tbWFuZENlbnRlckxpc3RlbmVyczpBcnJheTx7IG9uQ29tbWFuZENlbnRlclVwZGF0ZWQ6KCkgPT4gdm9pZCB9PiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIGluaXRBdXRob3JpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgY2xpZW50U2VydmVyVGltZU9mZnNldDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgY29uZmlnc0hhc2g6c3RyaW5nO1xuXG4gICAgICAgICAgICBwcml2YXRlIGFiSWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hYklkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHJpdmF0ZSBhYlZhcmlhbnRJZDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ1ZhcmlhbnRJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBkZWZhdWx0VXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc2V0RGVmYXVsdElkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlZmF1bHRVc2VySWQgPSAhdmFsdWUgPyBcIlwiIDogdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RGVmYXVsdElkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWdEZWZhdWx0Ontba2V5OnN0cmluZ106IHN0cmluZ30gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNka0NvbmZpZygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmlyc3Q7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGpzb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0ID0ganNvbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihmaXJzdCAmJiBjb3VudCA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZztcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaXJzdDtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3QgPSBqc29uO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnRGVmYXVsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblRyaWVzOntba2V5OnN0cmluZ106IG51bWJlcn0gPSB7fTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgRGVmYXVsdFVzZXJJZEtleTpzdHJpbmcgPSBcImRlZmF1bHRfdXNlcl9pZFwiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZXNzaW9uTnVtS2V5OnN0cmluZyA9IFwic2Vzc2lvbl9udW1cIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVHJhbnNhY3Rpb25OdW1LZXk6c3RyaW5nID0gXCJ0cmFuc2FjdGlvbl9udW1cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEZhY2Vib29rSWRLZXk6c3RyaW5nID0gXCJmYWNlYm9va19pZFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgR2VuZGVyS2V5OnN0cmluZyA9IFwiZ2VuZGVyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBCaXJ0aFllYXJLZXk6c3RyaW5nID0gXCJiaXJ0aF95ZWFyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wMUtleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAxXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wMktleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wM0tleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAzXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFNka0NvbmZpZ0NhY2hlZEtleTpzdHJpbmcgPSBcInNka19jb25maWdfY2FjaGVkXCI7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNFbmFibGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMShkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAxS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMktleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDNLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRGYWNlYm9va0lkKGZhY2Vib29rSWQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZmFjZWJvb2tJZCA9IGZhY2Vib29rSWQ7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRmFjZWJvb2tJZEtleSwgZmFjZWJvb2tJZCk7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBmYWNlYm9vayBpZDogXCIgKyBmYWNlYm9va0lkKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRHZW5kZXIoZ2VuZGVyOkVHQUdlbmRlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdlbmRlciA9IGlzTmFOKE51bWJlcihFR0FHZW5kZXJbZ2VuZGVyXSkpID8gRUdBR2VuZGVyW2dlbmRlcl0udG9TdHJpbmcoKS50b0xvd2VyQ2FzZSgpIDogRUdBR2VuZGVyW0VHQUdlbmRlcltnZW5kZXJdXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuR2VuZGVyS2V5LCBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBnZW5kZXI6IFwiICsgR0FTdGF0ZS5pbnN0YW5jZS5nZW5kZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEJpcnRoWWVhcihiaXJ0aFllYXI6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYmlydGhZZWFyID0gYmlydGhZZWFyO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkJpcnRoWWVhcktleSwgYmlydGhZZWFyLnRvU3RyaW5nKCkpO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYmlydGggeWVhcjogXCIgKyBiaXJ0aFllYXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFNlc3Npb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uTnVtSW50Om51bWJlciA9IEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpICsgMTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW0gPSBzZXNzaW9uTnVtSW50O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJhbnNhY3Rpb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpICsgMTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtID0gdHJhbnNhY3Rpb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRyaWVzOm51bWJlciA9IEdBU3RhdGUuZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbikgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl0gPSB0cmllcztcblxuICAgICAgICAgICAgICAgIC8vIFBlcnNpc3RcbiAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICB2YWx1ZXNbXCJwcm9ncmVzc2lvblwiXSA9IHByb2dyZXNzaW9uO1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInRyaWVzXCJdID0gdHJpZXM7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuUHJvZ3Jlc3Npb24sIHZhbHVlcywgdHJ1ZSwgXCJwcm9ncmVzc2lvblwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihwcm9ncmVzc2lvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBkZWxldGUgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBEZWxldGVcbiAgICAgICAgICAgICAgICB2YXIgcGFybXM6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgcGFybXMucHVzaChbXCJwcm9ncmVzc2lvblwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgcHJvZ3Jlc3Npb25dKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgcGFybXMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEtleXMoZ2FtZUtleTpzdHJpbmcsIGdhbWVTZWNyZXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZUtleSA9IGdhbWVLZXk7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lU2VjcmV0ID0gZ2FtZVNlY3JldDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nID0gZmxhZztcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVXNlIG1hbnVhbCBzZXNzaW9uIGhhbmRsaW5nOiBcIiArIGZsYWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24oZmxhZzpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCA9IGZsYWc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gUkVRVUlSRUQgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ2XCJdID0gMjtcbiAgICAgICAgICAgICAgICAvLyBVc2VyIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBDbGllbnQgVGltZXN0YW1wICh0aGUgYWRqdXN0ZWQgdGltZXN0YW1wKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2xpZW50X3RzXCJdID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSBtYWtlIChoYXJkY29kZWQgdG8gYXBwbGUpXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImRldmljZVwiXSA9IEdBRGV2aWNlLmRldmljZU1vZGVsO1xuICAgICAgICAgICAgICAgIC8vIEJyb3dzZXIgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnJvd3Nlcl92ZXJzaW9uXCJdID0gR0FEZXZpY2UuYnJvd3NlclZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBudW1iZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLlNlc3Npb25OdW1LZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uX3R5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gQ09ORElUSU9OQUwgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwIGJ1aWxkIHZlcnNpb24gKHVzZSBpZiBub3QgbmlsKVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJ1aWxkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBPUFRJT05BTCBjcm9zcy1zZXNzaW9uIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIGZhY2Vib29rIGlkIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbR0FTdGF0ZS5GYWNlYm9va0lkS2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuZmFjZWJvb2tJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gZ2VuZGVyIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkdlbmRlcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gYmlydGhfeWVhciAob3B0aW9uYWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkJpcnRoWWVhcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmJpcnRoWWVhcjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmdldElkZW50aWZpZXIoKTtcblxuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicmFuZG9tX3NhbHRcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcblxuICAgICAgICAgICAgICAgIHJldHVybiBpbml0QW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q2xpZW50VHNBZGp1c3RlZCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyOm51bWJlciA9IGNsaWVudFRzICsgR0FTdGF0ZS5pbnN0YW5jZS5jbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0O1xuXG4gICAgICAgICAgICAgICAgaWYoR0FWYWxpZGF0b3IudmFsaWRhdGVDbGllbnRUcyhjbGllbnRUc0FkanVzdGVkSW50ZWdlcikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2xpZW50VHNBZGp1c3RlZEludGVnZXI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUcztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2Vzc2lvbklzU3RhcnRlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ICE9IDA7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNhY2hlSWRlbnRpZmllcigpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgPSBHQVN0YXRlLmluc3RhbmNlLnVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgPSBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImlkZW50aWZpZXIsIHtjbGVhbjpcIiArIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciArIFwifVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbnN1cmVQZXJzaXN0ZWRTdGF0ZXMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGdldCBhbmQgZXh0cmFjdCBzdG9yZWQgc3RhdGVzXG4gICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUubG9hZCgpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBpbnRvIEdBU3RhdGUgaW5zdGFuY2VcbiAgICAgICAgICAgICAgICB2YXIgaW5zdGFuY2U6R0FTdGF0ZSA9IEdBU3RhdGUuaW5zdGFuY2U7XG5cbiAgICAgICAgICAgICAgICBpbnN0YW5jZS5zZXREZWZhdWx0SWQoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXkpIDogR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpKTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNlc3Npb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5TZXNzaW9uTnVtS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXkpKSA6IDAuMDtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnRyYW5zYWN0aW9uTnVtID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXkpKSA6IDAuMDtcblxuICAgICAgICAgICAgICAgIC8vIHJlc3RvcmUgY3Jvc3Mgc2Vzc2lvbiB1c2VyIHZhbHVlc1xuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmZhY2Vib29rSWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5GYWNlYm9va0lkS2V5LCBpbnN0YW5jZS5mYWNlYm9va0lkKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuZmFjZWJvb2tJZCA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5GYWNlYm9va0lkS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmZhY2Vib29rSWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJmYWNlYm9va2lkIGZvdW5kIGluIERCOiBcIiArIGluc3RhbmNlLmZhY2Vib29rSWQpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZ2VuZGVyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuR2VuZGVyS2V5LCBpbnN0YW5jZS5nZW5kZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5nZW5kZXIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZ2VuZGVyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZ2VuZGVyIGZvdW5kIGluIERCOiBcIiArIGluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5iaXJ0aFllYXIgJiYgaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXksIGluc3RhbmNlLmJpcnRoWWVhci50b1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuYmlydGhZZWFyID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkJpcnRoWWVhcktleSkpIDogMDtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJiaXJ0aFllYXIgZm91bmQgaW4gREI6IFwiICsgaW5zdGFuY2UuYmlydGhZZWFyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHJlc3RvcmUgZGltZW5zaW9uIHNldHRpbmdzXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAxS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDEgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMktleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAyIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDNLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMyBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gZ2V0IGNhY2hlZCBpbml0IGNhbGwgdmFsdWVzXG4gICAgICAgICAgICAgICAgdmFyIHNka0NvbmZpZ0NhY2hlZFN0cmluZzpzdHJpbmcgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICBpZiAoc2RrQ29uZmlnQ2FjaGVkU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gZGVjb2RlIEpTT05cbiAgICAgICAgICAgICAgICAgICAgdmFyIHNka0NvbmZpZ0NhY2hlZCA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2RrQ29uZmlnQ2FjaGVkU3RyaW5nKSk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCA9IHNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmNvbmZpZ3NIYXNoID0gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXSA/IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5hYklkID0gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuYWJWYXJpYW50SWQgPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfdmFyaWFudF9pZFwiXSA/IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0c19nYV9wcm9ncmVzc2lvbjpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLlByb2dyZXNzaW9uKTtcblxuICAgICAgICAgICAgICAgIGlmIChyZXN1bHRzX2dhX3Byb2dyZXNzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXN1bHRzX2dhX3Byb2dyZXNzaW9uLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVzdWx0Ontba2V5OnN0cmluZ106IGFueX0gPSByZXN1bHRzX2dhX3Byb2dyZXNzaW9uW2ldO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJlc3VsdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Jlc3VsdFtcInByb2dyZXNzaW9uXCJdIGFzIHN0cmluZ10gPSByZXN1bHRbXCJ0cmllc1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY2FsY3VsYXRlU2VydmVyVGltZU9mZnNldChzZXJ2ZXJUczpudW1iZXIpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHNlcnZlclRzIC0gY2xpZW50VHM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KToge1tpZDpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDp7W2lkOnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcih2YXIga2V5IGluIGZpZWxkcylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlOmFueSA9IGZpZWxkc1trZXldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZigha2V5IHx8ICF2YWx1ZSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9XCIgKyBrZXkgKyBcIiwgdmFsdWU9XCIgKyB2YWx1ZSArXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCIgaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyBrZXkgb3IgdmFsdWUgaXMgbnVsbFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYoY291bnQgPCBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0NPVU5UKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZWdleCA9IG5ldyBSZWdFeHAoXCJeW2EtekEtWjAtOV9dezEsXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEggKyBcIn0kXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGtleSwgcmVnZXgpKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHR5cGUgPSB0eXBlb2YgdmFsdWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHR5cGUgPT09IFwic3RyaW5nXCIgfHwgdmFsdWUgaW5zdGFuY2VvZiBTdHJpbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZUFzU3RyaW5nOnN0cmluZyA9IHZhbHVlIGFzIHN0cmluZztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodmFsdWVBc1N0cmluZy5sZW5ndGggPD0gR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIICYmIHZhbHVlQXNTdHJpbmcubGVuZ3RoID4gMClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRba2V5XSA9IHZhbHVlQXNTdHJpbmc7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9XCIgKyBrZXkgKyBcIiwgdmFsdWU9XCIgKyB2YWx1ZSArIFwiIGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMgdmFsdWUgaXMgYW4gZW1wdHkgc3RyaW5nIG9yIGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY2hhcmFjdGVycyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX1ZBTFVFX1NUUklOR19MRU5HVEggKyBcIilcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZih0eXBlID09PSBcIm51bWJlclwiIHx8IHZhbHVlIGluc3RhbmNlb2YgTnVtYmVyKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVBc051bWJlcjpudW1iZXIgPSB2YWx1ZSBhcyBudW1iZXI7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFtrZXldID0gdmFsdWVBc051bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9XCIgKyBrZXkgKyBcIiwgdmFsdWU9XCIgKyB2YWx1ZSArIFwiIGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMgdmFsdWUgaXMgbm90IGEgc3RyaW5nIG9yIG51bWJlclwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9XCIgKyBrZXkgKyBcIiwgdmFsdWU9XCIgKyB2YWx1ZSArIFwiIGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMga2V5IGNvbnRhaW5zIGlsbGVnYWwgY2hhcmFjdGVyLCBpcyBlbXB0eSBvciBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGNoYXJhY3RlcnMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIICsgXCIpXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkczogZW50cnkgd2l0aCBrZXk9XCIgKyBrZXkgKyBcIiwgdmFsdWU9XCIgKyB2YWx1ZSArIFwiIGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdCBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGN1c3RvbSBmaWVsZHMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVCArIFwiKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMSBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAxIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDIgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDIoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMiBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAyKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAzIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAzKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDMgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMyhcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29uZmlndXJhdGlvblN0cmluZ1ZhbHVlKGtleTpzdHJpbmcsIGRlZmF1bHRWYWx1ZTpzdHJpbmcpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0udG9TdHJpbmcoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGRlZmF1bHRWYWx1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNDb21tYW5kQ2VudGVyUmVhZHkoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY29tbWFuZENlbnRlcklzUmVhZHk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQ29tbWFuZENlbnRlckxpc3RlbmVyKGxpc3RlbmVyOnsgb25Db21tYW5kQ2VudGVyVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmNvbW1hbmRDZW50ZXJMaXN0ZW5lcnMuaW5kZXhPZihsaXN0ZW5lcikgPCAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVyTGlzdGVuZXJzLnB1c2gobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVDb21tYW5kQ2VudGVyTGlzdGVuZXIobGlzdGVuZXI6eyBvbkNvbW1hbmRDZW50ZXJVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBpbmRleCA9IEdBU3RhdGUuaW5zdGFuY2UuY29tbWFuZENlbnRlckxpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKTtcbiAgICAgICAgICAgICAgICBpZihpbmRleCA+IC0xKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVyTGlzdGVuZXJzLnNwbGljZShpbmRleCwgMSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHBvcHVsYXRlQ29uZmlndXJhdGlvbnMoc2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbnM6YW55W10gPSBzZGtDb25maWdbXCJjb25maWdzXCJdO1xuXG4gICAgICAgICAgICAgICAgaWYoY29uZmlndXJhdGlvbnMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY29uZmlndXJhdGlvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uOntba2V5OnN0cmluZ106IGFueX0gPSBjb25maWd1cmF0aW9uc1tpXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY29uZmlndXJhdGlvbilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIga2V5OnN0cmluZyA9IGNvbmZpZ3VyYXRpb25bXCJrZXlcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlOmFueSA9IGNvbmZpZ3VyYXRpb25bXCJ2YWx1ZVwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdID8gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdIDogTnVtYmVyLk1JTl9WQUxVRTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgZW5kX3RzOm51bWJlciA9IGNvbmZpZ3VyYXRpb25bXCJlbmRfdHNcIl0gPyBjb25maWd1cmF0aW9uW1wiZW5kX3RzXCJdIDogTnVtYmVyLk1BWF9WQUxVRTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihrZXkgJiYgdmFsdWUgJiYgY2xpZW50X3RzX2FkanVzdGVkID4gc3RhcnRfdHMgJiYgY2xpZW50X3RzX2FkanVzdGVkIDwgZW5kX3RzKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJjb25maWd1cmF0aW9uIGFkZGVkOiBcIiArIEpTT04uc3RyaW5naWZ5KGNvbmZpZ3VyYXRpb24pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVySXNSZWFkeSA9IHRydWU7XG5cbiAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXJzOkFycmF5PHsgb25Db21tYW5kQ2VudGVyVXBkYXRlZDooKSA9PiB2b2lkIH0+ID0gR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVyTGlzdGVuZXJzO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGxpc3RlbmVycy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGxpc3RlbmVyc1tpXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGlzdGVuZXJzW2ldLm9uQ29tbWFuZENlbnRlclVwZGF0ZWQoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0YXNrc1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FTZGtFcnJvclR5cGU7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFNka0Vycm9yVGFza1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhDb3VudDpudW1iZXIgPSAxMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGNvdW50TWFwOntba2V5Om51bWJlcl06IG51bWJlcn0gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBleGVjdXRlKHVybDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlLCBwYXlsb2FkRGF0YTpzdHJpbmcsIHNlY3JldEtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIVNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID49IFNka0Vycm9yVGFzay5NYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIGhhc2hIbWFjOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoc2VjcmV0S2V5LCBwYXlsb2FkRGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdDpYTUxIdHRwUmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmKHJlcXVlc3QucmVhZHlTdGF0ZSA9PT0gNClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXJlcXVlc3QucmVzcG9uc2VUZXh0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZGsgZXJyb3IgZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyByZXF1ZXN0LnN0YXR1c1RleHQgKyBcIiwgU3RhdHVzIGNvZGU6IFwiICsgcmVxdWVzdC5zdGF0dXMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5zdGF0dXMgIT0gMjAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJzZGsgZXJyb3IgZmFpbGVkLiByZXNwb25zZSBjb2RlIG5vdCAyMDAuIHN0YXR1cyBjb2RlOiBcIiArIHJlcXVlc3Quc3RhdHVzICsgXCIsIGRlc2NyaXB0aW9uOiBcIiArIHJlcXVlc3Quc3RhdHVzVGV4dCArIFwiLCBib2R5OiBcIiArIHJlcXVlc3QucmVzcG9uc2VUZXh0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdICsgMTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwiYXBwbGljYXRpb24vanNvblwiKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGhhc2hIbWFjKTtcblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5zZW5kKHBheWxvYWREYXRhKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBTZGtFcnJvclRhc2sgPSBnYW1lYW5hbHl0aWNzLnRhc2tzLlNka0Vycm9yVGFzaztcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIVFRQQXBpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm90b2NvbDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGhvc3ROYW1lOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NCYXNlVXJsOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZVVybFBhdGg6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdXNlR3ppcDpib29sZWFuO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBiYXNlIHVybCBzZXR0aW5nc1xuICAgICAgICAgICAgICAgIHRoaXMucHJvdG9jb2wgPSBcImh0dHBzXCI7XG4gICAgICAgICAgICAgICAgdGhpcy5ob3N0TmFtZSA9IFwiYXBpLmludGVncmF0aW9uLmdhbWVhbmFseXRpY3MuY29tXCI7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gXCJ2MlwiO1xuICAgICAgICAgICAgICAgIHRoaXMucmVtb3RlQ29uZmlnc1ZlcnNpb24gPSBcInYxXCI7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYmFzZSB1cmxcbiAgICAgICAgICAgICAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLnByb3RvY29sICsgXCI6Ly9cIiArIHRoaXMuaG9zdE5hbWUgKyBcIi9cIiArIHRoaXMudmVyc2lvbjtcbiAgICAgICAgICAgICAgICB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsID0gdGhpcy5wcm90b2NvbCArIFwiOi8vXCIgKyB0aGlzLmhvc3ROYW1lICsgXCIvcmVtb3RlX2NvbmZpZ3MvXCIgKyB0aGlzLnJlbW90ZUNvbmZpZ3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5pbml0aWFsaXplVXJsUGF0aCA9IFwiaW5pdFwiO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzVXJsUGF0aCA9IFwiZXZlbnRzXCI7XG5cbiAgICAgICAgICAgICAgICB0aGlzLnVzZUd6aXAgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHJlcXVlc3RJbml0KGNvbmZpZ3NIYXNoOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsICsgXCIvXCIgKyB0aGlzLmluaXRpYWxpemVVcmxQYXRoICsgXCI/Z2FtZV9rZXk9XCIgKyBnYW1lS2V5ICsgXCImaW50ZXJ2YWxfc2Vjb25kcz0wJmNvbmZpZ3NfaGFzaD1cIiArIGNvbmZpZ3NIYXNoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdpbml0JyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0QW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0SW5pdEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAvLyBtYWtlIEpTT04gc3RyaW5nIGZyb20gZGF0YVxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGluaXRBbm5vdGF0aW9ucyk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YTpzdHJpbmcgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnNlbmRSZXF1ZXN0KHVybCwgcGF5bG9hZERhdGEsIGV4dHJhQXJncywgdGhpcy51c2VHemlwLCBHQUhUVFBBcGkuaW5pdFJlcXVlc3RDYWxsYmFjaywgY2FsbGJhY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZEV2ZW50c0luQXJyYXkoZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiwgcmVxdWVzdElkOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihldmVudEFycmF5Lmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRFdmVudHNJbkFycmF5IGNhbGxlZCB3aXRoIG1pc3NpbmcgZXZlbnRBcnJheVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnZXZlbnRzJyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBKU09OIGVuY29kaW5nIGZhaWxlZCBvZiBldmVudEFycmF5XCIpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCwgbnVsbCwgcmVxdWVzdElkLCBldmVudEFycmF5Lmxlbmd0aCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGEgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2gocmVxdWVzdElkKTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChldmVudEFycmF5Lmxlbmd0aC50b1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5zZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZW5kU2RrRXJyb3JFdmVudCh0eXBlOkVHQVNka0Vycm9yVHlwZSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2VjcmV0S2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5LCBzZWNyZXRLZXksIHR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmV2ZW50c1VybFBhdGg7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEpTT05TdHJpbmc6c3RyaW5nID0gXCJcIjtcblxuICAgICAgICAgICAgICAgIHZhciBqc29uOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHR5cGVTdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yVHlwZVRvU3RyaW5nKHR5cGUpO1xuICAgICAgICAgICAgICAgIGpzb25bXCJ0eXBlXCJdID0gdHlwZVN0cmluZztcblxuICAgICAgICAgICAgICAgIHZhciBldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICAgICAgZXZlbnRBcnJheS5wdXNoKGpzb24pO1xuICAgICAgICAgICAgICAgIHBheWxvYWRKU09OU3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighcGF5bG9hZEpTT05TdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwic2VuZFNka0Vycm9yRXZlbnQ6IEpTT04gZW5jb2RpbmcgZmFpbGVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kU2RrRXJyb3JFdmVudCBqc29uOiBcIiArIHBheWxvYWRKU09OU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suZXhlY3V0ZSh1cmwsIHR5cGUsIHBheWxvYWRKU09OU3RyaW5nLCBzZWNyZXRLZXkpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrKHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4gPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IGV4dHJhWzBdO1xuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IGV4dHJhWzFdO1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWQ6c3RyaW5nID0gZXh0cmFbMl07XG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50Q291bnQ6bnVtYmVyID0gcGFyc2VJbnQoZXh0cmFbM10pO1xuICAgICAgICAgICAgICAgIHZhciBib2R5OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3BvbnNlQ29kZTpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgYm9keSA9IHJlcXVlc3QucmVzcG9uc2VUZXh0O1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlQ29kZSA9IHJlcXVlc3Quc3RhdHVzO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImV2ZW50cyByZXF1ZXN0IGNvbnRlbnQ6IFwiICsgYm9keSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJFdmVudHNcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBpZiBub3QgMjAwIHJlc3VsdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgZXZlbnRzIENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SnNvbkRpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IGJvZHkgPyBKU09OLnBhcnNlKGJvZHkpIDoge307XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgRXZlbnRzIENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyByZXR1cm4gcmVzcG9uc2VcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCByZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRSZXF1ZXN0KHVybDpzdHJpbmcsIHBheWxvYWREYXRhOnN0cmluZywgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4sIGd6aXA6Ym9vbGVhbiwgY2FsbGJhY2s6KHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4pID0+IHZvaWQsIGNhbGxiYWNrMjoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYXV0aG9yaXphdGlvbiBoYXNoXG4gICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKTtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKGtleSwgcGF5bG9hZERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhdXRob3JpemF0aW9uKTtcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBleHRyYUFyZ3MpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhcmdzLnB1c2goZXh0cmFBcmdzW3NdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0LCB1cmwsIGNhbGxiYWNrMiwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vcGVuKFwiUE9TVFwiLCB1cmwsIHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtVHlwZVwiLCBcInRleHQvcGxhaW5cIik7XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGF1dGhvcml6YXRpb24pO1xuXG4gICAgICAgICAgICAgICAgaWYoZ3ppcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImd6aXAgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgLy9yZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LUVuY29kaW5nXCIsIFwiZ3ppcFwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2VuZChwYXlsb2FkRGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+ID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBleHRyYVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYm9keTpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIGJvZHkgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgICAgICAgICAgICAgIC8vIHByb2Nlc3MgdGhlIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImluaXQgcmVxdWVzdCBjb250ZW50IDogXCIgKyBib2R5KTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SnNvbkRpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IGJvZHkgPyBKU09OLnBhcnNlKGJvZHkpIDoge307XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RSZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlID0gR0FIVFRQQXBpLmluc3RhbmNlLnByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlLCByZXF1ZXN0LnN0YXR1c1RleHQsIGJvZHksIFwiSW5pdFwiKTtcblxuICAgICAgICAgICAgICAgIC8vIGlmIG5vdCAyMDAgcmVzdWx0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdEpzb25EaWN0ID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gSnNvbiBkZWNvZGluZyBmYWlsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByaW50IHJlYXNvbiBpZiBiYWQgcmVxdWVzdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gcmV0dXJuIGJhZCByZXF1ZXN0IHJlc3VsdFxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIEluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkSW5pdFZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UocmVxdWVzdEpzb25EaWN0LCByZXF1ZXN0UmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCk7XG5cbiAgICAgICAgICAgICAgICBpZighdmFsaWRhdGVkSW5pdFZhbHVlcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXNwb25zZSwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBhbGwgb2tcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCB2YWxpZGF0ZWRJbml0VmFsdWVzLCBcIlwiLCAwKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjcmVhdGVQYXlsb2FkRGF0YShwYXlsb2FkOnN0cmluZywgZ3ppcDpib29sZWFuKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmKGd6aXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBwYXlsb2FkRGF0YSA9IEdBVXRpbGl0aWVzLkd6aXBDb21wcmVzcyhwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gR0FMb2dnZXIuRChcIkd6aXAgc3RhdHMuIFNpemU6IFwiICsgRW5jb2RpbmcuVVRGOC5HZXRCeXRlcyhwYXlsb2FkKS5MZW5ndGggKyBcIiwgQ29tcHJlc3NlZDogXCIgKyBwYXlsb2FkRGF0YS5MZW5ndGggKyBcIiwgQ29udGVudDogXCIgKyBwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwYXlsb2FkRGF0YSA9IHBheWxvYWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWREYXRhO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlOm51bWJlciwgcmVzcG9uc2VNZXNzYWdlOnN0cmluZywgYm9keTpzdHJpbmcsIHJlcXVlc3RJZDpzdHJpbmcpOiBFR0FIVFRQQXBpUmVzcG9uc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBpZiBubyByZXN1bHQgLSBvZnRlbiBubyBjb25uZWN0aW9uXG4gICAgICAgICAgICAgICAgaWYoIWJvZHkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgcmVzcG9uc2VNZXNzYWdlICsgXCIsIFN0YXR1cyBjb2RlOiBcIiArIHJlc3BvbnNlQ29kZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBva1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDIwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuT2s7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gNDAxIGNhbiByZXR1cm4gMCBzdGF0dXNcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSAwIHx8IHJlc3BvbnNlQ29kZSA9PT0gNDAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA0MDEgLSBVbmF1dGhvcml6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLlVuYXV0aG9yaXplZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSA0MDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMCAtIEJhZCBSZXF1ZXN0LlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0O1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDUwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNTAwIC0gSW50ZXJuYWwgU2VydmVyIEVycm9yLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5JbnRlcm5hbFNlcnZlckVycm9yO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JUeXBlVG9TdHJpbmcodmFsdWU6RUdBU2RrRXJyb3JUeXBlKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgc3dpdGNoKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQ6XG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmVqZWN0ZWRcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FIVFRQQXBpUmVzcG9uc2U7XG4gICAgICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvclR5cGUgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBU2RrRXJyb3JUeXBlO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUV2ZW50c1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUV2ZW50cyA9IG5ldyBHQUV2ZW50cygpO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ6c3RyaW5nID0gXCJ1c2VyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNlc3Npb25FbmQ6c3RyaW5nID0gXCJzZXNzaW9uX2VuZFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlEZXNpZ246c3RyaW5nID0gXCJkZXNpZ25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QnVzaW5lc3M6c3RyaW5nID0gXCJidXNpbmVzc1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlQcm9ncmVzc2lvbjpzdHJpbmcgPSBcInByb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVJlc291cmNlOnN0cmluZyA9IFwicmVzb3VyY2VcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RXJyb3I6c3RyaW5nID0gXCJlcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4RXZlbnRDb3VudDpudW1iZXIgPSA1MDA7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEV2ZW50IHNwZWNpZmljIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0O1xuXG4gICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IHNlc3Npb24gbnVtYmVyICBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50U2Vzc2lvbk51bSgpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXksIEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBTRVNTSU9OIFNUQVJUIGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBldmVudCByaWdodCBhd2F5XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydCwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25FbmRFdmVudCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25fc3RhcnRfdHM6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50X3RzX2FkanVzdGVkOm51bWJlciA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uTGVuZ3RoOm51bWJlciA9IGNsaWVudF90c19hZGp1c3RlZCAtIHNlc3Npb25fc3RhcnRfdHM7XG5cbiAgICAgICAgICAgICAgICBpZihzZXNzaW9uTGVuZ3RoIDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFNob3VsZCBuZXZlciBoYXBwZW4uXG4gICAgICAgICAgICAgICAgICAgIC8vIENvdWxkIGJlIGJlY2F1c2Ugb2YgZWRnZSBjYXNlcyByZWdhcmRpbmcgdGltZSBhbHRlcmluZyBvbiBkZXZpY2UuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTZXNzaW9uIGxlbmd0aCB3YXMgY2FsY3VsYXRlZCB0byBiZSBsZXNzIHRoZW4gMC4gU2hvdWxkIG5vdCBiZSBwb3NzaWJsZS4gUmVzZXR0aW5nIHRvIDAuXCIpO1xuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uTGVuZ3RoID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wibGVuZ3RoXCJdID0gc2Vzc2lvbkxlbmd0aDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBFTkQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBhbGwgZXZlbnQgcmlnaHQgYXdheVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoXCJcIiwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGNhcnRUeXBlOnN0cmluZyA9IG51bGwsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3ksIGFtb3VudCwgY2FydFR5cGUsIGl0ZW1UeXBlLCBpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgdHJhbnNhY3Rpb24gbnVtYmVyIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRUcmFuc2FjdGlvbk51bSgpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5LCBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBSZXF1aXJlZFxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QnVzaW5lc3M7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY3VycmVuY3lcIl0gPSBjdXJyZW5jeTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhbW91bnRcIl0gPSBhbW91bnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W0dBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXldID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gT3B0aW9uYWxcbiAgICAgICAgICAgICAgICBpZiAoY2FydFR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXJ0X3R5cGVcIl0gPSBjYXJ0VHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHMpKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgQlVTSU5FU1MgZXZlbnQ6IHtjdXJyZW5jeTpcIiArIGN1cnJlbmN5ICsgXCIsIGFtb3VudDpcIiArIGFtb3VudCArIFwiLCBpdGVtVHlwZTpcIiArIGl0ZW1UeXBlICsgXCIsIGl0ZW1JZDpcIiArIGl0ZW1JZCArIFwiLCBjYXJ0VHlwZTpcIiArIGNhcnRUeXBlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGUsIGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIElmIGZsb3cgdHlwZSBpcyBzaW5rIHJldmVyc2UgYW1vdW50XG4gICAgICAgICAgICAgICAgaWYgKGZsb3dUeXBlID09PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlNpbmspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbW91bnQgKj0gLTE7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGV2ZW50IHNwZWNpZmljIHZhbHVlc1xuICAgICAgICAgICAgICAgIHZhciBmbG93VHlwZVN0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5yZXNvdXJjZUZsb3dUeXBlVG9TdHJpbmcoZmxvd1R5cGUpO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gZmxvd1R5cGVTdHJpbmcgKyBcIjpcIiArIGN1cnJlbmN5ICsgXCI6XCIgKyBpdGVtVHlwZSArIFwiOlwiICsgaXRlbUlkO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlSZXNvdXJjZTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhbW91bnRcIl0gPSBhbW91bnQ7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHMpKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUkVTT1VSQ0UgZXZlbnQ6IHtjdXJyZW5jeTpcIiArIGN1cnJlbmN5ICsgXCIsIGFtb3VudDpcIiArIGFtb3VudCArIFwiLCBpdGVtVHlwZTpcIiArIGl0ZW1UeXBlICsgXCIsIGl0ZW1JZDpcIiArIGl0ZW1JZCArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxOnN0cmluZywgcHJvZ3Jlc3Npb24wMjpzdHJpbmcsIHByb2dyZXNzaW9uMDM6c3RyaW5nLCBzY29yZTpudW1iZXIsIHNlbmRTY29yZTpib29sZWFuLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwcm9ncmVzc2lvblN0YXR1c1N0cmluZzpzdHJpbmcgPSBHQUV2ZW50cy5wcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHByb2dyZXNzaW9uU3RhdHVzKTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gUHJvZ3Jlc3Npb24gaWRlbnRpZmllclxuICAgICAgICAgICAgICAgIHZhciBwcm9ncmVzc2lvbklkZW50aWZpZXI6c3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgaWYgKCFwcm9ncmVzc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiZXZlbnRfaWRcIl0gPSBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiOlwiICsgcHJvZ3Jlc3Npb25JZGVudGlmaWVyO1xuXG4gICAgICAgICAgICAgICAgLy8gQXR0ZW1wdFxuICAgICAgICAgICAgICAgIHZhciBhdHRlbXB0X251bTpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHNjb3JlIGlmIHNwZWNpZmllZCBhbmQgc3RhdHVzIGlzIG5vdCBzdGFydFxuICAgICAgICAgICAgICAgIGlmIChzZW5kU2NvcmUgJiYgcHJvZ3Jlc3Npb25TdGF0dXMgIT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuU3RhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJzY29yZVwiXSA9IHNjb3JlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENvdW50IGF0dGVtcHRzIG9uIGVhY2ggcHJvZ3Jlc3Npb24gZmFpbCBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuRmFpbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBhdHRlbXB0IG51bWJlclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBpbmNyZW1lbnQgYW5kIGFkZCBhdHRlbXB0X251bSBvbiBjb21wbGV0ZSBhbmQgZGVsZXRlIHBlcnNpc3RlZFxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgYXR0ZW1wdCBudW1iZXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIGV2ZW50XG4gICAgICAgICAgICAgICAgICAgIGF0dGVtcHRfbnVtID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImF0dGVtcHRfbnVtXCJdID0gYXR0ZW1wdF9udW07XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5jbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb25JZGVudGlmaWVyKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRmllbGRzVG9FdmVudChldmVudERpY3QsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHMpKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUFJPR1JFU1NJT04gZXZlbnQ6IHtzdGF0dXM6XCIgKyBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiLCBwcm9ncmVzc2lvbjAxOlwiICsgcHJvZ3Jlc3Npb24wMSArIFwiLCBwcm9ncmVzc2lvbjAyOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiLCBwcm9ncmVzc2lvbjAzOlwiICsgcHJvZ3Jlc3Npb24wMyArIFwiLCBzY29yZTpcIiArIHNjb3JlICsgXCIsIGF0dGVtcHQ6XCIgKyBhdHRlbXB0X251bSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyLCBzZW5kVmFsdWU6Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkLCB2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5RGVzaWduO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImV2ZW50X2lkXCJdID0gZXZlbnRJZDtcblxuICAgICAgICAgICAgICAgIGlmKHNlbmRWYWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInZhbHVlXCJdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREYXRhKTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIERFU0lHTiBldmVudDoge2V2ZW50SWQ6XCIgKyBldmVudElkICsgXCIsIHZhbHVlOlwiICsgdmFsdWUgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5LCBtZXNzYWdlOnN0cmluZywgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgc2V2ZXJpdHlTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMuZXJyb3JTZXZlcml0eVRvU3RyaW5nKHNldmVyaXR5KTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUVycm9yRXZlbnQoc2V2ZXJpdHksIG1lc3NhZ2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUVycm9yO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInNldmVyaXR5XCJdID0gc2V2ZXJpdHlTdHJpbmc7XG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wibWVzc2FnZVwiXSA9IG1lc3NhZ2U7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGEpO1xuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRmllbGRzVG9FdmVudChldmVudERhdGEsIEdBU3RhdGUudmFsaWRhdGVBbmRDbGVhbkN1c3RvbUZpZWxkcyhmaWVsZHMpKTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgRVJST1IgZXZlbnQ6IHtzZXZlcml0eTpcIiArIHNldmVyaXR5U3RyaW5nICsgXCIsIG1lc3NhZ2U6XCIgKyBtZXNzYWdlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHByb2Nlc3NFdmVudHMoY2F0ZWdvcnk6c3RyaW5nLCBwZXJmb3JtQ2xlYW5VcDpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHRocm93IG5ldyBFcnJvcihcInByb2Nlc3NFdmVudHMgbm90IGltcGxlbWVudGVkXCIpO1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZGVudGlmaWVyOnN0cmluZyA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDbGVhbnVwXG4gICAgICAgICAgICAgICAgICAgIGlmKHBlcmZvcm1DbGVhblVwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5jbGVhbnVwRXZlbnRzKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5maXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cygpO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gUHJlcGFyZSBTUUxcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlbGVjdEFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIFwibmV3XCJdKTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlV2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIFwibmV3XCJdKTtcbiAgICAgICAgICAgICAgICAgICAgaWYoY2F0ZWdvcnkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdEFyZ3MucHVzaChbXCJjYXRlZ29yeVwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgY2F0ZWdvcnldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZVNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlU2V0QXJncy5wdXNoKFtcInN0YXR1c1wiLCByZXF1ZXN0SWRlbnRpZmllcl0pO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBldmVudHMgdG8gcHJvY2Vzc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnRzOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBmb3IgZXJyb3JzIG9yIGVtcHR5XG4gICAgICAgICAgICAgICAgICAgIGlmKCFldmVudHMgfHwgZXZlbnRzLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IE5vIGV2ZW50cyB0byBzZW5kXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMudXBkYXRlU2Vzc2lvblN0b3JlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBudW1iZXIgb2YgZXZlbnRzIGFuZCB0YWtlIHNvbWUgYWN0aW9uIGlmIHRoZXJlIGFyZSB0b28gbWFueT9cbiAgICAgICAgICAgICAgICAgICAgaWYoZXZlbnRzLmxlbmd0aCA+IEdBRXZlbnRzLk1heEV2ZW50Q291bnQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIE1ha2UgYSBsaW1pdCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgICAgICAgICBldmVudHMgPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MsIHRydWUsIEdBRXZlbnRzLk1heEV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIEdldCBsYXN0IHRpbWVzdGFtcFxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RJdGVtOntba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbZXZlbnRzLmxlbmd0aCAtIDFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RUaW1lc3RhbXA6c3RyaW5nID0gbGFzdEl0ZW1bXCJjbGllbnRfdHNcIl0gYXMgc3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFNlbGVjdCBhZ2FpblxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZXZlbnRzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBTZW5kaW5nIFwiICsgZXZlbnRzLmxlbmd0aCArIFwiIGV2ZW50cy5cIik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gU2V0IHN0YXR1cyBvZiBldmVudHMgdG8gJ3NlbmRpbmcnIChhbHNvIGNoZWNrIGZvciBlcnJvcilcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHVwZGF0ZVNldEFyZ3MsIHVwZGF0ZVdoZXJlQXJncykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBwYXlsb2FkIGRhdGEgZnJvbSBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgdmFyIHBheWxvYWRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGk6bnVtYmVyID0gMDsgaSA8IGV2ZW50cy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2Ontba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbaV07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0ID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChldltcImV2ZW50XCJdKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXZlbnREaWN0Lmxlbmd0aCAhPSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBheWxvYWRBcnJheS5wdXNoKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZEV2ZW50c0luQXJyYXkocGF5bG9hZEFycmF5LCByZXF1ZXN0SWRlbnRpZmllciwgR0FFdmVudHMucHJvY2Vzc0V2ZW50c0NhbGxiYWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3IgZHVyaW5nIFByb2Nlc3NFdmVudHMoKTogXCIgKyBlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudHNDYWxsYmFjayhyZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlLCBkYXRhRGljdDp7W2tleTpzdHJpbmddOiBhbnl9LCAgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZFdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0SWRXaGVyZUFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIHJlcXVlc3RJZF0pO1xuXG4gICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuT2spXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBEZWxldGUgZXZlbnRzXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLkV2ZW50cywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFB1dCBldmVudHMgYmFjayAoT25seSBpbiBjYXNlIG9mIG5vIHJlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgc2V0QXJnczpBcnJheTxbc3RyaW5nLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0QXJncy5wdXNoKFtcInN0YXR1c1wiLCBcIm5ld1wiXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzIHRvIGNvbGxlY3RvciAtIFJldHJ5aW5nIG5leHQgdGltZVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgc2V0QXJncywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHMgKFdoZW4gZ2V0dGluZyBzb21lIGFud3NlciBiYWNrIGFsd2F5cyBhc3N1bWUgZXZlbnRzIGFyZSBwcm9jZXNzZWQpXG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihkYXRhRGljdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIganNvbjphbnk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqIGluIGRhdGFEaWN0KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAganNvbiA9IGRhdGFEaWN0W2pdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdCAmJiBqc29uLmNvbnN0cnVjdG9yID09PSBBcnJheSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogXCIgKyBldmVudENvdW50ICsgXCIgZXZlbnRzIHNlbnQuIFwiICsgY291bnQgKyBcIiBldmVudHMgZmFpbGVkIEdBIHNlcnZlciB2YWxpZGF0aW9uLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLkV2ZW50cywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2xlYW51cEV2ZW50cygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS51cGRhdGUoRUdBU3RvcmUuRXZlbnRzLCBbW1wic3RhdHVzXCIgLCBcIm5ld1wiXV0pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBmaXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gR2V0IGFsbCBzZXNzaW9ucyB0aGF0IGFyZSBub3QgY3VycmVudFxuICAgICAgICAgICAgICAgIHZhciBhcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgIGFyZ3MucHVzaChbXCJzZXNzaW9uX2lkXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsLCBHQVN0YXRlLmdldFNlc3Npb25JZCgpXSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbnM6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5TZXNzaW9ucywgYXJncyk7XG5cbiAgICAgICAgICAgICAgICBpZiAoIXNlc3Npb25zIHx8IHNlc3Npb25zLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoc2Vzc2lvbnMubGVuZ3RoICsgXCIgc2Vzc2lvbihzKSBsb2NhdGVkIHdpdGggbWlzc2luZyBzZXNzaW9uX2VuZCBldmVudC5cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgbWlzc2luZyBzZXNzaW9uX2VuZCBldmVudHNcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHNlc3Npb25zLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlc3Npb25FbmRFdmVudDp7W2tleTpzdHJpbmddOiBhbnl9ID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChzZXNzaW9uc1tpXVtcImV2ZW50XCJdIGFzIHN0cmluZykpO1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnRfdHM6bnVtYmVyID0gc2Vzc2lvbkVuZEV2ZW50W1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHN0YXJ0X3RzOm51bWJlciA9IHNlc3Npb25zW2ldW1widGltZXN0YW1wXCJdIGFzIG51bWJlcjtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgbGVuZ3RoOm51bWJlciA9IGV2ZW50X3RzIC0gc3RhcnRfdHM7XG4gICAgICAgICAgICAgICAgICAgIGxlbmd0aCA9IE1hdGgubWF4KDAsIGxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzIGxlbmd0aCBjYWxjdWxhdGVkOiBcIiArIGxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkVuZEV2ZW50W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImxlbmd0aFwiXSA9IGxlbmd0aDtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKHNlc3Npb25FbmRFdmVudCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgIC8vIENoZWNrIGlmIHdlIGFyZSBpbml0aWFsaXplZFxuICAgICAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IGFkZCBldmVudDogU0RLIGlzIG5vdCBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgZGIgc2l6ZSBsaW1pdHMgKDEwbWIpXG4gICAgICAgICAgICAgICAgICAgIC8vIElmIGRhdGFiYXNlIGlzIHRvbyBsYXJnZSBibG9jayBhbGwgZXhjZXB0IHVzZXIsIHNlc3Npb24gYW5kIGJ1c2luZXNzXG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0b3JlLmlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpICYmICFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudERhdGFbXCJjYXRlZ29yeVwiXSBhcyBzdHJpbmcsIC9eKHVzZXJ8c2Vzc2lvbl9lbmR8YnVzaW5lc3MpJC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRGF0YWJhc2UgdG9vIGxhcmdlLiBFdmVudCBoYXMgYmVlbiBibG9ja2VkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBkZWZhdWx0IGFubm90YXRpb25zXG4gICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gd2l0aCBvbmx5IGRlZmF1bHQgYW5ub3RhdGlvbnNcbiAgICAgICAgICAgICAgICAgICAgdmFyIGpzb25EZWZhdWx0czpzdHJpbmcgPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShldikpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIE1lcmdlIHdpdGggZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgZSBpbiBldmVudERhdGEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2W2VdID0gZXZlbnREYXRhW2VdO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gc3RyaW5nIHJlcHJlc2VudGF0aW9uXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2KTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBvdXRwdXQgaWYgVkVSQk9TRSBMT0cgZW5hYmxlZFxuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmlpKFwiRXZlbnQgYWRkZWQgdG8gcXVldWU6IFwiICsganNvbik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzdGF0dXNcIl0gPSBcIm5ld1wiO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjYXRlZ29yeVwiXSA9IGV2W1wiY2F0ZWdvcnlcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNsaWVudF90c1wiXSA9IGV2W1wiY2xpZW50X3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGV2KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuRXZlbnRzLCB2YWx1ZXMpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzZXNzaW9uIHN0b3JlIGlmIG5vdCBsYXN0XG4gICAgICAgICAgICAgICAgICAgIGlmIChldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9PSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlNlc3Npb25zLCBbW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgZXZbXCJzZXNzaW9uX2lkXCJdIGFzIHN0cmluZ11dKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlcyA9IHt9O1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IGV2W1wic2Vzc2lvbl9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInRpbWVzdGFtcFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IGpzb25EZWZhdWx0cztcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLlNlc3Npb25zLCB2YWx1ZXMsIHRydWUsIFwic2Vzc2lvbl9pZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZEV2ZW50VG9TdG9yZTogZXJyb3JcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyB1cGRhdGVTZXNzaW9uU3RvcmUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1widGltZXN0YW1wXCJdID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShHQVN0YXRlLmdldEV2ZW50QW5ub3RhdGlvbnMoKSkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5TZXNzaW9ucywgdmFsdWVzLCB0cnVlLCBcInNlc3Npb25faWRcIik7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zYXZlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBhZGQgdG8gZGljdCAoaWYgbm90IG5pbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMVwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAyXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDNcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkRmllbGRzVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSwgZmllbGRzOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fZmllbGRzXCJdID0gZmllbGRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU291cmNlIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5Tb3VyY2VdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU291cmNlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNpbmtcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0IHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlN0YXJ0XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29tcGxldGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiRmFpbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGVycm9yU2V2ZXJpdHlUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkRlYnVnIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5EZWJ1Z10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkZWJ1Z1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuSW5mbyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuSW5mb10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbmZvXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndhcm5pbmdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkVycm9yIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5FcnJvcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJlcnJvclwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuQ3JpdGljYWwgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImNyaXRpY2FsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0aHJlYWRpbmdcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG4gICAgICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVRocmVhZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVRocmVhZGluZyA9IG5ldyBHQVRocmVhZGluZygpO1xuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGJsb2NrczpQcmlvcml0eVF1ZXVlPFRpbWVkQmxvY2s+ID0gbmV3IFByaW9yaXR5UXVldWU8VGltZWRCbG9jaz4oPElDb21wYXJlcjxudW1iZXI+PntcbiAgICAgICAgICAgICAgICBjb21wYXJlOiAoeDpudW1iZXIsIHk6bnVtYmVyKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB4IC0geTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHByaXZhdGUgcmVhZG9ubHkgaWQyVGltZWRCbG9ja01hcDp7W2tleTpudW1iZXJdOiBUaW1lZEJsb2NrfSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuVGltZW91dElkOm51bWJlcjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFRocmVhZFdhaXRUaW1lSW5NczpudW1iZXIgPSAxMDAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzOm51bWJlciA9IDguMDtcbiAgICAgICAgICAgIHByaXZhdGUga2VlcFJ1bm5pbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgaXNSdW5uaW5nOmJvb2xlYW47XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbml0aWFsaXppbmcgR0EgdGhyZWFkLi4uXCIpO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0YXJ0VGhyZWFkKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlVGltZWRCbG9jayhkZWxheUluU2Vjb25kczpudW1iZXIgPSAwKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0aW1lOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHRpbWUuc2V0U2Vjb25kcyh0aW1lLmdldFNlY29uZHMoKSArIGRlbGF5SW5TZWNvbmRzKTtcblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBuZXcgVGltZWRCbG9jayh0aW1lKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gdGltZWRCbG9jaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGFza09uR0FUaHJlYWQodGFza0Jsb2NrOigpID0+IHZvaWQsIGRlbGF5SW5TZWNvbmRzOm51bWJlciA9IDApOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRpbWU6RGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgdGltZS5zZXRTZWNvbmRzKHRpbWUuZ2V0U2Vjb25kcygpICsgZGVsYXlJblNlY29uZHMpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IG5ldyBUaW1lZEJsb2NrKHRpbWUpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSB0YXNrQmxvY2s7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFt0aW1lZEJsb2NrLmlkXSA9IHRpbWVkQmxvY2s7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGltZWRCbG9ja09uR0FUaHJlYWQodGltZWRCbG9jazpUaW1lZEJsb2NrKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2NoZWR1bGVUaW1lcihpbnRlcnZhbDpudW1iZXIsIGNhbGxiYWNrOigpID0+IHZvaWQpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdGltZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICB0aW1lLnNldFNlY29uZHModGltZS5nZXRTZWNvbmRzKCkgKyBpbnRlcnZhbCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSk7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9IGNhbGxiYWNrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRUaW1lZEJsb2NrQnlJZChibG9ja0lkZW50aWZpZXI6bnVtYmVyKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChibG9ja0lkZW50aWZpZXIgaW4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW2Jsb2NrSWRlbnRpZmllcl1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAgIGlmKCFHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zY2hlZHVsZVRpbWVyKEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcywgR0FUaHJlYWRpbmcucHJvY2Vzc0V2ZW50UXVldWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uQW5kU3RvcFF1ZXVlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFbmRpbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0b3BFdmVudFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uRW5kRXZlbnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdG9wRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2Uua2VlcFJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpZ25vcmVUaW1lcihibG9ja0lkZW50aWZpZXI6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChibG9ja0lkZW50aWZpZXIgaW4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbYmxvY2tJZGVudGlmaWVyXS5pZ25vcmUgPSB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGludGVydmFsID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcyA9IGludGVydmFsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2s6VGltZWRCbG9jayk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmJsb2Nrcy5lbnF1ZXVlKHRpbWVkQmxvY2suZGVhZGxpbmUuZ2V0VGltZSgpLCB0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBjbGVhclRpbWVvdXQoR0FUaHJlYWRpbmcucnVuVGltZW91dElkKTtcblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jaztcblxuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoKHRpbWVkQmxvY2sgPSBHQVRocmVhZGluZy5nZXROZXh0QmxvY2soKSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghdGltZWRCbG9jay5pZ25vcmUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodGltZWRCbG9jay5hc3luYylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF0aW1lZEJsb2NrLnJ1bm5pbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVkQmxvY2sucnVubmluZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucnVuVGltZW91dElkID0gc2V0VGltZW91dChHQVRocmVhZGluZy5ydW4sIEdBVGhyZWFkaW5nLlRocmVhZFdhaXRUaW1lSW5Ncyk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3Igb24gR0EgdGhyZWFkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRW5kaW5nIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnRUaHJlYWQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdGFydGluZyBHQSB0aHJlYWRcIik7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucnVuVGltZW91dElkID0gc2V0VGltZW91dChHQVRocmVhZGluZy5ydW4sIDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXROZXh0QmxvY2soKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBub3c6RGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmhhc0l0ZW1zKCkgJiYgR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLnBlZWsoKS5kZWFkbGluZS5nZXRUaW1lKCkgPD0gbm93LmdldFRpbWUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkuYXN5bmMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkucnVubmluZylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLnBlZWsoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmRlcXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MuZGVxdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudFF1ZXVlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIHRydWUpO1xuICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2NoZWR1bGVUaW1lcihHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMsIEdBVGhyZWFkaW5nLnByb2Nlc3NFdmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBpbXBvcnQgR0FUaHJlYWRpbmcgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5HQVRocmVhZGluZztcbiAgICBpbXBvcnQgVGltZWRCbG9jayA9IGdhbWVhbmFseXRpY3MudGhyZWFkaW5nLlRpbWVkQmxvY2s7XG4gICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgIGltcG9ydCBHQURldmljZSA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLkdBRGV2aWNlO1xuICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICBpbXBvcnQgRUdBSFRUUEFwaVJlc3BvbnNlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcbiAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICBpbXBvcnQgR0FFdmVudHMgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5HQUV2ZW50cztcblxuICAgIGV4cG9ydCBjbGFzcyBHYW1lQW5hbHl0aWNzXG4gICAge1xuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbml0VGltZWRCbG9ja0lkOm51bWJlciA9IC0xO1xuICAgICAgICBwdWJsaWMgc3RhdGljIG1ldGhvZE1hcDp7W2lkOnN0cmluZ106ICguLi5hcmdzOiBhbnlbXSkgPT4gdm9pZH0gPSB7fTtcblxuICAgICAgICBwdWJsaWMgc3RhdGljIGluaXQoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS50b3VjaCgpO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQnVpbGQnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQnVpbGQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlVXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZVVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpbml0aWFsaXplJ10gPSBHYW1lQW5hbHl0aWNzLmluaXRpYWxpemU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkQnVzaW5lc3NFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRCdXNpbmVzc0V2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFJlc291cmNlRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkUmVzb3VyY2VFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRQcm9ncmVzc2lvbkV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZFByb2dyZXNzaW9uRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRGVzaWduRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRGVzaWduRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRXJyb3JFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRFcnJvckV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEVycm9yRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRXJyb3JFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkSW5mb0xvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkSW5mb0xvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkVmVyYm9zZUxvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkVmVyYm9zZUxvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbiddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAxJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAyJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAzJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEZhY2Vib29rSWQnXSA9IEdhbWVBbmFseXRpY3Muc2V0RmFjZWJvb2tJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRHZW5kZXInXSA9IEdhbWVBbmFseXRpY3Muc2V0R2VuZGVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEJpcnRoWWVhciddID0gR2FtZUFuYWx5dGljcy5zZXRCaXJ0aFllYXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwnXSA9IEdhbWVBbmFseXRpY3Muc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWw7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc3RhcnRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnN0YXJ0U2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydlbmRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmVuZFNlc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnb25TdG9wJ10gPSBHYW1lQW5hbHl0aWNzLm9uU3RvcDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblJlc3VtZSddID0gR2FtZUFuYWx5dGljcy5vblJlc3VtZTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRDb21tYW5kQ2VudGVyTGlzdGVuZXInXSA9IEdhbWVBbmFseXRpY3MuYWRkQ29tbWFuZENlbnRlckxpc3RlbmVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3JlbW92ZUNvbW1hbmRDZW50ZXJMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5yZW1vdmVDb21tYW5kQ2VudGVyTGlzdGVuZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0Q29tbWFuZENlbnRlclZhbHVlQXNTdHJpbmcnXSA9IEdhbWVBbmFseXRpY3MuZ2V0Q29tbWFuZENlbnRlclZhbHVlQXNTdHJpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnaXNDb21tYW5kQ2VudGVyUmVhZHknXSA9IEdhbWVBbmFseXRpY3MuaXNDb21tYW5kQ2VudGVyUmVhZHk7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnZ2V0Q29uZmlndXJhdGlvbnNDb250ZW50QXNTdHJpbmcnXSA9IEdhbWVBbmFseXRpY3MuZ2V0Q29uZmlndXJhdGlvbnNDb250ZW50QXNTdHJpbmc7XG5cbiAgICAgICAgICAgIGlmKHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnICYmIHR5cGVvZiB3aW5kb3dbJ0dhbWVBbmFseXRpY3MnXSAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvd1snR2FtZUFuYWx5dGljcyddWydxJ10gIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBxOmFueVtdID0gd2luZG93WydHYW1lQW5hbHl0aWNzJ11bJ3EnXTtcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpIGluIHEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmdhQ29tbWFuZC5hcHBseShudWxsLCBxW2ldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdhQ29tbWFuZCguLi5hcmdzOiBhbnlbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoYXJncy5sZW5ndGggPiAwKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGFyZ3NbMF0gaW4gZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGFyZ3MubGVuZ3RoID4gMSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFthcmdzWzBdXS5hcHBseShudWxsLCBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChhcmdzLCAxKSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwW2FyZ3NbMF1dKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlcyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUJ1aWxkKGJ1aWxkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkJ1aWxkIHZlcnNpb24gbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUJ1aWxkKGJ1aWxkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgYnVpbGQ6IENhbm5vdCBiZSBudWxsLCBlbXB0eSBvciBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBidWlsZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRCdWlsZChidWlsZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb24oc2RrR2FtZUVuZ2luZVZlcnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTZGtXcmFwcGVyVmVyc2lvbihzZGtHYW1lRW5naW5lVmVyc2lvbikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHNkayB2ZXJzaW9uOiBTZGsgdmVyc2lvbiBub3Qgc3VwcG9ydGVkLiBTdHJpbmc6IFwiICsgc2RrR2FtZUVuZ2luZVZlcnNpb24pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uID0gc2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb24oZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFbmdpbmVWZXJzaW9uKGdhbWVFbmdpbmVWZXJzaW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgZ2FtZSBlbmdpbmUgdmVyc2lvbjogR2FtZSBlbmdpbmUgdmVyc2lvbiBub3Qgc3VwcG9ydGVkLiBTdHJpbmc6IFwiICsgZ2FtZUVuZ2luZVZlcnNpb24pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uID0gZ2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlVXNlcklkKHVJZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBIGN1c3RvbSB1c2VyIGlkIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVVc2VySWQodUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgdXNlcl9pZDogQ2Fubm90IGJlIG51bGwsIGVtcHR5IG9yIGFib3ZlIDY0IGxlbmd0aC4gV2lsbCB1c2UgZGVmYXVsdCB1c2VyX2lkIG1ldGhvZC4gVXNlZCBzdHJpbmc6IFwiICsgdUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0VXNlcklkKHVJZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgaW5pdGlhbGl6ZShnYW1lS2V5OnN0cmluZyA9IFwiXCIsIGdhbWVTZWNyZXQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNESyBhbHJlYWR5IGluaXRpYWxpemVkLiBDYW4gb25seSBiZSBjYWxsZWQgb25jZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGZhaWxlZCBpbml0aWFsaXplLiBHYW1lIGtleSBvciBzZWNyZXQga2V5IGlzIGludmFsaWQuIENhbiBvbmx5IGNvbnRhaW4gY2hhcmFjdGVycyBBLXogMC05LCBnYW1lS2V5IGlzIDMyIGxlbmd0aCwgZ2FtZVNlY3JldCBpcyA0MCBsZW5ndGguIEZhaWxlZCBrZXlzIC0gZ2FtZUtleTogXCIgKyBnYW1lS2V5ICsgXCIsIHNlY3JldEtleTogXCIgKyBnYW1lU2VjcmV0KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0S2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KTtcblxuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW50ZXJuYWxJbml0aWFsaXplKCk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGltZWRCbG9ja09uR0FUaHJlYWQodGltZWRCbG9jayk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiLCBjYXJ0VHlwZTpzdHJpbmcgPSBcIlwiLyosIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSovKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gZXZlbnRzXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBjYXJ0VHlwZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSA9IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkLCBjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cyA9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZCwgcHJvZ3Jlc3Npb24wMTpzdHJpbmcgPSBcIlwiLCBwcm9ncmVzc2lvbjAyOnN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDM6c3RyaW5nID0gXCJcIiwgc2NvcmU/OmFueS8qLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30qLyk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgcHJvZ3Jlc3Npb24gZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOmJvb2xlYW4gPSB0eXBlb2Ygc2NvcmUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgLy8gaWYodHlwZW9mIHNjb3JlID09PSBcIm9iamVjdFwiKVxuICAgICAgICAgICAgICAgIC8vIHtcbiAgICAgICAgICAgICAgICAvLyAgICAgZmllbGRzID0gc2NvcmUgYXMge1tpZDpzdHJpbmddOiBhbnl9O1xuICAgICAgICAgICAgICAgIC8vIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzLCBzZW5kU2NvcmUgPyBzY29yZSA6IDAsIHNlbmRTY29yZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZERlc2lnbkV2ZW50KGV2ZW50SWQ6c3RyaW5nLCB2YWx1ZT86YW55LyosIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSovKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBkZXNpZ24gZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBzZW5kVmFsdWU6Ym9vbGVhbiA9IHR5cGVvZiB2YWx1ZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICAvLyBpZih0eXBlb2YgdmFsdWUgPT09IFwib2JqZWN0XCIpXG4gICAgICAgICAgICAgICAgLy8ge1xuICAgICAgICAgICAgICAgIC8vICAgICBmaWVsZHMgPSB2YWx1ZSBhcyB7W2lkOnN0cmluZ106IGFueX07XG4gICAgICAgICAgICAgICAgLy8gfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERlc2lnbkV2ZW50KGV2ZW50SWQsIHNlbmRWYWx1ZSA/IHZhbHVlICA6IDAsIHNlbmRWYWx1ZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSA9IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXJyb3JFdmVudChzZXZlcml0eSwgbWVzc2FnZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRJbmZvTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldEluZm9Mb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbmZvIGxvZ2dpbmcgZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZFZlcmJvc2VMb2coZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0VmVyYm9zZUxvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZlcmJvc2UgbG9nZ2luZyBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmVyYm9zZSBsb2dnaW5nIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRWZXJib3NlTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHN1Ym1pc3Npb24gZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHN1Ym1pc3Npb24gZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RmFjZWJvb2tJZChmYWNlYm9va0lkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUZhY2Vib29rSWQoZmFjZWJvb2tJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEZhY2Vib29rSWQoZmFjZWJvb2tJZCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEdlbmRlcihnZW5kZXI6RUdBR2VuZGVyID0gRUdBR2VuZGVyLlVuZGVmaW5lZCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlR2VuZGVyKGdlbmRlcikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEdlbmRlcihnZW5kZXIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRCaXJ0aFllYXIoYmlydGhZZWFyOm51bWJlciA9IDApOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUJpcnRoeWVhcihiaXJ0aFllYXIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRCaXJ0aFllYXIoYmlydGhZZWFyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbEluU2Vjb25kcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc3RhcnRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy9pZihHQVN0YXRlLmdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuY3JlYXRlVGltZWRCbG9jaygpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW5pdFRpbWVkQmxvY2tJZCA9IHRpbWVkQmxvY2suaWQ7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9ICgpID0+XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbmRTZXNzaW9uQW5kU3RvcFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLnJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm9uU3RvcCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKEV4Y2VwdGlvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29tbWFuZENlbnRlclZhbHVlQXNTdHJpbmcoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyA9IG51bGwpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5LCBkZWZhdWx0VmFsdWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpc0NvbW1hbmRDZW50ZXJSZWFkeSgpOmJvb2xlYW5cbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaXNDb21tYW5kQ2VudGVyUmVhZHkoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQ29tbWFuZENlbnRlckxpc3RlbmVyKGxpc3RlbmVyOnsgb25Db21tYW5kQ2VudGVyVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5hZGRDb21tYW5kQ2VudGVyTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVDb21tYW5kQ2VudGVyTGlzdGVuZXIobGlzdGVuZXI6eyBvbkNvbW1hbmRDZW50ZXJVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLnJlbW92ZUNvbW1hbmRDZW50ZXJMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldEFCVGVzdGluZ0lkKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbnRlcm5hbEluaXRpYWxpemUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmVuc3VyZVBlcnNpc3RlZFN0YXRlcygpO1xuICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSwgR0FTdGF0ZS5nZXREZWZhdWx0SWQoKSk7XG5cbiAgICAgICAgICAgIEdBU3RhdGUuc2V0SW5pdGlhbGl6ZWQodHJ1ZSk7XG5cbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xuXG4gICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBuZXdTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FMb2dnZXIuaShcIlN0YXJ0aW5nIGEgbmV3IHNlc3Npb24uXCIpO1xuXG4gICAgICAgICAgICAvLyBtYWtlIHN1cmUgdGhlIGN1cnJlbnQgY3VzdG9tIGRpbWVuc2lvbnMgYXJlIHZhbGlkXG4gICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnJlcXVlc3RJbml0KEdBU3RhdGUuaW5zdGFuY2UuY29uZmlnc0hhc2gsIEdhbWVBbmFseXRpY3Muc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2spO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2soaW5pdFJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwgaW5pdFJlc3BvbnNlRGljdDp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBpbml0IGlzIG9rXG4gICAgICAgICAgICBpZigoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCkgJiYgaW5pdFJlc3BvbnNlRGljdClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBzZXQgdGhlIHRpbWUgb2Zmc2V0IC0gaG93IG1hbnkgc2Vjb25kcyB0aGUgbG9jYWwgdGltZSBpcyBkaWZmZXJlbnQgZnJvbSBzZXJ2ZXJ0aW1lXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVPZmZzZXRTZWNvbmRzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlRGljdFtcInNlcnZlcl90c1wiXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUczpudW1iZXIgPSBpbml0UmVzcG9uc2VEaWN0W1wic2VydmVyX3RzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgdGltZU9mZnNldFNlY29uZHMgPSBHQVN0YXRlLmNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1widGltZV9vZmZzZXRcIl0gPSB0aW1lT2Zmc2V0U2Vjb25kcztcblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0NvbmZpZygpO1xuICAgICAgICAgICAgICAgICAgICAvLyB1c2UgY2FjaGVkIGlmIG5vdCBDcmVhdGVkXG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc1wiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImFiX2lkXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IG5ldyBjb25maWcgaW4gc3FsIGxpdGUgY3Jvc3Mgc2Vzc2lvbiBzdG9yYWdlXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5LCBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShpbml0UmVzcG9uc2VEaWN0KSkpO1xuXG4gICAgICAgICAgICAgICAgLy8gc2V0IG5ldyBjb25maWcgYW5kIGNhY2hlIGluIG1lbW9yeVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gaW5pdFJlc3BvbnNlRGljdDtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IGluaXRSZXNwb25zZURpY3Q7XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09IEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkluaXRpYWxpemUgU0RLIGZhaWxlZCAtIFVuYXV0aG9yaXplZFwiKTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbG9nIHRoZSBzdGF0dXMgaWYgbm8gY29ubmVjdGlvblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuUmVxdWVzdFRpbWVvdXQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBubyByZXNwb25zZS4gQ291bGQgYmUgb2ZmbGluZSBvciB0aW1lb3V0LlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVzcG9uc2UuIENvdWxkIGJlIGJhZCByZXNwb25zZSBmcm9tIHByb3h5IG9yIEdBIHNlcnZlcnMuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXF1ZXN0IG9yIHVua25vd24gcmVzcG9uc2UuXCIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluaXQgY2FsbCBmYWlsZWQgKHBlcmhhcHMgb2ZmbGluZSlcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgY2FjaGVkIGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBsYXN0IGNyb3NzIHNlc3Npb24gc3RvcmVkIGNvbmZpZyBpbml0IHZhbHVlc1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGRlZmF1bHQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgaW5pdCB2YWx1ZXNcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGNhY2hlZCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBzZXQgb2Zmc2V0IGluIHN0YXRlIChtZW1vcnkpIGZyb20gY3VycmVudCBjb25maWcgKGNvbmZpZyBjb3VsZCBiZSBmcm9tIGNhY2hlIGV0Yy4pXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQgPSBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gPyBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gYXMgbnVtYmVyIDogMDtcblxuICAgICAgICAgICAgLy8gcG9wdWxhdGUgY29uZmlndXJhdGlvbnNcbiAgICAgICAgICAgIEdBU3RhdGUucG9wdWxhdGVDb25maWd1cmF0aW9ucyhHQVN0YXRlLmdldFNka0NvbmZpZygpKTtcblxuICAgICAgICAgICAgLy8gaWYgU0RLIGlzIGRpc2FibGVkIGluIGNvbmZpZ1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzdGFydCBzZXNzaW9uOiBTREsgaXMgZGlzYWJsZWQuXCIpO1xuICAgICAgICAgICAgICAgIC8vIHN0b3AgZXZlbnQgcXVldWVcbiAgICAgICAgICAgICAgICAvLyArIG1ha2Ugc3VyZSBpdCdzIGFibGUgdG8gcmVzdGFydCBpZiBhbm90aGVyIHNlc3Npb24gZGV0ZWN0cyBpdCdzIGVuYWJsZWQgYWdhaW5cbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wRXZlbnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIGdlbmVyYXRlIHRoZSBuZXcgc2Vzc2lvblxuICAgICAgICAgICAgdmFyIG5ld1Nlc3Npb25JZDpzdHJpbmcgPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIGlkXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZCA9IG5ld1Nlc3Npb25JZDtcblxuICAgICAgICAgICAgLy8gU2V0IHNlc3Npb24gc3RhcnRcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgIC8vIEFkZCBzZXNzaW9uIHN0YXJ0IGV2ZW50XG4gICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uU3RhcnRFdmVudCgpO1xuXG4gICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuZ2V0VGltZWRCbG9ja0J5SWQoR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkKTtcblxuICAgICAgICAgICAgaWYodGltZWRCbG9jayAhPSBudWxsKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2sucnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmluaXRUaW1lZEJsb2NrSWQgPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJSZXN1bWluZyBzZXNzaW9uLlwiKTtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm5ld1Nlc3Npb24oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIGlzU2RrUmVhZHkobmVlZHNJbml0aWFsaXplZDpib29sZWFuLCB3YXJuOmJvb2xlYW4gPSB0cnVlLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIpOiBib29sZWFuXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKG1lc3NhZ2UpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbWVzc2FnZSA9IG1lc3NhZ2UgKyBcIjogXCI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIElzIFNESyBpbml0aWFsaXplZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBJcyBTREsgZW5hYmxlZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNESyBpcyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgc2Vzc2lvbiBzdGFydGVkXG4gICAgICAgICAgICBpZiAobmVlZHNJbml0aWFsaXplZCAmJiAhR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNlc3Npb24gaGFzIG5vdCBzdGFydGVkIHlldFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9XG59XG5nYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuaW5pdCgpO1xudmFyIEdhbWVBbmFseXRpY3MgPSBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuZ2FDb21tYW5kO1xuIl19

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
