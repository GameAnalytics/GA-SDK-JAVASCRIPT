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
            return GALogger;
        }());
        GALogger.instance = new GALogger();
        GALogger.Tag = "GameAnalytics";
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
            return GAUtilities;
        }());
        GAUtilities.keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
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
                    GALogger.i("Validation fail - business event - currency: Cannot be (null) and need to be A-Z, 3 characters and in the standard at openexchangerates.org. Failed currency: " + currency);
                    return false;
                }
                if (!GAValidator.validateShortString(cartType, true)) {
                    GALogger.i("Validation fail - business event - cartType. Cannot be above 32 length. String: " + cartType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.i("Validation fail - business event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.i("Validation fail - business event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.i("Validation fail - business event - itemId. Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.i("Validation fail - business event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateResourceEvent = function (flowType, currency, amount, itemType, itemId, availableCurrencies, availableItemTypes) {
                if (flowType == gameanalytics.EGAResourceFlowType.Undefined) {
                    GALogger.i("Validation fail - resource event - flowType: Invalid flow type.");
                    return false;
                }
                if (!currency) {
                    GALogger.i("Validation fail - resource event - currency: Cannot be (null)");
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableCurrencies, currency)) {
                    GALogger.i("Validation fail - resource event - currency: Not found in list of pre-defined available resource currencies. String: " + currency);
                    return false;
                }
                if (!(amount > 0)) {
                    GALogger.i("Validation fail - resource event - amount: Float amount cannot be 0 or negative. Value: " + amount);
                    return false;
                }
                if (!itemType) {
                    GALogger.i("Validation fail - resource event - itemType: Cannot be (null)");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.i("Validation fail - resource event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.i("Validation fail - resource event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableItemTypes, itemType)) {
                    GALogger.i("Validation fail - resource event - itemType: Not found in list of pre-defined available resource itemTypes. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.i("Validation fail - resource event - itemId: Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.i("Validation fail - resource event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateProgressionEvent = function (progressionStatus, progression01, progression02, progression03) {
                if (progressionStatus == gameanalytics.EGAProgressionStatus.Undefined) {
                    GALogger.i("Validation fail - progression event: Invalid progression status.");
                    return false;
                }
                if (progression03 && !(progression02 || !progression01)) {
                    GALogger.i("Validation fail - progression event: 03 found but 01+02 are invalid. Progression must be set as either 01, 01+02 or 01+02+03.");
                    return false;
                }
                else if (progression02 && !progression01) {
                    GALogger.i("Validation fail - progression event: 02 found but not 01. Progression must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                else if (!progression01) {
                    GALogger.i("Validation fail - progression event: progression01 not valid. Progressions must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(progression01, false)) {
                    GALogger.i("Validation fail - progression event - progression01: Cannot be (null), empty or above 64 characters. String: " + progression01);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(progression01)) {
                    GALogger.i("Validation fail - progression event - progression01: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression01);
                    return false;
                }
                if (progression02) {
                    if (!GAValidator.validateEventPartLength(progression02, true)) {
                        GALogger.i("Validation fail - progression event - progression02: Cannot be empty or above 64 characters. String: " + progression02);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression02)) {
                        GALogger.i("Validation fail - progression event - progression02: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression02);
                        return false;
                    }
                }
                if (progression03) {
                    if (!GAValidator.validateEventPartLength(progression03, true)) {
                        GALogger.i("Validation fail - progression event - progression03: Cannot be empty or above 64 characters. String: " + progression03);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression03)) {
                        GALogger.i("Validation fail - progression event - progression03: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression03);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateDesignEvent = function (eventId, value) {
                if (!GAValidator.validateEventIdLength(eventId)) {
                    GALogger.i("Validation fail - design event - eventId: Cannot be (null) or empty. Only 5 event parts allowed seperated by :. Each part need to be 32 characters or less. String: " + eventId);
                    return false;
                }
                if (!GAValidator.validateEventIdCharacters(eventId)) {
                    GALogger.i("Validation fail - design event - eventId: Non valid characters. Only allowed A-z, 0-9, -_., ()!?. String: " + eventId);
                    return false;
                }
                return true;
            };
            GAValidator.validateErrorEvent = function (severity, message) {
                if (severity == gameanalytics.EGAErrorSeverity.Undefined) {
                    GALogger.i("Validation fail - error event - severity: Severity was unsupported value.");
                    return false;
                }
                if (!GAValidator.validateLongString(message, true)) {
                    GALogger.i("Validation fail - error event - message: Message cannot be above 8192 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateSdkErrorEvent = function (gameKey, gameSecret, type) {
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    return false;
                }
                if (type === EGASdkErrorType.Undefined) {
                    GALogger.i("Validation fail - sdk error event - type: Type was unsupported value.");
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
            GAValidator.validateAndCleanInitRequestResponse = function (initResponse) {
                if (initResponse == null) {
                    GALogger.w("validateInitRequestResponse failed - no response dictionary.");
                    return null;
                }
                var validatedDict = {};
                try {
                    validatedDict["enabled"] = initResponse["enabled"];
                }
                catch (e) {
                    GALogger.w("validateInitRequestResponse failed - invalid type in 'enabled' field.");
                    return null;
                }
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
                try {
                    var configurations = initResponse["configurations"];
                    validatedDict["configurations"] = configurations;
                }
                catch (e) {
                    GALogger.w("validateInitRequestResponse failed - invalid type in 'configurations' field. type=" + typeof initResponse["configurations"] + ", value=" + initResponse["configurations"] + ", " + e);
                    return null;
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
                    GALogger.i("Validation fail - user id: id cannot be (null), empty or above 64 characters.");
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
                        GALogger.i("resource currencies validation failed: a resource currency can only be A-Z, a-z. String was: " + resourceCurrencies[i]);
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
                        GALogger.i("resource item types validation failed: a resource item type cannot contain other characters than A-z, 0-9, -_., ()!?. String was: " + resourceItemTypes[i]);
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
                    GALogger.i(arrayTag + " validation failed: array cannot be null. ");
                    return false;
                }
                if (allowNoValues == false && arrayOfStrings.length == 0) {
                    GALogger.i(arrayTag + " validation failed: array cannot be empty. ");
                    return false;
                }
                if (maxCount > 0 && arrayOfStrings.length > maxCount) {
                    GALogger.i(arrayTag + " validation failed: array cannot exceed " + maxCount + " values. It has " + arrayOfStrings.length + " values.");
                    return false;
                }
                for (var i = 0; i < arrayOfStrings.length; ++i) {
                    var stringLength = !arrayOfStrings[i] ? 0 : arrayOfStrings[i].length;
                    if (stringLength === 0) {
                        GALogger.i(arrayTag + " validation failed: contained an empty string. Array=" + JSON.stringify(arrayOfStrings));
                        return false;
                    }
                    if (maxStringLength > 0 && stringLength > maxStringLength) {
                        GALogger.i(arrayTag + " validation failed: a string exceeded max allowed length (which is: " + maxStringLength + "). String was: " + arrayOfStrings[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateFacebookId = function (facebookId) {
                if (!GAValidator.validateString(facebookId, false)) {
                    GALogger.i("Validation fail - facebook id: id cannot be (null), empty or above 64 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateGender = function (gender) {
                if (isNaN(Number(gameanalytics.EGAGender[gender]))) {
                    if (gender == gameanalytics.EGAGender.Undefined || !(gender == gameanalytics.EGAGender.Male || gender == gameanalytics.EGAGender.Female)) {
                        GALogger.i("Validation fail - gender: Has to be 'male' or 'female'. Was: " + gender);
                        return false;
                    }
                }
                else {
                    if (gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Undefined] || !(gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Male] || gender == gameanalytics.EGAGender[gameanalytics.EGAGender.Female])) {
                        GALogger.i("Validation fail - gender: Has to be 'male' or 'female'. Was: " + gender);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateBirthyear = function (birthYear) {
                if (birthYear < 0 || birthYear > 9999) {
                    GALogger.i("Validation fail - birthYear: Cannot be (null) or invalid range.");
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
            return GADevice;
        }());
        GADevice.sdkWrapperVersion = "javascript 3.0.0";
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
            return TimedBlock;
        }());
        TimedBlock.idCounter = 0;
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
            return GAStore;
        }());
        GAStore.instance = new GAStore();
        GAStore.MaxNumberOfEntries = 2000;
        GAStore.KeyPrefix = "GA::";
        GAStore.EventsStoreKey = "ga_event";
        GAStore.SessionsStoreKey = "ga_session";
        GAStore.ProgressionStoreKey = "ga_progression";
        GAStore.ItemsStoreKey = "ga_items";
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
                var currentSdkConfig = GAState.getSdkConfig();
                if (currentSdkConfig["enabled"] && currentSdkConfig["enabled"] == "false") {
                    return false;
                }
                else if (!GAState.instance.initAuthorized) {
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
                var index = GAState.instance.commandCenterListeners.indexOf(listener);
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
                var configurations = sdkConfig["configurations"];
                if (configurations) {
                    for (var i = 0; i < configurations.length; ++i) {
                        var configuration = configurations[i];
                        if (configuration) {
                            var key = configuration["key"];
                            var value = configuration["value"];
                            var start_ts = configuration["start"] ? configuration["start"] : Number.MIN_VALUE;
                            var end_ts = configuration["end"] ? configuration["end"] : Number.MAX_VALUE;
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
            return GAState;
        }());
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
            return SdkErrorTask;
        }());
        SdkErrorTask.MaxCount = 10;
        SdkErrorTask.countMap = {};
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
                this.hostName = "api.gameanalytics.com";
                this.version = "v2";
                this.baseUrl = this.protocol + "://" + this.hostName + "/" + this.version;
                this.initializeUrlPath = "init";
                this.eventsUrlPath = "events";
                this.useGzip = false;
            }
            GAHTTPApi.prototype.requestInit = function (callback) {
                var gameKey = GAState.getGameKey();
                var url = this.baseUrl + "/" + gameKey + "/" + this.initializeUrlPath;
                url = "https://rubick.gameanalytics.com/v2/command_center?game_key=" + gameKey + "&interval_seconds=1000000";
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
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
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
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null);
                    return;
                }
                if (requestJsonDict == null) {
                    GALogger.d("Failed Init Call. Json decoding failed");
                    callback(http.EGAHTTPApiResponse.JsonDecodeFailed, null);
                    return;
                }
                if (requestResponseEnum === http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                    callback(requestResponseEnum, null);
                    return;
                }
                var validatedInitValues = GAValidator.validateAndCleanInitRequestResponse(requestJsonDict);
                if (!validatedInitValues) {
                    callback(http.EGAHTTPApiResponse.BadResponse, null);
                    return;
                }
                callback(http.EGAHTTPApiResponse.Ok, validatedInitValues);
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
            return GAHTTPApi;
        }());
        GAHTTPApi.instance = new GAHTTPApi();
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
            return GAEvents;
        }());
        GAEvents.instance = new GAEvents();
        GAEvents.CategorySessionStart = "user";
        GAEvents.CategorySessionEnd = "session_end";
        GAEvents.CategoryDesign = "design";
        GAEvents.CategoryBusiness = "business";
        GAEvents.CategoryProgression = "progression";
        GAEvents.CategoryResource = "resource";
        GAEvents.CategoryError = "error";
        GAEvents.MaxEventCount = 500;
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
            return GAThreading;
        }());
        GAThreading.instance = new GAThreading();
        GAThreading.ThreadWaitTimeInMs = 1000;
        GAThreading.ProcessEventsIntervalInSeconds = 8.0;
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
            if (GAState.getUseManualSessionHandling()) {
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
            if (GAState.getUseManualSessionHandling()) {
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
            GAHTTPApi.instance.requestInit(GameAnalytics.startNewSessionCallback);
        };
        GameAnalytics.startNewSessionCallback = function (initResponse, initResponseDict) {
            if (initResponse === EGAHTTPApiResponse.Ok && initResponseDict) {
                var timeOffsetSeconds = 0;
                if (initResponseDict["server_ts"]) {
                    var serverTs = initResponseDict["server_ts"];
                    timeOffsetSeconds = GAState.calculateServerTimeOffset(serverTs);
                }
                initResponseDict["time_offset"] = timeOffsetSeconds;
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
        return GameAnalytics;
    }());
    GameAnalytics.initTimedBlockId = -1;
    GameAnalytics.methodMap = {};
    gameanalytics.GameAnalytics = GameAnalytics;
})(gameanalytics || (gameanalytics = {}));
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy90aHJlYWRpbmcvVGltZWRCbG9jay50cyIsInNyYy90aHJlYWRpbmcvUHJpb3JpdHlRdWV1ZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2V2ZW50cy9HQUV2ZW50cy50cyIsInNyYy90aHJlYWRpbmcvR0FUaHJlYWRpbmcudHMiLCJzcmMvR2FtZUFuYWx5dGljcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFPLGFBQWEsQ0EwRG5CO0FBMURELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQVFYO0lBUkQsV0FBWSxnQkFBZ0I7UUFFeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFSVyxnQkFBZ0IsR0FBaEIsOEJBQWdCLEtBQWhCLDhCQUFnQixRQVEzQjtJQUVELElBQVksU0FLWDtJQUxELFdBQVksU0FBUztRQUVqQixtREFBYSxDQUFBO1FBQ2IseUNBQVEsQ0FBQTtRQUNSLDZDQUFVLENBQUE7SUFDZCxDQUFDLEVBTFcsU0FBUyxHQUFULHVCQUFTLEtBQVQsdUJBQVMsUUFLcEI7SUFFRCxJQUFZLG9CQU1YO0lBTkQsV0FBWSxvQkFBb0I7UUFFNUIseUVBQWEsQ0FBQTtRQUNiLGlFQUFTLENBQUE7UUFDVCx1RUFBWSxDQUFBO1FBQ1osK0RBQVEsQ0FBQTtJQUNaLENBQUMsRUFOVyxvQkFBb0IsR0FBcEIsa0NBQW9C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LGdCQUFnQixJQUFJLENBQUMsT0FBTyxDQUFDLGdCQUFnQixFQUFFLENBQUMsQ0FDcEQsQ0FBQztnQkFDRyxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FDVCxDQUFDO29CQUNHLFFBQVEsQ0FBQyxDQUFDLENBQUMsT0FBTyxHQUFHLDZCQUE2QixDQUFDLENBQUM7Z0JBQ3hELENBQUM7Z0JBQ0QsTUFBTSxDQUFDLEtBQUssQ0FBQztZQUNqQixDQUFDO1lBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQztRQUNoQixDQUFDO1FBQ0wsb0JBQUM7SUFBRCxDQXBzQkEsQUFvc0JDO0lBbHNCa0IsOEJBQWdCLEdBQVUsQ0FBQyxDQUFDLENBQUM7SUFDOUIsdUJBQVMsR0FBMkMsRUFBRSxDQUFDO0lBSDVELDJCQUFhLGdCQW9zQnpCLENBQUE7QUFDTCxDQUFDLEVBbnRCTSxhQUFhLEtBQWIsYUFBYSxRQW10Qm5CO0FBQ0QsYUFBYSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUNuQyxJQUFJLGFBQWEsR0FBRyxhQUFhLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyIsImZpbGUiOiJkaXN0L0dhbWVBbmFseXRpY3MuZGVidWcuanMiLCJzb3VyY2VzQ29udGVudCI6WyJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHlcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIERlYnVnID0gMSxcbiAgICAgICAgSW5mbyA9IDIsXG4gICAgICAgIFdhcm5pbmcgPSAzLFxuICAgICAgICBFcnJvciA9IDQsXG4gICAgICAgIENyaXRpY2FsID0gNVxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQUdlbmRlclxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgTWFsZSA9IDEsXG4gICAgICAgIEZlbWFsZSA9IDJcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FQcm9ncmVzc2lvblN0YXR1c1xuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgU3RhcnQgPSAxLFxuICAgICAgICBDb21wbGV0ZSA9IDIsXG4gICAgICAgIEZhaWwgPSAzXG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBUmVzb3VyY2VGbG93VHlwZVxuICAgIHtcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgU291cmNlID0gMSxcbiAgICAgICAgU2luayA9IDJcbiAgICB9XG5cbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVNka0Vycm9yVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICAgICAgUmVqZWN0ZWQgPSAxXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FIVFRQQXBpUmVzcG9uc2VcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gY2xpZW50XG4gICAgICAgICAgICBOb1Jlc3BvbnNlLFxuICAgICAgICAgICAgQmFkUmVzcG9uc2UsXG4gICAgICAgICAgICBSZXF1ZXN0VGltZW91dCwgLy8gNDA4XG4gICAgICAgICAgICBKc29uRW5jb2RlRmFpbGVkLFxuICAgICAgICAgICAgSnNvbkRlY29kZUZhaWxlZCxcbiAgICAgICAgICAgIC8vIHNlcnZlclxuICAgICAgICAgICAgSW50ZXJuYWxTZXJ2ZXJFcnJvcixcbiAgICAgICAgICAgIEJhZFJlcXVlc3QsIC8vIDQwMFxuICAgICAgICAgICAgVW5hdXRob3JpemVkLCAvLyA0MDFcbiAgICAgICAgICAgIFVua25vd25SZXNwb25zZUNvZGUsXG4gICAgICAgICAgICBPa1xuICAgICAgICB9XG4gICAgfVxufVxudmFyIEVHQUVycm9yU2V2ZXJpdHkgPSBnYW1lYW5hbHl0aWNzLkVHQUVycm9yU2V2ZXJpdHk7XG52YXIgRUdBR2VuZGVyID0gZ2FtZWFuYWx5dGljcy5FR0FHZW5kZXI7XG52YXIgRUdBUHJvZ3Jlc3Npb25TdGF0dXMgPSBnYW1lYW5hbHl0aWNzLkVHQVByb2dyZXNzaW9uU3RhdHVzO1xudmFyIEVHQVJlc291cmNlRmxvd1R5cGUgPSBnYW1lYW5hbHl0aWNzLkVHQVJlc291cmNlRmxvd1R5cGU7XG4iLCIvL0dBTE9HR0VSX1NUQVJUXG5tb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xuICAgIHtcbiAgICAgICAgZW51bSBFR0FMb2dnZXJNZXNzYWdlVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBFcnJvciA9IDAsXG4gICAgICAgICAgICBXYXJuaW5nID0gMSxcbiAgICAgICAgICAgIEluZm8gPSAyLFxuICAgICAgICAgICAgRGVidWcgPSAzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FMb2dnZXJcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUxvZ2dlciA9IG5ldyBHQUxvZ2dlcigpO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nVmVyYm9zZUVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGRlYnVnRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xuXG4gICAgICAgICAgICAvLyBGaWVsZHMgYW5kIHByb3BlcnRpZXM6IEVORFxuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kZWJ1Z0VuYWJsZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBTVEFSVFxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluZm9Mb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFZlcmJvc2VMb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiSW5mby9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB3KGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJXYXJuaW5nL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGUoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkVycm9yL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkluZm8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGQoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRGVidWcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh0eXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmc6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlb2YgY29uc29sZS5kZWJ1ZyA9PT0gXCJmdW5jdGlvblwiKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ldGhvZHM6IEVORFxuICAgICAgICB9XG4gICAgfVxufVxuLy9HQUxPR0dFUl9FTkRcbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB1dGlsaXRpZXNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FVdGlsaXRpZXNcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRIbWFjKGtleTpzdHJpbmcsIGRhdGE6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGVuY3J5cHRlZE1lc3NhZ2UgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KGRhdGEsIGtleSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ01hdGNoKHM6c3RyaW5nLCBwYXR0ZXJuOlJlZ0V4cCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighcyB8fCAhcGF0dGVybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF0dGVybi50ZXN0KHMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGpvaW5TdHJpbmdBcnJheSh2OkFycmF5PHN0cmluZz4sIGRlbGltaXRlcjpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwiXCI7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMCwgaWwgPSB2Lmxlbmd0aDsgaSA8IGlsOyBpKyspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoaSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSBkZWxpbWl0ZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IHZbaV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhcnJheTpBcnJheTxzdHJpbmc+LCBzZWFyY2g6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhcnJheS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGFycmF5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJyYXlbc10gPT09IHNlYXJjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBrZXlTdHI6c3RyaW5nID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlucHV0ID0gZW5jb2RlVVJJKGlucHV0KTtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIyID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG5cbiAgICAgICAgICAgICAgICAgICBlbmMxID0gY2hyMSA+PiAyO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSAoKGNocjEgJiAzKSA8PCA0KSB8IChjaHIyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSAoKGNocjIgJiAxNSkgPDwgMikgfCAoY2hyMyA+PiA2KTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gY2hyMyAmIDYzO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGlzTmFOKGNocjIpKVxuICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICBlbmMzID0gZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChpc05hTihjaHIzKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMxKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMyKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMzKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmM0KTtcbiAgICAgICAgICAgICAgICAgICBjaHIxID0gY2hyMiA9IGNocjMgPSAwO1xuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBlbmMyID0gZW5jMyA9IGVuYzQgPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gb3V0cHV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBvdXRwdXQ6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgY2hyMTpudW1iZXIsIGNocjI6bnVtYmVyLCBjaHIzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGVuYzE6bnVtYmVyLCBlbmMyOm51bWJlciwgZW5jMzpudW1iZXIsIGVuYzQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgaSA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyByZW1vdmUgYWxsIGNoYXJhY3RlcnMgdGhhdCBhcmUgbm90IEEtWiwgYS16LCAwLTksICssIC8sIG9yID1cbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0dGVzdCA9IC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZztcbiAgICAgICAgICAgICAgICBpZiAoYmFzZTY0dGVzdC5leGVjKGlucHV0KSkge1xuICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJUaGVyZSB3ZXJlIGludmFsaWQgYmFzZTY0IGNoYXJhY3RlcnMgaW4gdGhlIGlucHV0IHRleHQuIFZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGFyZSBBLVosIGEteiwgMC05LCAnKycsICcvJyxhbmQgJz0nLiBFeHBlY3QgZXJyb3JzIGluIGRlY29kaW5nLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5wdXQgPSBpbnB1dC5yZXBsYWNlKC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZywgXCJcIik7XG5cbiAgICAgICAgICAgICAgICBkb1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jMyA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IChlbmMxIDw8IDIpIHwgKGVuYzIgPj4gNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9ICgoZW5jMiAmIDE1KSA8PCA0KSB8IChlbmMzID4+IDIpO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSAoKGVuYzMgJiAzKSA8PCA2KSB8IGVuYzQ7XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjEpO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzMgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjIpO1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBpZiAoZW5jNCAhPSA2NCkge1xuICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArIFN0cmluZy5mcm9tQ2hhckNvZGUoY2hyMyk7XG4gICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gZGVjb2RlVVJJKG91dHB1dCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdGltZUludGVydmFsU2luY2UxOTcwKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBkYXRlOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBNYXRoLnJvdW5kKGRhdGUuZ2V0VGltZSgpIC8gMTAwMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlR3VpZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItXCIgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItNFwiICsgR0FVdGlsaXRpZXMuczQoKS5zdWJzdHIoMCwzKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzNCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKCgoMStNYXRoLnJhbmRvbSgpKSoweDEwMDAwKXwwKS50b1N0cmluZygxNikuc3Vic3RyaW5nKDEpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHZhbGlkYXRvcnNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FTZGtFcnJvclR5cGU7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVZhbGlkYXRvclxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGNhcnRUeXBlOnN0cmluZywgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbmN5XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGN1cnJlbmN5OiBDYW5ub3QgYmUgKG51bGwpIGFuZCBuZWVkIHRvIGJlIEEtWiwgMyBjaGFyYWN0ZXJzIGFuZCBpbiB0aGUgc3RhbmRhcmQgYXQgb3BlbmV4Y2hhbmdlcmF0ZXMub3JnLiBGYWlsZWQgY3VycmVuY3k6IFwiICsgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gZG8gbm90IHZhbGlkYXRlIGFtb3VudCAtIGludGVnZXIgaXMgbmV2ZXIgbnVsbCAhXG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjYXJ0VHlwZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhjYXJ0VHlwZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBjYXJ0VHlwZS4gQ2Fubm90IGJlIGFib3ZlIDMyIGxlbmd0aC4gU3RyaW5nOiBcIiArIGNhcnRUeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGxlbmd0aFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbVR5cGUgY2hhcnNcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtSWRcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1JZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkLiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1JZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtSWQ6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlLCBjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZywgYXZhaWxhYmxlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+LCBhdmFpbGFibGVJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxvd1R5cGUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBmbG93VHlwZTogSW52YWxpZCBmbG93IHR5cGUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghY3VycmVuY3kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBjdXJyZW5jeTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlQ3VycmVuY2llcywgY3VycmVuY3kpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IE5vdCBmb3VuZCBpbiBsaXN0IG9mIHByZS1kZWZpbmVkIGF2YWlsYWJsZSByZXNvdXJjZSBjdXJyZW5jaWVzLiBTdHJpbmc6IFwiICsgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghKGFtb3VudCA+IDApKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gYW1vdW50OiBGbG9hdCBhbW91bnQgY2Fubm90IGJlIDAgb3IgbmVnYXRpdmUuIFZhbHVlOiBcIiArIGFtb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFpdGVtVHlwZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1UeXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlSXRlbVR5cGVzLCBpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGl0ZW1UeXBlcy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1JZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgaXRlbUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxOnN0cmluZywgcHJvZ3Jlc3Npb24wMjpzdHJpbmcsIHByb2dyZXNzaW9uMDM6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IEludmFsaWQgcHJvZ3Jlc3Npb24gc3RhdHVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIE1ha2Ugc3VyZSBwcm9ncmVzc2lvbnMgYXJlIGRlZmluZWQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1xuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvbjAzICYmICEocHJvZ3Jlc3Npb24wMiB8fCAhcHJvZ3Jlc3Npb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAzIGZvdW5kIGJ1dCAwMSswMiBhcmUgaW52YWxpZC4gUHJvZ3Jlc3Npb24gbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswMy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAocHJvZ3Jlc3Npb24wMiAmJiAhcHJvZ3Jlc3Npb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogMDIgZm91bmQgYnV0IG5vdCAwMS4gUHJvZ3Jlc3Npb24gbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghcHJvZ3Jlc3Npb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogcHJvZ3Jlc3Npb24wMSBub3QgdmFsaWQuIFByb2dyZXNzaW9ucyBtdXN0IGJlIHNldCBhcyBlaXRoZXIgMDEsIDAxKzAyIG9yIDAxKzAyKzAzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJvZ3Jlc3Npb24wMSAocmVxdWlyZWQpXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChwcm9ncmVzc2lvbjAxLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMiwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDI6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMikpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDI6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gcHJvZ3Jlc3Npb24wM1xuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChwcm9ncmVzc2lvbjAzLCB0cnVlKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMzogQ2Fubm90IGJlIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAzKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMzogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURlc2lnbkV2ZW50KGV2ZW50SWQ6c3RyaW5nLCB2YWx1ZTpudW1iZXIpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50SWRMZW5ndGgoZXZlbnRJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZGVzaWduIGV2ZW50IC0gZXZlbnRJZDogQ2Fubm90IGJlIChudWxsKSBvciBlbXB0eS4gT25seSA1IGV2ZW50IHBhcnRzIGFsbG93ZWQgc2VwZXJhdGVkIGJ5IDouIEVhY2ggcGFydCBuZWVkIHRvIGJlIDMyIGNoYXJhY3RlcnMgb3IgbGVzcy4gU3RyaW5nOiBcIiArIGV2ZW50SWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBOb24gdmFsaWQgY2hhcmFjdGVycy4gT25seSBhbGxvd2VkIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWx1ZTogYWxsb3cgMCwgbmVnYXRpdmUgYW5kIG5pbCAobm90IHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5LCBtZXNzYWdlOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoc2V2ZXJpdHkgPT0gRUdBRXJyb3JTZXZlcml0eS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBzZXZlcml0eTogU2V2ZXJpdHkgd2FzIHVuc3VwcG9ydGVkIHZhbHVlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlTG9uZ1N0cmluZyhtZXNzYWdlLCB0cnVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIG1lc3NhZ2U6IE1lc3NhZ2UgY2Fubm90IGJlIGFib3ZlIDgxOTIgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTZGtFcnJvckV2ZW50KGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZywgdHlwZTpFR0FTZGtFcnJvclR5cGUpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlS2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAodHlwZSA9PT0gRUdBU2RrRXJyb3JUeXBlLlVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBzZGsgZXJyb3IgZXZlbnQgLSB0eXBlOiBUeXBlIHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVLZXlzKGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZUtleSwgL15bQS16MC05XXszMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZ2FtZVNlY3JldCwgL15bQS16MC05XXs0MH0kLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGN1cnJlbmN5LCAvXltBLVpdezN9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydExlbmd0aChldmVudFBhcnQ6c3RyaW5nLCBhbGxvd051bGw6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOdWxsICYmICFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50UGFydClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoZXZlbnRQYXJ0Lmxlbmd0aCA+IDY0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoZXZlbnRQYXJ0OnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGV2ZW50UGFydCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZExlbmd0aChldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXlteOl17MSw2NH0oPzo6W146XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudElkQ2hhcmFjdGVycyhldmVudElkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSg6W0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9KXswLDR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShpbml0UmVzcG9uc2U6e1trZXk6c3RyaW5nXTogYW55fSk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBtYWtlIHN1cmUgd2UgaGF2ZSBhIHZhbGlkIGRpY3RcbiAgICAgICAgICAgICAgICBpZiAoaW5pdFJlc3BvbnNlID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIG5vIHJlc3BvbnNlIGRpY3Rpb25hcnkuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlbmFibGVkIGZpZWxkXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiZW5hYmxlZFwiXSA9IGluaXRSZXNwb25zZVtcImVuYWJsZWRcIl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2VuYWJsZWQnIGZpZWxkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgc2VydmVyX3RzXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyVHNOdW1iZXI6bnVtYmVyID0gaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyVHNOdW1iZXIgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wic2VydmVyX3RzXCJdID0gc2VydmVyVHNOdW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdmFsdWUgaW4gJ3NlcnZlcl90cycgZmllbGQuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnc2VydmVyX3RzJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY29uZmlndXJhdGlvbnMgZmllbGRcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uczphbnlbXSA9IGluaXRSZXNwb25zZVtcImNvbmZpZ3VyYXRpb25zXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wiY29uZmlndXJhdGlvbnNcIl0gPSBjb25maWd1cmF0aW9ucztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnY29uZmlndXJhdGlvbnMnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImNvbmZpZ3VyYXRpb25zXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wiY29uZmlndXJhdGlvbnNcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHZhbGlkYXRlZERpY3Q7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCdWlsZChidWlsZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNob3J0U3RyaW5nKGJ1aWxkLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrV3JhcHBlclZlcnNpb24od3JhcHBlclZlcnNpb246c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2god3JhcHBlclZlcnNpb24sIC9eKHVuaXR5fHVucmVhbHxnYW1lbWFrZXJ8Y29jb3MyZHxjb25zdHJ1Y3R8ZGVmb2xkKSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRW5naW5lVmVyc2lvbihlbmdpbmVWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWVuZ2luZVZlcnNpb24gfHwgIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGVuZ2luZVZlcnNpb24sIC9eKHVuaXR5fHVucmVhbHxnYW1lbWFrZXJ8Y29jb3MyZHxjb25zdHJ1Y3R8ZGVmb2xkKSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlVXNlcklkKHVJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVN0cmluZyh1SWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSB1c2VyIGlkOiBpZCBjYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNob3J0U3RyaW5nKHNob3J0U3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5IG9yIG5pbFxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzaG9ydFN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghc2hvcnRTdHJpbmcgfHwgc2hvcnRTdHJpbmcubGVuZ3RoID4gMzIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU3RyaW5nKHM6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIXMgfHwgcy5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVMb25nU3RyaW5nKGxvbmdTdHJpbmc6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhbG9uZ1N0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghbG9uZ1N0cmluZyB8fCBsb25nU3RyaW5nLmxlbmd0aCA+IDgxOTIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvblR5cGU6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjb25uZWN0aW9uVHlwZSwgL14od3dhbnx3aWZpfGxhbnxvZmZsaW5lKSQvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnMoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwiY3VzdG9tIGRpbWVuc2lvbnNcIiwgY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCA2NCwgZmFsc2UsIFwicmVzb3VyY2UgY3VycmVuY2llc1wiLCByZXNvdXJjZUN1cnJlbmNpZXMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nIGZvciByZWdleFxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzb3VyY2VDdXJyZW5jaWVzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChyZXNvdXJjZUN1cnJlbmNpZXNbaV0sIC9eW0EtWmEtel0rJC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwicmVzb3VyY2UgY3VycmVuY2llcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBjdXJyZW5jeSBjYW4gb25seSBiZSBBLVosIGEtei4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUN1cnJlbmNpZXNbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJyZXNvdXJjZSBpdGVtIHR5cGVzXCIsIHJlc291cmNlSXRlbVR5cGVzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHJlc291cmNlSXRlbVR5cGUgZm9yIGV2ZW50cGFydCB2YWxpZGF0aW9uXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXNvdXJjZUl0ZW1UeXBlcy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHJlc291cmNlSXRlbVR5cGVzW2ldKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcInJlc291cmNlIGl0ZW0gdHlwZXMgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgcmVzb3VyY2UgaXRlbSB0eXBlIGNhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmcgd2FzOiBcIiArIHJlc291cmNlSXRlbVR5cGVzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAxKGRpbWVuc2lvbjAxOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAxKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24wMjpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uMDM6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKG1heENvdW50Om51bWJlciwgbWF4U3RyaW5nTGVuZ3RoOm51bWJlciwgYWxsb3dOb1ZhbHVlczpib29sZWFuLCBsb2dUYWc6c3RyaW5nLCBhcnJheU9mU3RyaW5nczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhcnJheVRhZzpzdHJpbmcgPSBsb2dUYWc7XG5cbiAgICAgICAgICAgICAgICAvLyB1c2UgYXJyYXlUYWcgdG8gYW5ub3RhdGUgd2FybmluZyBsb2dcbiAgICAgICAgICAgICAgICBpZiAoIWFycmF5VGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYXJyYXlUYWcgPSBcIkFycmF5XCI7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoIWFycmF5T2ZTdHJpbmdzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgYmUgbnVsbC4gXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHlcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOb1ZhbHVlcyA9PSBmYWxzZSAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIGVtcHR5LiBcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBleGNlZWRpbmcgbWF4IGNvdW50XG4gICAgICAgICAgICAgICAgaWYgKG1heENvdW50ID4gMCAmJiBhcnJheU9mU3RyaW5ncy5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGV4Y2VlZCBcIiArIG1heENvdW50ICsgXCIgdmFsdWVzLiBJdCBoYXMgXCIgKyBhcnJheU9mU3RyaW5ncy5sZW5ndGggKyBcIiB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmdcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5T2ZTdHJpbmdzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHN0cmluZ0xlbmd0aDpudW1iZXIgPSAhYXJyYXlPZlN0cmluZ3NbaV0gPyAwIDogYXJyYXlPZlN0cmluZ3NbaV0ubGVuZ3RoO1xuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eSAobm90IGFsbG93ZWQpXG4gICAgICAgICAgICAgICAgICAgIGlmIChzdHJpbmdMZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogY29udGFpbmVkIGFuIGVtcHR5IHN0cmluZy4gQXJyYXk9XCIgKyBKU09OLnN0cmluZ2lmeShhcnJheU9mU3RyaW5ncykpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZXhjZWVkaW5nIG1heCBsZW5ndGhcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1heFN0cmluZ0xlbmd0aCA+IDAgJiYgc3RyaW5nTGVuZ3RoID4gbWF4U3RyaW5nTGVuZ3RoKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgc3RyaW5nIGV4Y2VlZGVkIG1heCBhbGxvd2VkIGxlbmd0aCAod2hpY2ggaXM6IFwiICsgbWF4U3RyaW5nTGVuZ3RoICsgXCIpLiBTdHJpbmcgd2FzOiBcIiArIGFycmF5T2ZTdHJpbmdzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVN0cmluZyhmYWNlYm9va0lkLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZmFjZWJvb2sgaWQ6IGlkIGNhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlR2VuZGVyKGdlbmRlcjphbnkpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoaXNOYU4oTnVtYmVyKEVHQUdlbmRlcltnZW5kZXJdKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZ2VuZGVyID09IEVHQUdlbmRlci5VbmRlZmluZWQgfHwgIShnZW5kZXIgPT0gRUdBR2VuZGVyLk1hbGUgfHwgZ2VuZGVyID09IEVHQUdlbmRlci5GZW1hbGUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZ2VuZGVyOiBIYXMgdG8gYmUgJ21hbGUnIG9yICdmZW1hbGUnLiBXYXM6IFwiICsgZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZ2VuZGVyID09IEVHQUdlbmRlcltFR0FHZW5kZXIuVW5kZWZpbmVkXSB8fCAhKGdlbmRlciA9PSBFR0FHZW5kZXJbRUdBR2VuZGVyLk1hbGVdIHx8IGdlbmRlciA9PSBFR0FHZW5kZXJbRUdBR2VuZGVyLkZlbWFsZV0pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZ2VuZGVyOiBIYXMgdG8gYmUgJ21hbGUnIG9yICdmZW1hbGUnLiBXYXM6IFwiICsgZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJpcnRoeWVhcihiaXJ0aFllYXI6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChiaXJ0aFllYXIgPCAwIHx8IGJpcnRoWWVhciA+IDk5OTkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYmlydGhZZWFyOiBDYW5ub3QgYmUgKG51bGwpIG9yIGludmFsaWQgcmFuZ2UuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ2xpZW50VHMoY2xpZW50VHM6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChjbGllbnRUcyA8ICgtNDI5NDk2NzI5NSsxKSB8fCBjbGllbnRUcyA+ICg0Mjk0OTY3Mjk1LTEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBkZXZpY2VcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZhbHVlVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmFsdWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZhbHVlOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZhbHVlID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmVyc2lvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihuYW1lOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSB2ZXJzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBRGV2aWNlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IHNka1dyYXBwZXJWZXJzaW9uOnN0cmluZyA9IFwiamF2YXNjcmlwdCAzLjAuMFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgb3NWZXJzaW9uUGFpcjpOYW1lVmVyc2lvbiA9IEdBRGV2aWNlLm1hdGNoSXRlbShbXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnBsYXRmb3JtLFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci51c2VyQWdlbnQsXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLmFwcFZlcnNpb24sXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnZlbmRvclxuICAgICAgICAgICAgXS5qb2luKCcgJyksIFtcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIndpbmRvd3NfcGhvbmVcIiwgXCJXaW5kb3dzIFBob25lXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzXCIsIFwiV2luXCIsIFwiTlRcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQYWRcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQb2RcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImFuZHJvaWRcIiwgXCJBbmRyb2lkXCIsIFwiQW5kcm9pZFwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImJsYWNrQmVycnlcIiwgXCJCbGFja0JlcnJ5XCIsIFwiL1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIm1hY19vc3hcIiwgXCJNYWNcIiwgXCJPUyBYXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwidGl6ZW5cIiwgXCJUaXplblwiLCBcIlRpemVuXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwibGludXhcIiwgXCJMaW51eFwiLCBcInJ2XCIpXG4gICAgICAgICAgICBdKTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBidWlsZFBsYXRmb3JtOnN0cmluZyA9IEdBRGV2aWNlLnJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1vZGVsOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1vZGVsKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1hbnVmYWN0dXJlcjpzdHJpbmcgPSBHQURldmljZS5nZXREZXZpY2VNYW51ZmFjdHVyZXIoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgb3NWZXJzaW9uOnN0cmluZyA9IEdBRGV2aWNlLmdldE9TVmVyc2lvblN0cmluZygpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBicm93c2VyVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRCcm93c2VyVmVyc2lvblN0cmluZygpO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY29ubmVjdGlvblR5cGU6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWF4U2FmZUludGVnZXI6bnVtYmVyID0gTWF0aC5wb3coMiwgNTMpIC0gMTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB0b3VjaCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uuc2RrV3JhcHBlclZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29ubmVjdGlvblR5cGUoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihuYXZpZ2F0b3Iub25MaW5lKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSA9PT0gXCJpb3NcIiB8fCBHQURldmljZS5idWlsZFBsYXRmb3JtID09PSBcImFuZHJvaWRcIilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcInd3YW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gXCJsYW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBUT0RPOiBEZXRlY3Qgd2lmaSB1c2FnZVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwib2ZmbGluZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0T1NWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5idWlsZFBsYXRmb3JtICsgXCIgXCIgKyBHQURldmljZS5vc1ZlcnNpb25QYWlyLnZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5vc1ZlcnNpb25QYWlyLm5hbWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEJyb3dzZXJWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB1YTpzdHJpbmcgPSBuYXZpZ2F0b3IudXNlckFnZW50O1xuICAgICAgICAgICAgICAgIHZhciB0ZW06UmVnRXhwTWF0Y2hBcnJheTtcbiAgICAgICAgICAgICAgICB2YXIgTTpSZWdFeHBNYXRjaEFycmF5ID0gdWEubWF0Y2goLyhvcGVyYXxjaHJvbWV8c2FmYXJpfGZpcmVmb3h8dWJyb3dzZXJ8bXNpZXx0cmlkZW50fGZiYXYoPz1cXC8pKVxcLz9cXHMqKFxcZCspL2kpIHx8IFtdO1xuXG4gICAgICAgICAgICAgICAgaWYoTS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiaW9zXCIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndlYmtpdF9cIiArIEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKC90cmlkZW50L2kudGVzdChNWzFdKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IC9cXGJydlsgOl0rKFxcZCspL2cuZXhlYyh1YSkgfHwgW107XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAnSUUgJyArICh0ZW1bMV0gfHwgJycpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0gPT09ICdDaHJvbWUnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGVtID0gdWEubWF0Y2goL1xcYihPUFJ8RWRnZXxVQnJvd3NlcilcXC8oXFxkKykvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYodGVtIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRlbS5zbGljZSgxKS5qb2luKCcgJykucmVwbGFjZSgnT1BSJywgJ09wZXJhJykucmVwbGFjZSgnVUJyb3dzZXInLCAnVUMnKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoTVsxXSAmJiBNWzFdLnRvTG93ZXJDYXNlKCkgPT09ICdmYmF2JylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIE1bMV0gPSBcImZhY2Vib29rXCI7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoTVsyXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZmFjZWJvb2sgXCIgKyBNWzJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIE1TdHJpbmc6c3RyaW5nW10gPSBNWzJdPyBbTVsxXSwgTVsyXV06IFtuYXZpZ2F0b3IuYXBwTmFtZSwgbmF2aWdhdG9yLmFwcFZlcnNpb24sICctPyddO1xuXG4gICAgICAgICAgICAgICAgaWYoKHRlbSA9IHVhLm1hdGNoKC92ZXJzaW9uXFwvKFxcZCspL2kpKSAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVN0cmluZy5zcGxpY2UoMSwgMSwgdGVtWzFdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gTVN0cmluZy5qb2luKCcgJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTW9kZWwoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwidW5rbm93blwiO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcInVua25vd25cIjtcblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1hdGNoSXRlbShhZ2VudDpzdHJpbmcsIGRhdGE6QXJyYXk8TmFtZVZhbHVlVmVyc2lvbj4pOk5hbWVWZXJzaW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpOYW1lVmVyc2lvbiA9IG5ldyBOYW1lVmVyc2lvbihcInVua25vd25cIiwgXCIwLjAuMFwiKTtcblxuICAgICAgICAgICAgICAgIHZhciBpOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGo6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgcmVnZXg6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciByZWdleHY6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaDpib29sZWFuO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaGVzOlJlZ0V4cE1hdGNoQXJyYXk7XG4gICAgICAgICAgICAgICAgdmFyIG1hdGhjZXNSZXN1bHQ6c3RyaW5nO1xuICAgICAgICAgICAgICAgIHZhciB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVnZXggPSBuZXcgUmVnRXhwKGRhdGFbaV0udmFsdWUsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgIG1hdGNoID0gcmVnZXgudGVzdChhZ2VudCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVnZXh2ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZlcnNpb24gKyAnWy0gLzo7XShbXFxcXGQuX10rKScsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBtYXRjaGVzID0gYWdlbnQubWF0Y2gocmVnZXh2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gPSAnJztcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzWzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWF0aGNlc1Jlc3VsdCA9IG1hdGNoZXNbMV07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGhjZXNSZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1hdGNoZXNBcnJheTpzdHJpbmdbXSA9IG1hdGhjZXNSZXN1bHQuc3BsaXQoL1suX10rLyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gMDsgaiA8IE1hdGgubWluKG1hdGNoZXNBcnJheS5sZW5ndGgsIDMpOyBqICs9IDEpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uICs9IG1hdGNoZXNBcnJheVtqXSArIChqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMykgLSAxID8gJy4nIDogJycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJzAuMC4wJztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lm5hbWUgPSBkYXRhW2ldLm5hbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQudmVyc2lvbiA9IHZlcnNpb247XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICDCoMKgwqDCoMKgwqDCoMKgfVxuICAgICAgICAgICAgwqDCoMKgwqB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgZXhwb3J0IGNsYXNzIFRpbWVkQmxvY2tcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGRlYWRsaW5lOkRhdGU7XG4gICAgICAgICAgICBwdWJsaWMgYmxvY2s6KCkgPT4gdm9pZDtcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBpZDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgaWdub3JlOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgYXN5bmM6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBydW5uaW5nOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBpZENvdW50ZXI6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKGRlYWRsaW5lOkRhdGUpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWFkbGluZSA9IGRlYWRsaW5lO1xuICAgICAgICAgICAgICAgIHRoaXMuaWdub3JlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgdGhpcy5hc3luYyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHRoaXMucnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHRoaXMuaWQgPSArK1RpbWVkQmxvY2suaWRDb3VudGVyO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBJQ29tcGFyZXI8VD5cbiAgICAgICAge1xuICAgICAgICAgICAgY29tcGFyZSh4OlQsIHk6VCk6IG51bWJlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBQcmlvcml0eVF1ZXVlPFRJdGVtPlxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgX3N1YlF1ZXVlczp7W2tleTpudW1iZXJdOiBBcnJheTxUSXRlbT59O1xuICAgICAgICAgICAgcHVibGljIF9zb3J0ZWRLZXlzOkFycmF5PG51bWJlcj47XG4gICAgICAgICAgICBwcml2YXRlIGNvbXBhcmVyOklDb21wYXJlcjxudW1iZXI+O1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IocHJpb3JpdHlDb21wYXJlcjpJQ29tcGFyZXI8bnVtYmVyPilcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmNvbXBhcmVyID0gcHJpb3JpdHlDb21wYXJlcjtcbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXMgPSB7fTtcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzID0gW107XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBlbnF1ZXVlKHByaW9yaXR5Om51bWJlciwgaXRlbTpUSXRlbSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih0aGlzLl9zb3J0ZWRLZXlzLmluZGV4T2YocHJpb3JpdHkpID09PSAtMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYWRkUXVldWVPZlByaW9yaXR5KHByaW9yaXR5KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXNbcHJpb3JpdHldLnB1c2goaXRlbSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYWRkUXVldWVPZlByaW9yaXR5KHByaW9yaXR5Om51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnB1c2gocHJpb3JpdHkpO1xuICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMuc29ydCgoeDpudW1iZXIsIHk6bnVtYmVyKSA9PiB0aGlzLmNvbXBhcmVyLmNvbXBhcmUoeCwgeSkpO1xuICAgICAgICAgICAgICAgIHRoaXMuX3N1YlF1ZXVlc1twcmlvcml0eV0gPSBbXTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHBlZWsoKTogVEl0ZW1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih0aGlzLmhhc0l0ZW1zKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5fc3ViUXVldWVzW3RoaXMuX3NvcnRlZEtleXNbMF1dWzBdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgcXVldWUgaXMgZW1wdHlcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgaGFzSXRlbXMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLl9zb3J0ZWRLZXlzLmxlbmd0aCA+IDA7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBkZXF1ZXVlKCk6IFRJdGVtXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5oYXNJdGVtcygpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuZGVxdWV1ZUZyb21IaWdoUHJpb3JpdHlRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgcXVldWUgaXMgZW1wdHlcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGRlcXVldWVGcm9tSGlnaFByaW9yaXR5UXVldWUoKTogVEl0ZW1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RLZXk6bnVtYmVyID0gdGhpcy5fc29ydGVkS2V5c1swXTtcbiAgICAgICAgICAgICAgICB2YXIgbmV4dEl0ZW06VEl0ZW0gPSB0aGlzLl9zdWJRdWV1ZXNbZmlyc3RLZXldLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5fc3ViUXVldWVzW2ZpcnN0S2V5XS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSB0aGlzLl9zdWJRdWV1ZXNbZmlyc3RLZXldO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBuZXh0SXRlbTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdG9yZVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVN0b3JlQXJnc09wZXJhdG9yXG4gICAgICAgIHtcbiAgICAgICAgICAgIEVxdWFsLFxuICAgICAgICAgICAgTGVzc09yRXF1YWwsXG4gICAgICAgICAgICBOb3RFcXVhbFxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgRXZlbnRzID0gMCxcbiAgICAgICAgICAgIFNlc3Npb25zID0gMSxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uID0gMlxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdG9yZSA9IG5ldyBHQVN0b3JlKCk7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzdG9yYWdlQXZhaWxhYmxlOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhOdW1iZXJPZkVudHJpZXM6bnVtYmVyID0gMjAwMDtcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbnNTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0b3JlSXRlbXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgS2V5UHJlZml4OnN0cmluZyA9IFwiR0E6OlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRXZlbnRzU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9ldmVudFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbnNTdG9yZUtleTpzdHJpbmcgPSBcImdhX3Nlc3Npb25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFByb2dyZXNzaW9uU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9wcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgSXRlbXNTdG9yZUtleTpzdHJpbmcgPSBcImdhX2l0ZW1zXCI7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBsb2NhbFN0b3JhZ2UgPT09ICdvYmplY3QnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScsICd5ZXMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdG9yYWdlIGlzIGF2YWlsYWJsZT86IFwiICsgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JhZ2VBdmFpbGFibGUoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlLmxlbmd0aCArIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZS5sZW5ndGggPiBHQVN0b3JlLk1heE51bWJlck9mRW50cmllcztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZWxlY3Qoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10sIHNvcnQ6Ym9vbGVhbiA9IGZhbHNlLCBtYXhDb3VudDpudW1iZXIgPSAwKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBhZGQ6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBhcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighYWRkKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoYWRkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQucHVzaChlbnRyeSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihzb3J0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnNvcnQoKGE6e1trZXk6c3RyaW5nXTogYW55fSwgYjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGFbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKSAtIChiW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYobWF4Q291bnQgPiAwICYmIHJlc3VsdC5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHJlc3VsdC5zbGljZSgwLCBtYXhDb3VudCArIDEpXG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGUoc3RvcmU6RUdBU3RvcmUsIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgYW55XT4sIHdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgd2hlcmVBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gd2hlcmVBcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZih1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBzZXRBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzRW50cnk6W3N0cmluZywgYW55XSA9IHNldEFyZ3Nbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc2V0QXJnc0VudHJ5WzBdXSA9IHNldEFyZ3NFbnRyeVsxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlbGV0ZShzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGRlbDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFkZWwpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihkZWwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5zcGxpY2UoaSwgMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAtLWk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5zZXJ0KHN0b3JlOkVHQVN0b3JlLCBuZXdFbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9LCByZXBsYWNlOmJvb2xlYW4gPSBmYWxzZSwgcmVwbGFjZUtleTpzdHJpbmcgPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVwbGFjZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlS2V5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgcmVwbGFjZWQ6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVtyZXBsYWNlS2V5XSA9PSBuZXdFbnRyeVtyZXBsYWNlS2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gbmV3RW50cnkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzXSA9IG5ld0VudHJ5W3NdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXBsYWNlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighcmVwbGFjZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNhdmUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlN0b3JhZ2UgaXMgbm90IGF2YWlsYWJsZSwgY2Fubm90IHNhdmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlNlc3Npb25zU3RvcmVLZXksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSkpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuSXRlbXNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgbG9hZCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3QgbG9hZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5FdmVudHNTdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2V2ZW50cycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdzZXNzaW9ucycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ3Byb2dyZXNzaW9uJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcyA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnaXRlbXMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJdGVtKGtleTpzdHJpbmcsIHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLktleVByZWZpeCArIGtleTtcblxuICAgICAgICAgICAgICAgIGlmKCF2YWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGtleVdpdGhQcmVmaXggaW4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBkZWxldGUgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRJdGVtKGtleTpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLktleVByZWZpeCArIGtleTtcbiAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gYXMgc3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldFN0b3JlKHN0b3JlOkVHQVN0b3JlKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2goc3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLkV2ZW50czpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlNlc3Npb25zOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5Qcm9ncmVzc2lvbjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJHQVN0b3JlLmdldFN0b3JlKCk6IENhbm5vdCBmaW5kIHN0b3JlOiBcIiArIHN0b3JlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0YXRlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYW1lYW5hbHl0aWNzLmRldmljZS5HQURldmljZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdGF0ZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNka0Vycm9yOnN0cmluZyA9IFwic2RrX2Vycm9yXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVDpudW1iZXIgPSA1MDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEg6bnVtYmVyID0gNjQ7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIOm51bWJlciA9IDI1NjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0YXRlID0gbmV3IEdBU3RhdGUoKTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgdXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0VXNlcklkKHVzZXJJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQgPSB1c2VySWQ7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBpZGVudGlmaWVyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SWRlbnRpZmllcigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzSW5pdGlhbGl6ZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbml0aWFsaXplZCh2YWx1ZTpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25TdGFydDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25TdGFydCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB0cmFuc2FjdGlvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFRyYW5zYWN0aW9uTnVtKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvbklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbklkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAzOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lS2V5OnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZUtleSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVTZWNyZXQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lU2VjcmV0KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMzpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGJ1aWxkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QnVpbGQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEJ1aWxkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBidWlsZCB2ZXJzaW9uOiBcIiArIHZhbHVlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZmFjZWJvb2tJZDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGdlbmRlcjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGJpcnRoWWVhcjpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnQ2FjaGVkOntba2V5OnN0cmluZ106IGFueX07XG4gICAgICAgICAgICBwcml2YXRlIGNvbmZpZ3VyYXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgY29tbWFuZENlbnRlcklzUmVhZHk6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgY29tbWFuZENlbnRlckxpc3RlbmVyczpBcnJheTx7IG9uQ29tbWFuZENlbnRlclVwZGF0ZWQ6KCkgPT4gdm9pZCB9PiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIGluaXRBdXRob3JpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgY2xpZW50U2VydmVyVGltZU9mZnNldDpudW1iZXI7XG5cbiAgICAgICAgICAgIHByaXZhdGUgZGVmYXVsdFVzZXJJZDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHNldERlZmF1bHRJZCh2YWx1ZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWZhdWx0VXNlcklkID0gIXZhbHVlID8gXCJcIiA6IHZhbHVlO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldERlZmF1bHRJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5kZWZhdWx0VXNlcklkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnRGVmYXVsdDp7W2tleTpzdHJpbmddOiBzdHJpbmd9ID0ge307XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZGtDb25maWcoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0O1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqc29uIGluIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZmlyc3QgJiYgY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWc7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmlyc3Q7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGpzb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0ID0ganNvbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihmaXJzdCAmJiBjb3VudCA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0RlZmF1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25Ucmllczp7W2tleTpzdHJpbmddOiBudW1iZXJ9ID0ge307XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IERlZmF1bHRVc2VySWRLZXk6c3RyaW5nID0gXCJkZWZhdWx0X3VzZXJfaWRcIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbk51bUtleTpzdHJpbmcgPSBcInNlc3Npb25fbnVtXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFRyYW5zYWN0aW9uTnVtS2V5OnN0cmluZyA9IFwidHJhbnNhY3Rpb25fbnVtXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBGYWNlYm9va0lkS2V5OnN0cmluZyA9IFwiZmFjZWJvb2tfaWRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEdlbmRlcktleTpzdHJpbmcgPSBcImdlbmRlclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQmlydGhZZWFyS2V5OnN0cmluZyA9IFwiYmlydGhfeWVhclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDFLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDJLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDNLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wM1wiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZGtDb25maWdDYWNoZWRLZXk6c3RyaW5nID0gXCJzZGtfY29uZmlnX2NhY2hlZFwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoY3VycmVudFNka0NvbmZpZ1tcImVuYWJsZWRcIl0gJiYgY3VycmVudFNka0NvbmZpZ1tcImVuYWJsZWRcIl0gPT0gXCJmYWxzZVwiKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDMoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkID0gZmFjZWJvb2tJZDtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5GYWNlYm9va0lkS2V5LCBmYWNlYm9va0lkKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGZhY2Vib29rIGlkOiBcIiArIGZhY2Vib29rSWQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEdlbmRlcihnZW5kZXI6RUdBR2VuZGVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyID0gaXNOYU4oTnVtYmVyKEVHQUdlbmRlcltnZW5kZXJdKSkgPyBFR0FHZW5kZXJbZ2VuZGVyXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCkgOiBFR0FHZW5kZXJbRUdBR2VuZGVyW2dlbmRlcl1dLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXksIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGdlbmRlcjogXCIgKyBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QmlydGhZZWFyKGJpcnRoWWVhcjpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5iaXJ0aFllYXIgPSBiaXJ0aFllYXI7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5LCBiaXJ0aFllYXIudG9TdHJpbmcoKSk7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBiaXJ0aCB5ZWFyOiBcIiArIGJpcnRoWWVhcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50U2Vzc2lvbk51bSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IHNlc3Npb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0cmFuc2FjdGlvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSB0cmFuc2FjdGlvbk51bUludDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJpZXM6bnVtYmVyID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXSA9IHRyaWVzO1xuXG4gICAgICAgICAgICAgICAgLy8gUGVyc2lzdFxuICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInByb2dyZXNzaW9uXCJdID0gcHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgdmFsdWVzW1widHJpZXNcIl0gPSB0cmllcztcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgdmFsdWVzLCB0cnVlLCBcInByb2dyZXNzaW9uXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIERlbGV0ZVxuICAgICAgICAgICAgICAgIHZhciBwYXJtczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBwYXJtcy5wdXNoKFtcInByb2dyZXNzaW9uXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBwcm9ncmVzc2lvbl0pO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlByb2dyZXNzaW9uLCBwYXJtcyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0S2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5ID0gZ2FtZUtleTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQgPSBnYW1lU2VjcmV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmcgPSBmbGFnO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgbWFudWFsIHNlc3Npb24gaGFuZGxpbmc6IFwiICsgZmxhZyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gUkVRVUlSRUQgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ2XCJdID0gMjtcbiAgICAgICAgICAgICAgICAvLyBVc2VyIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBDbGllbnQgVGltZXN0YW1wICh0aGUgYWRqdXN0ZWQgdGltZXN0YW1wKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2xpZW50X3RzXCJdID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSBtYWtlIChoYXJkY29kZWQgdG8gYXBwbGUpXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImRldmljZVwiXSA9IEdBRGV2aWNlLmRldmljZU1vZGVsO1xuICAgICAgICAgICAgICAgIC8vIEJyb3dzZXIgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnJvd3Nlcl92ZXJzaW9uXCJdID0gR0FEZXZpY2UuYnJvd3NlclZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBudW1iZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLlNlc3Npb25OdW1LZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uX3R5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gQ09ORElUSU9OQUwgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwIGJ1aWxkIHZlcnNpb24gKHVzZSBpZiBub3QgbmlsKVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJ1aWxkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBPUFRJT05BTCBjcm9zcy1zZXNzaW9uIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIGZhY2Vib29rIGlkIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbR0FTdGF0ZS5GYWNlYm9va0lkS2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuZmFjZWJvb2tJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gZ2VuZGVyIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkdlbmRlcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gYmlydGhfeWVhciAob3B0aW9uYWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkJpcnRoWWVhcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmJpcnRoWWVhcjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmdldElkZW50aWZpZXIoKTtcblxuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGluaXRBbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnRUc0FkanVzdGVkKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHNBZGp1c3RlZEludGVnZXI6bnVtYmVyID0gY2xpZW50VHMgKyBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQ7XG5cbiAgICAgICAgICAgICAgICBpZihHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUc0FkanVzdGVkSW50ZWdlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXNzaW9uSXNTdGFydGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQgIT0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2FjaGVJZGVudGlmaWVyKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UudXNlcklkO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiaWRlbnRpZmllciwge2NsZWFuOlwiICsgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyICsgXCJ9XCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZVBlcnNpc3RlZFN0YXRlcygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gZ2V0IGFuZCBleHRyYWN0IHN0b3JlZCBzdGF0ZXNcbiAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5sb2FkKCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGludG8gR0FTdGF0ZSBpbnN0YW5jZVxuICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZTpHQVN0YXRlID0gR0FTdGF0ZS5pbnN0YW5jZTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNldERlZmF1bHRJZChHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgOiBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCkpO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuU2Vzc2lvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkgIT0gbnVsbCA/IE51bWJlcihHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBjcm9zcyBzZXNzaW9uIHVzZXIgdmFsdWVzXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZmFjZWJvb2tJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXksIGluc3RhbmNlLmZhY2Vib29rSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5mYWNlYm9va0lkID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRmFjZWJvb2tJZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZmFjZWJvb2tJZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZhY2Vib29raWQgZm91bmQgaW4gREI6IFwiICsgaW5zdGFuY2UuZmFjZWJvb2tJZCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXksIGluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmdlbmRlciA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkdlbmRlcktleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkdlbmRlcktleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJnZW5kZXIgZm91bmQgaW4gREI6IFwiICsgaW5zdGFuY2UuZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmJpcnRoWWVhciAmJiBpbnN0YW5jZS5iaXJ0aFllYXIgIT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkJpcnRoWWVhcktleSwgaW5zdGFuY2UuYmlydGhZZWFyLnRvU3RyaW5nKCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5iaXJ0aFllYXIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5KSkgOiAwO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5iaXJ0aFllYXIgIT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImJpcnRoWWVhciBmb3VuZCBpbiBEQjogXCIgKyBpbnN0YW5jZS5iaXJ0aFllYXIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBkaW1lbnNpb24gc2V0dGluZ3NcbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMSBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDIgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAzIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBnZXQgY2FjaGVkIGluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkU3RyaW5nOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChzZGtDb25maWdDYWNoZWRTdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb246QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5Qcm9ncmVzc2lvbik7XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzdWx0c19nYV9wcm9ncmVzc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzdWx0c19nYV9wcm9ncmVzc2lvbi5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlc3VsdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gcmVzdWx0c19nYV9wcm9ncmVzc2lvbltpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1tyZXN1bHRbXCJwcm9ncmVzc2lvblwiXSBhcyBzdHJpbmddID0gcmVzdWx0W1widHJpZXNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHM6bnVtYmVyKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzOm51bWJlciA9IEdBVXRpbGl0aWVzLnRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXJ2ZXJUcyAtIGNsaWVudFRzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSk6IHtbaWQ6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6e1tpZDpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICBpZihmaWVsZHMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgICAgICBmb3IodmFyIGtleSBpbiBmaWVsZHMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZTphbnkgPSBmaWVsZHNba2V5XTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWtleSB8fCAhdmFsdWUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PVwiICsga2V5ICsgXCIsIHZhbHVlPVwiICsgdmFsdWUgK1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIFwiIGhhcyBiZWVuIG9taXR0ZWQgYmVjYXVzZSBpdHMga2V5IG9yIHZhbHVlIGlzIG51bGxcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmKGNvdW50IDwgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVnZXggPSBuZXcgUmVnRXhwKFwiXlthLXpBLVowLTlfXXsxLFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19LRVlfTEVOR1RIICsgXCJ9JFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChrZXksIHJlZ2V4KSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0eXBlID0gdHlwZW9mIHZhbHVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlID09PSBcInN0cmluZ1wiIHx8IHZhbHVlIGluc3RhbmNlb2YgU3RyaW5nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVBc1N0cmluZzpzdHJpbmcgPSB2YWx1ZSBhcyBzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHZhbHVlQXNTdHJpbmcubGVuZ3RoIDw9IEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSCAmJiB2YWx1ZUFzU3RyaW5nLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0W2tleV0gPSB2YWx1ZUFzU3RyaW5nO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PVwiICsga2V5ICsgXCIsIHZhbHVlPVwiICsgdmFsdWUgKyBcIiBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIHZhbHVlIGlzIGFuIGVtcHR5IHN0cmluZyBvciBleGNlZWRzIHRoZSBtYXggbnVtYmVyIG9mIGNoYXJhY3RlcnMgKFwiICsgR0FTdGF0ZS5NQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIICsgXCIpXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UgaWYodHlwZSA9PT0gXCJudW1iZXJcIiB8fCB2YWx1ZSBpbnN0YW5jZW9mIE51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlQXNOdW1iZXI6bnVtYmVyID0gdmFsdWUgYXMgbnVtYmVyO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRba2V5XSA9IHZhbHVlQXNOdW1iZXI7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PVwiICsga2V5ICsgXCIsIHZhbHVlPVwiICsgdmFsdWUgKyBcIiBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIHZhbHVlIGlzIG5vdCBhIHN0cmluZyBvciBudW1iZXJcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PVwiICsga2V5ICsgXCIsIHZhbHVlPVwiICsgdmFsdWUgKyBcIiBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIGtleSBjb250YWlucyBpbGxlZ2FsIGNoYXJhY3RlciwgaXMgZW1wdHkgb3IgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjaGFyYWN0ZXJzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfS0VZX0xFTkdUSCArIFwiKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHM6IGVudHJ5IHdpdGgga2V5PVwiICsga2V5ICsgXCIsIHZhbHVlPVwiICsgdmFsdWUgKyBcIiBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXQgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjdXN0b20gZmllbGRzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQgKyBcIilcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDEgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMSBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAyIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDIgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMyBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMyhHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAzIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDMoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25TdHJpbmdWYWx1ZShrZXk6c3RyaW5nLCBkZWZhdWx0VmFsdWU6c3RyaW5nKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zW2tleV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldLnRvU3RyaW5nKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBkZWZhdWx0VmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzQ29tbWFuZENlbnRlclJlYWR5KCk6Ym9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmNvbW1hbmRDZW50ZXJJc1JlYWR5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZENvbW1hbmRDZW50ZXJMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uQ29tbWFuZENlbnRlclVwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluZGV4ID0gR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVyTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UuY29tbWFuZENlbnRlckxpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKSA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNvbW1hbmRDZW50ZXJMaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZUNvbW1hbmRDZW50ZXJMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uQ29tbWFuZENlbnRlclVwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluZGV4ID0gR0FTdGF0ZS5pbnN0YW5jZS5jb21tYW5kQ2VudGVyTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIGlmKGluZGV4ID4gLTEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNvbW1hbmRDZW50ZXJMaXN0ZW5lcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29uZmlndXJhdGlvbnNDb250ZW50QXNTdHJpbmcoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9ucyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcG9wdWxhdGVDb25maWd1cmF0aW9ucyhzZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uczphbnlbXSA9IHNka0NvbmZpZ1tcImNvbmZpZ3VyYXRpb25zXCJdO1xuICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3VyYXRpb25zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGNvbmZpZ3VyYXRpb25zLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbjp7W2tleTpzdHJpbmddOiBhbnl9ID0gY29uZmlndXJhdGlvbnNbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3VyYXRpb24pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBjb25maWd1cmF0aW9uW1wia2V5XCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZTphbnkgPSBjb25maWd1cmF0aW9uW1widmFsdWVcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHN0YXJ0X3RzOm51bWJlciA9IGNvbmZpZ3VyYXRpb25bXCJzdGFydFwiXSA/IGNvbmZpZ3VyYXRpb25bXCJzdGFydFwiXSA6IE51bWJlci5NSU5fVkFMVUU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGVuZF90czpudW1iZXIgPSBjb25maWd1cmF0aW9uW1wiZW5kXCJdID8gY29uZmlndXJhdGlvbltcImVuZFwiXSA6IE51bWJlci5NQVhfVkFMVUU7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY2xpZW50X3RzX2FkanVzdGVkOm51bWJlciA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoa2V5ICYmIHZhbHVlICYmIGNsaWVudF90c19hZGp1c3RlZCA+IHN0YXJ0X3RzICYmIGNsaWVudF90c19hZGp1c3RlZCA8IGVuZF90cylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiY29uZmlndXJhdGlvbiBhZGRlZDogXCIgKyBKU09OLnN0cmluZ2lmeShjb25maWd1cmF0aW9uKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY29tbWFuZENlbnRlcklzUmVhZHkgPSB0cnVlO1xuXG4gICAgICAgICAgICAgICAgdmFyIGxpc3RlbmVyczpBcnJheTx7IG9uQ29tbWFuZENlbnRlclVwZGF0ZWQ6KCkgPT4gdm9pZCB9PiA9IEdBU3RhdGUuaW5zdGFuY2UuY29tbWFuZENlbnRlckxpc3RlbmVycztcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBsaXN0ZW5lcnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihsaXN0ZW5lcnNbaV0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxpc3RlbmVyc1tpXS5vbkNvbW1hbmRDZW50ZXJVcGRhdGVkKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGFza3NcbiAgICB7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvclR5cGUgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBU2RrRXJyb3JUeXBlO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBTZGtFcnJvclRhc2tcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4Q291bnQ6bnVtYmVyID0gMTA7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBjb3VudE1hcDp7W2tleTpudW1iZXJdOiBudW1iZXJ9ID0ge307XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZXhlY3V0ZSh1cmw6c3RyaW5nLCB0eXBlOkVHQVNka0Vycm9yVHlwZSwgcGF5bG9hZERhdGE6c3RyaW5nLCBzZWNyZXRLZXk6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSAwO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA+PSBTZGtFcnJvclRhc2suTWF4Q291bnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBoYXNoSG1hYzpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKHNlY3JldEtleSwgcGF5bG9hZERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcblxuICAgICAgICAgICAgICAgIHJlcXVlc3Qub25yZWFkeXN0YXRlY2hhbmdlID0gKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZihyZXF1ZXN0LnJlYWR5U3RhdGUgPT09IDQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFyZXF1ZXN0LnJlc3BvbnNlVGV4dClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2RrIGVycm9yIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgcmVxdWVzdC5zdGF0dXNUZXh0ICsgXCIsIFN0YXR1cyBjb2RlOiBcIiArIHJlcXVlc3Quc3RhdHVzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKHJlcXVlc3Quc3RhdHVzICE9IDIwMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwic2RrIGVycm9yIGZhaWxlZC4gcmVzcG9uc2UgY29kZSBub3QgMjAwLiBzdGF0dXMgY29kZTogXCIgKyByZXF1ZXN0LnN0YXR1cyArIFwiLCBkZXNjcmlwdGlvbjogXCIgKyByZXF1ZXN0LnN0YXR1c1RleHQgKyBcIiwgYm9keTogXCIgKyByZXF1ZXN0LnJlc3BvbnNlVGV4dCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSArIDE7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vcGVuKFwiUE9TVFwiLCB1cmwsIHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtVHlwZVwiLCBcImFwcGxpY2F0aW9uL2pzb25cIik7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQXV0aG9yaXphdGlvblwiLCBoYXNoSG1hYyk7XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2VuZChwYXlsb2FkRGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcbiAgICAgICAgaW1wb3J0IFNka0Vycm9yVGFzayA9IGdhbWVhbmFseXRpY3MudGFza3MuU2RrRXJyb3JUYXNrO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUhUVFBBcGlcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUhUVFBBcGkgPSBuZXcgR0FIVFRQQXBpKCk7XG4gICAgICAgICAgICBwcml2YXRlIHByb3RvY29sOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgaG9zdE5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSB2ZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzVXJsUGF0aDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHVzZUd6aXA6Ym9vbGVhbjtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYmFzZSB1cmwgc2V0dGluZ3NcbiAgICAgICAgICAgICAgICB0aGlzLnByb3RvY29sID0gXCJodHRwc1wiO1xuICAgICAgICAgICAgICAgIHRoaXMuaG9zdE5hbWUgPSBcImFwaS5nYW1lYW5hbHl0aWNzLmNvbVwiO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IFwidjJcIjtcblxuICAgICAgICAgICAgICAgIC8vIGNyZWF0ZSBiYXNlIHVybFxuICAgICAgICAgICAgICAgIHRoaXMuYmFzZVVybCA9IHRoaXMucHJvdG9jb2wgKyBcIjovL1wiICsgdGhpcy5ob3N0TmFtZSArIFwiL1wiICsgdGhpcy52ZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5pbml0aWFsaXplVXJsUGF0aCA9IFwiaW5pdFwiO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzVXJsUGF0aCA9IFwiZXZlbnRzXCI7XG5cbiAgICAgICAgICAgICAgICB0aGlzLnVzZUd6aXAgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHJlcXVlc3RJbml0KGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSkgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmluaXRpYWxpemVVcmxQYXRoO1xuICAgICAgICAgICAgICAgIHVybCA9IFwiaHR0cHM6Ly9ydWJpY2suZ2FtZWFuYWx5dGljcy5jb20vdjIvY29tbWFuZF9jZW50ZXI/Z2FtZV9rZXk9XCIgKyBnYW1lS2V5ICsgXCImaW50ZXJ2YWxfc2Vjb25kcz0xMDAwMDAwXCI7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2luaXQnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGluaXRBbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRJbml0QW5ub3RhdGlvbnMoKTtcblxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoaW5pdEFubm90YXRpb25zKTtcblxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQsIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZyA9IHRoaXMuY3JlYXRlUGF5bG9hZERhdGEoSlNPTnN0cmluZywgdGhpcy51c2VHemlwKTtcbiAgICAgICAgICAgICAgICB2YXIgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5pbml0UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZW5kRXZlbnRzSW5BcnJheShldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+LCByZXF1ZXN0SWQ6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGV2ZW50QXJyYXkubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZEV2ZW50c0luQXJyYXkgY2FsbGVkIHdpdGggbWlzc2luZyBldmVudEFycmF5XCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5ldmVudHNVcmxQYXRoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdldmVudHMnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBKU09OIHN0cmluZyBmcm9tIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldmVudEFycmF5KTtcblxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRFdmVudHNJbkFycmF5IEpTT04gZW5jb2RpbmcgZmFpbGVkIG9mIGV2ZW50QXJyYXlcIik7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50QXJyYXkubGVuZ3RoKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YSA9IHRoaXMuY3JlYXRlUGF5bG9hZERhdGEoSlNPTnN0cmluZywgdGhpcy51c2VHemlwKTtcbiAgICAgICAgICAgICAgICB2YXIgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChyZXF1ZXN0SWQpO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKGV2ZW50QXJyYXkubGVuZ3RoLnRvU3RyaW5nKCkpO1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5zZW5kUmVxdWVzdCh1cmwsIHBheWxvYWREYXRhLCBleHRyYUFyZ3MsIHRoaXMudXNlR3ppcCwgR0FIVFRQQXBpLnNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2ssIGNhbGxiYWNrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlbmRTZGtFcnJvckV2ZW50KHR5cGU6RUdBU2RrRXJyb3JUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuICAgICAgICAgICAgICAgIHZhciBzZWNyZXRLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTZGtFcnJvckV2ZW50KGdhbWVLZXksIHNlY3JldEtleSwgdHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnZXZlbnRzJyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkSlNPTlN0cmluZzpzdHJpbmcgPSBcIlwiO1xuXG4gICAgICAgICAgICAgICAgdmFyIGpzb246e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgdHlwZVN0cmluZzpzdHJpbmcgPSBHQUhUVFBBcGkuc2RrRXJyb3JUeXBlVG9TdHJpbmcodHlwZSk7XG4gICAgICAgICAgICAgICAganNvbltcInR5cGVcIl0gPSB0eXBlU3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50QXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgICAgICBldmVudEFycmF5LnB1c2goanNvbik7XG4gICAgICAgICAgICAgICAgcGF5bG9hZEpTT05TdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldmVudEFycmF5KTtcblxuICAgICAgICAgICAgICAgIGlmKCFwYXlsb2FkSlNPTlN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJzZW5kU2RrRXJyb3JFdmVudDogSlNPTiBlbmNvZGluZyBmYWlsZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRTZGtFcnJvckV2ZW50IGpzb246IFwiICsgcGF5bG9hZEpTT05TdHJpbmcpO1xuICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5leGVjdXRlKHVybCwgdHlwZSwgcGF5bG9hZEpTT05TdHJpbmcsIHNlY3JldEtleSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2socmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZDpzdHJpbmcgPSBleHRyYVsyXTtcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRDb3VudDpudW1iZXIgPSBwYXJzZUludChleHRyYVszXSk7XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZXZlbnRzIHJlcXVlc3QgY29udGVudDogXCIgKyBib2R5KTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0UmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSA9IEdBSFRUUEFwaS5pbnN0YW5jZS5wcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZSwgcmVxdWVzdC5zdGF0dXNUZXh0LCBib2R5LCBcIkV2ZW50c1wiKTtcblxuICAgICAgICAgICAgICAgIC8vIGlmIG5vdCAyMDAgcmVzdWx0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgZXZlbnRzIENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SnNvbkRpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IGJvZHkgPyBKU09OLnBhcnNlKGJvZHkpIDoge307XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgRXZlbnRzIENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyByZXR1cm4gcmVzcG9uc2VcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCByZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRSZXF1ZXN0KHVybDpzdHJpbmcsIHBheWxvYWREYXRhOnN0cmluZywgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4sIGd6aXA6Ym9vbGVhbiwgY2FsbGJhY2s6KHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4pID0+IHZvaWQsIGNhbGxiYWNrMjoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYXV0aG9yaXphdGlvbiBoYXNoXG4gICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKTtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKGtleSwgcGF5bG9hZERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhdXRob3JpemF0aW9uKTtcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBleHRyYUFyZ3MpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhcmdzLnB1c2goZXh0cmFBcmdzW3NdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0LCB1cmwsIGNhbGxiYWNrMiwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vcGVuKFwiUE9TVFwiLCB1cmwsIHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtVHlwZVwiLCBcInRleHQvcGxhaW5cIik7XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGF1dGhvcml6YXRpb24pO1xuXG4gICAgICAgICAgICAgICAgaWYoZ3ppcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImd6aXAgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgLy9yZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LUVuY29kaW5nXCIsIFwiZ3ppcFwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2VuZChwYXlsb2FkRGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0pID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4gPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IGV4dHJhWzBdO1xuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IGV4dHJhWzFdO1xuICAgICAgICAgICAgICAgIHZhciBib2R5OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3BvbnNlQ29kZTpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgYm9keSA9IHJlcXVlc3QucmVzcG9uc2VUZXh0O1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlQ29kZSA9IHJlcXVlc3Quc3RhdHVzO1xuXG4gICAgICAgICAgICAgICAgLy8gcHJvY2VzcyB0aGUgcmVzcG9uc2VcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiaW5pdCByZXF1ZXN0IGNvbnRlbnQgOiBcIiArIGJvZHkpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJJbml0XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdEpzb25EaWN0ID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gSnNvbiBkZWNvZGluZyBmYWlsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByaW50IHJlYXNvbiBpZiBiYWQgcmVxdWVzdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gcmV0dXJuIGJhZCByZXF1ZXN0IHJlc3VsdFxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIEluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkSW5pdFZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FWYWxpZGF0b3IudmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UocmVxdWVzdEpzb25EaWN0KTtcblxuICAgICAgICAgICAgICAgIGlmKCF2YWxpZGF0ZWRJbml0VmFsdWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGFsbCBva1xuICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5PaywgdmFsaWRhdGVkSW5pdFZhbHVlcyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3JlYXRlUGF5bG9hZERhdGEocGF5bG9hZDpzdHJpbmcsIGd6aXA6Ym9vbGVhbik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YTpzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBpZihnemlwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gcGF5bG9hZERhdGEgPSBHQVV0aWxpdGllcy5HemlwQ29tcHJlc3MocGF5bG9hZCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIEdBTG9nZ2VyLkQoXCJHemlwIHN0YXRzLiBTaXplOiBcIiArIEVuY29kaW5nLlVURjguR2V0Qnl0ZXMocGF5bG9hZCkuTGVuZ3RoICsgXCIsIENvbXByZXNzZWQ6IFwiICsgcGF5bG9hZERhdGEuTGVuZ3RoICsgXCIsIENvbnRlbnQ6IFwiICsgcGF5bG9hZCk7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImd6aXAgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcGF5bG9hZERhdGEgPSBwYXlsb2FkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBwYXlsb2FkRGF0YTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBwcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZTpudW1iZXIsIHJlc3BvbnNlTWVzc2FnZTpzdHJpbmcsIGJvZHk6c3RyaW5nLCByZXF1ZXN0SWQ6c3RyaW5nKTogRUdBSFRUUEFwaVJlc3BvbnNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gaWYgbm8gcmVzdWx0IC0gb2Z0ZW4gbm8gY29ubmVjdGlvblxuICAgICAgICAgICAgICAgIGlmKCFib2R5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiBmYWlsZWQuIE1pZ2h0IGJlIG5vIGNvbm5lY3Rpb24uIERlc2NyaXB0aW9uOiBcIiArIHJlc3BvbnNlTWVzc2FnZSArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByZXNwb25zZUNvZGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gb2tcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSAyMDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLk9rO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIDQwMSBjYW4gcmV0dXJuIDAgc3RhdHVzXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMCB8fCByZXNwb25zZUNvZGUgPT09IDQwMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAxIC0gVW5hdXRob3JpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNDAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA0MDAgLSBCYWQgUmVxdWVzdC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSA1MDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDUwMCAtIEludGVybmFsIFNlcnZlciBFcnJvci5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuSW50ZXJuYWxTZXJ2ZXJFcnJvcjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLlVua25vd25SZXNwb25zZUNvZGU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNka0Vycm9yVHlwZVRvU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yVHlwZSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh2YWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkOlxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlamVjdGVkXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgZXZlbnRzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBFR0FIVFRQQXBpUmVzcG9uc2UgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBSFRUUEFwaVJlc3BvbnNlO1xuICAgICAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JUeXBlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQVNka0Vycm9yVHlwZTtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FFdmVudHNcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FFdmVudHMgPSBuZXcgR0FFdmVudHMoKTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2Vzc2lvblN0YXJ0OnN0cmluZyA9IFwidXNlclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uRW5kOnN0cmluZyA9IFwic2Vzc2lvbl9lbmRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RGVzaWduOnN0cmluZyA9IFwiZGVzaWduXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUJ1c2luZXNzOnN0cmluZyA9IFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5UHJvZ3Jlc3Npb246c3RyaW5nID0gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlSZXNvdXJjZTpzdHJpbmcgPSBcInJlc291cmNlXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUVycm9yOnN0cmluZyA9IFwiZXJyb3JcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heEV2ZW50Q291bnQ6bnVtYmVyID0gNTAwO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcblxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25TdGFydEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydDtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBzZXNzaW9uIG51bWJlciAgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5TZXNzaW9uTnVtS2V5LCBHQVN0YXRlLmdldFNlc3Npb25OdW0oKS50b1N0cmluZygpKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBTVEFSVCBldmVudFwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgZXZlbnQgcmlnaHQgYXdheVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uU3RhcnQsIGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRTZXNzaW9uRW5kRXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uX3N0YXJ0X3RzOm51bWJlciA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudF90c19hZGp1c3RlZDpudW1iZXIgPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkxlbmd0aDpudW1iZXIgPSBjbGllbnRfdHNfYWRqdXN0ZWQgLSBzZXNzaW9uX3N0YXJ0X3RzO1xuXG4gICAgICAgICAgICAgICAgaWYoc2Vzc2lvbkxlbmd0aCA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBTaG91bGQgbmV2ZXIgaGFwcGVuLlxuICAgICAgICAgICAgICAgICAgICAvLyBDb3VsZCBiZSBiZWNhdXNlIG9mIGVkZ2UgY2FzZXMgcmVnYXJkaW5nIHRpbWUgYWx0ZXJpbmcgb24gZGV2aWNlLlxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU2Vzc2lvbiBsZW5ndGggd2FzIGNhbGN1bGF0ZWQgdG8gYmUgbGVzcyB0aGVuIDAuIFNob3VsZCBub3QgYmUgcG9zc2libGUuIFJlc2V0dGluZyB0byAwLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkxlbmd0aCA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgc3BlY2lmaWMgZGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImxlbmd0aFwiXSA9IHNlc3Npb25MZW5ndGg7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFNFU1NJT04gRU5EIGV2ZW50LlwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgYWxsIGV2ZW50IHJpZ2h0IGF3YXlcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBjYXJ0VHlwZTpzdHJpbmcgPSBudWxsLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGNhcnRUeXBlLCBpdGVtVHlwZSwgaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IHRyYW5zYWN0aW9uIG51bWJlciBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSwgR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gUmVxdWlyZWRcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUJ1c2luZXNzO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImN1cnJlbmN5XCJdID0gY3VycmVuY3k7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5XSA9IEdBU3RhdGUuZ2V0VHJhbnNhY3Rpb25OdW0oKTtcblxuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsXG4gICAgICAgICAgICAgICAgaWYgKGNhcnRUeXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2FydF90eXBlXCJdID0gY2FydFR5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEJVU0lORVNTIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIiwgY2FydFR5cGU6XCIgKyBjYXJ0VHlwZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBJZiBmbG93IHR5cGUgaXMgc2luayByZXZlcnNlIGFtb3VudFxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50ICo9IC0xO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBldmVudCBzcGVjaWZpYyB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgZmxvd1R5cGVTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKGZsb3dUeXBlKTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGZsb3dUeXBlU3RyaW5nICsgXCI6XCIgKyBjdXJyZW5jeSArIFwiOlwiICsgaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UmVzb3VyY2U7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFJFU09VUkNFIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZywgc2NvcmU6bnVtYmVyLCBzZW5kU2NvcmU6Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyhwcm9ncmVzc2lvblN0YXR1cyk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIFByb2dyZXNzaW9uIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25JZGVudGlmaWVyOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmICghcHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKCFwcm9ncmVzc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVByb2dyZXNzaW9uO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIjpcIiArIHByb2dyZXNzaW9uSWRlbnRpZmllcjtcblxuICAgICAgICAgICAgICAgIC8vIEF0dGVtcHRcbiAgICAgICAgICAgICAgICB2YXIgYXR0ZW1wdF9udW06bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBzY29yZSBpZiBzcGVjaWZpZWQgYW5kIHN0YXR1cyBpcyBub3Qgc3RhcnRcbiAgICAgICAgICAgICAgICBpZiAoc2VuZFNjb3JlICYmIHByb2dyZXNzaW9uU3RhdHVzICE9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wic2NvcmVcIl0gPSBzY29yZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDb3VudCBhdHRlbXB0cyBvbiBlYWNoIHByb2dyZXNzaW9uIGZhaWwgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgYXR0ZW1wdCBudW1iZXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5jcmVtZW50IGFuZCBhZGQgYXR0ZW1wdF9udW0gb24gY29tcGxldGUgYW5kIGRlbGV0ZSBwZXJzaXN0ZWRcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBldmVudFxuICAgICAgICAgICAgICAgICAgICBhdHRlbXB0X251bSA9IEdBU3RhdGUuZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhdHRlbXB0X251bVwiXSA9IGF0dGVtcHRfbnVtO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFBST0dSRVNTSU9OIGV2ZW50OiB7c3RhdHVzOlwiICsgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIiwgcHJvZ3Jlc3Npb24wMTpcIiArIHByb2dyZXNzaW9uMDEgKyBcIiwgcHJvZ3Jlc3Npb24wMjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIiwgcHJvZ3Jlc3Npb24wMzpcIiArIHByb2dyZXNzaW9uMDMgKyBcIiwgc2NvcmU6XCIgKyBzY29yZSArIFwiLCBhdHRlbXB0OlwiICsgYXR0ZW1wdF9udW0gKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlOm51bWJlciwgc2VuZFZhbHVlOmJvb2xlYW4sIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGVzaWduRXZlbnQoZXZlbnRJZCwgdmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeURlc2lnbjtcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJldmVudF9pZFwiXSA9IGV2ZW50SWQ7XG5cbiAgICAgICAgICAgICAgICBpZihzZW5kVmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJ2YWx1ZVwiXSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRGaWVsZHNUb0V2ZW50KGV2ZW50RGF0YSwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkcykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBERVNJR04gZXZlbnQ6IHtldmVudElkOlwiICsgZXZlbnRJZCArIFwiLCB2YWx1ZTpcIiArIHZhbHVlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNldmVyaXR5U3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmVycm9yU2V2ZXJpdHlUb1N0cmluZyhzZXZlcml0eSk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlFcnJvcjtcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJzZXZlcml0eVwiXSA9IHNldmVyaXR5U3RyaW5nO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcIm1lc3NhZ2VcIl0gPSBtZXNzYWdlO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREYXRhKTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEVSUk9SIGV2ZW50OiB7c2V2ZXJpdHk6XCIgKyBzZXZlcml0eVN0cmluZyArIFwiLCBtZXNzYWdlOlwiICsgbWVzc2FnZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwcm9jZXNzRXZlbnRzKGNhdGVnb3J5OnN0cmluZywgcGVyZm9ybUNsZWFuVXA6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyB0aHJvdyBuZXcgRXJyb3IoXCJwcm9jZXNzRXZlbnRzIG5vdCBpbXBsZW1lbnRlZFwiKTtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRlbnRpZmllcjpzdHJpbmcgPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYW51cFxuICAgICAgICAgICAgICAgICAgICBpZihwZXJmb3JtQ2xlYW5VcClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY2xlYW51cEV2ZW50cygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIFByZXBhcmUgU1FMXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZWxlY3RBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZVdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XG4gICAgICAgICAgICAgICAgICAgIGlmKGNhdGVnb3J5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJjYXRlZ29yeVwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgY2F0ZWdvcnldKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVTZXRBcmdzOkFycmF5PFtzdHJpbmcsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgcmVxdWVzdElkZW50aWZpZXJdKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZXZlbnRzIHRvIHByb2Nlc3NcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50czpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncyk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgZm9yIGVycm9ycyBvciBlbXB0eVxuICAgICAgICAgICAgICAgICAgICBpZighZXZlbnRzIHx8IGV2ZW50cy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBObyBldmVudHMgdG8gc2VuZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLnVwZGF0ZVNlc3Npb25TdG9yZSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgbnVtYmVyIG9mIGV2ZW50cyBhbmQgdGFrZSBzb21lIGFjdGlvbiBpZiB0aGVyZSBhcmUgdG9vIG1hbnk/XG4gICAgICAgICAgICAgICAgICAgIGlmKGV2ZW50cy5sZW5ndGggPiBHQUV2ZW50cy5NYXhFdmVudENvdW50KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBNYWtlIGEgbGltaXQgcmVxdWVzdFxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzLCB0cnVlLCBHQUV2ZW50cy5NYXhFdmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFldmVudHMpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBHZXQgbGFzdCB0aW1lc3RhbXBcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYXN0SXRlbTp7W2tleTpzdHJpbmddOiBhbnl9ID0gZXZlbnRzW2V2ZW50cy5sZW5ndGggLSAxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYXN0VGltZXN0YW1wOnN0cmluZyA9IGxhc3RJdGVtW1wiY2xpZW50X3RzXCJdIGFzIHN0cmluZztcblxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcImNsaWVudF90c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbCwgbGFzdFRpbWVzdGFtcF0pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBTZWxlY3QgYWdhaW5cbiAgICAgICAgICAgICAgICAgICAgICAgIGV2ZW50cyA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWV2ZW50cylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcImNsaWVudF90c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbCwgbGFzdFRpbWVzdGFtcF0pO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogU2VuZGluZyBcIiArIGV2ZW50cy5sZW5ndGggKyBcIiBldmVudHMuXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIFNldCBzdGF0dXMgb2YgZXZlbnRzIHRvICdzZW5kaW5nJyAoYWxzbyBjaGVjayBmb3IgZXJyb3IpXG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FTdG9yZS51cGRhdGUoRUdBU3RvcmUuRXZlbnRzLCB1cGRhdGVTZXRBcmdzLCB1cGRhdGVXaGVyZUFyZ3MpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDcmVhdGUgcGF5bG9hZCBkYXRhIGZyb20gZXZlbnRzXG4gICAgICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkQXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcblxuICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpOm51bWJlciA9IDA7IGkgPCBldmVudHMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gZXZlbnRzW2ldO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdCA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoZXZbXCJldmVudFwiXSkpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGV2ZW50RGljdC5sZW5ndGggIT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXlsb2FkQXJyYXkucHVzaChldmVudERpY3QpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRFdmVudHNJbkFycmF5KHBheWxvYWRBcnJheSwgcmVxdWVzdElkZW50aWZpZXIsIEdBRXZlbnRzLnByb2Nlc3NFdmVudHNDYWxsYmFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIGR1cmluZyBQcm9jZXNzRXZlbnRzKCk6IFwiICsgZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRzQ2FsbGJhY2socmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSwgZGF0YURpY3Q6e1trZXk6c3RyaW5nXTogYW55fSwgIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgcmVxdWVzdElkV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCByZXF1ZXN0SWRdKTtcblxuICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gRGVsZXRlIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogXCIgKyBldmVudENvdW50ICsgXCIgZXZlbnRzIHNlbnQuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBQdXQgZXZlbnRzIGJhY2sgKE9ubHkgaW4gY2FzZSBvZiBubyByZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cyB0byBjb2xsZWN0b3IgLSBSZXRyeWluZyBuZXh0IHRpbWVcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHNldEFyZ3MsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBEZWxldGUgZXZlbnRzIChXaGVuIGdldHRpbmcgc29tZSBhbndzZXIgYmFjayBhbHdheXMgYXNzdW1lIGV2ZW50cyBhcmUgcHJvY2Vzc2VkKVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZGF0YURpY3QpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGpzb246YW55O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiBpbiBkYXRhRGljdClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGpzb24gPSBkYXRhRGljdFtqXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgJiYganNvbi5jb25zdHJ1Y3RvciA9PT0gQXJyYXkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IFwiICsgZXZlbnRDb3VudCArIFwiIGV2ZW50cyBzZW50LiBcIiArIGNvdW50ICsgXCIgZXZlbnRzIGZhaWxlZCBHQSBzZXJ2ZXIgdmFsaWRhdGlvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNsZWFudXBFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgW1tcInN0YXR1c1wiICwgXCJuZXdcIl1dKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIEdldCBhbGwgc2Vzc2lvbnMgdGhhdCBhcmUgbm90IGN1cnJlbnRcbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBhcmdzLnB1c2goW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbCwgR0FTdGF0ZS5nZXRTZXNzaW9uSWQoKV0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25zOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuU2Vzc2lvbnMsIGFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgaWYgKCFzZXNzaW9ucyB8fCBzZXNzaW9ucy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKHNlc3Npb25zLmxlbmd0aCArIFwiIHNlc3Npb24ocykgbG9jYXRlZCB3aXRoIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnRzXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBzZXNzaW9ucy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uRW5kRXZlbnQ6e1trZXk6c3RyaW5nXTogYW55fSA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2Vzc2lvbnNbaV1bXCJldmVudFwiXSBhcyBzdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50X3RzOm51bWJlciA9IHNlc3Npb25FbmRFdmVudFtcImNsaWVudF90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdGFydF90czpudW1iZXIgPSBzZXNzaW9uc1tpXVtcInRpbWVzdGFtcFwiXSBhcyBudW1iZXI7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGxlbmd0aDpudW1iZXIgPSBldmVudF90cyAtIHN0YXJ0X3RzO1xuICAgICAgICAgICAgICAgICAgICBsZW5ndGggPSBNYXRoLm1heCgwLCBsZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJmaXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cyBsZW5ndGggY2FsY3VsYXRlZDogXCIgKyBsZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uRW5kRXZlbnRbXCJsZW5ndGhcIl0gPSBsZW5ndGg7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShzZXNzaW9uRW5kRXZlbnQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIENoZWNrIGlmIHdlIGFyZSBpbml0aWFsaXplZFxuICAgICAgICAgICAgICAgIGlmICghR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IGFkZCBldmVudDogU0RLIGlzIG5vdCBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgZGIgc2l6ZSBsaW1pdHMgKDEwbWIpXG4gICAgICAgICAgICAgICAgICAgIC8vIElmIGRhdGFiYXNlIGlzIHRvbyBsYXJnZSBibG9jayBhbGwgZXhjZXB0IHVzZXIsIHNlc3Npb24gYW5kIGJ1c2luZXNzXG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0b3JlLmlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpICYmICFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudERhdGFbXCJjYXRlZ29yeVwiXSBhcyBzdHJpbmcsIC9eKHVzZXJ8c2Vzc2lvbl9lbmR8YnVzaW5lc3MpJC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRGF0YWJhc2UgdG9vIGxhcmdlLiBFdmVudCBoYXMgYmVlbiBibG9ja2VkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBkZWZhdWx0IGFubm90YXRpb25zXG4gICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gd2l0aCBvbmx5IGRlZmF1bHQgYW5ub3RhdGlvbnNcbiAgICAgICAgICAgICAgICAgICAgdmFyIGpzb25EZWZhdWx0czpzdHJpbmcgPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShldikpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIE1lcmdlIHdpdGggZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgZSBpbiBldmVudERhdGEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2W2VdID0gZXZlbnREYXRhW2VdO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gc3RyaW5nIHJlcHJlc2VudGF0aW9uXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2KTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBvdXRwdXQgaWYgVkVSQk9TRSBMT0cgZW5hYmxlZFxuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmlpKFwiRXZlbnQgYWRkZWQgdG8gcXVldWU6IFwiICsganNvbik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzdGF0dXNcIl0gPSBcIm5ld1wiO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjYXRlZ29yeVwiXSA9IGV2W1wiY2F0ZWdvcnlcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNsaWVudF90c1wiXSA9IGV2W1wiY2xpZW50X3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGV2KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuRXZlbnRzLCB2YWx1ZXMpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzZXNzaW9uIHN0b3JlIGlmIG5vdCBsYXN0XG4gICAgICAgICAgICAgICAgICAgIGlmIChldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9PSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlNlc3Npb25zLCBbW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgZXZbXCJzZXNzaW9uX2lkXCJdIGFzIHN0cmluZ11dKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlcyA9IHt9O1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IGV2W1wic2Vzc2lvbl9pZFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInRpbWVzdGFtcFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IGpzb25EZWZhdWx0cztcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLlNlc3Npb25zLCB2YWx1ZXMsIHRydWUsIFwic2Vzc2lvbl9pZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcImFkZEV2ZW50VG9TdG9yZTogZXJyb3JcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyB1cGRhdGVTZXNzaW9uU3RvcmUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1widGltZXN0YW1wXCJdID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShHQVN0YXRlLmdldEV2ZW50QW5ub3RhdGlvbnMoKSkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5TZXNzaW9ucywgdmFsdWVzLCB0cnVlLCBcInNlc3Npb25faWRcIik7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zYXZlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBhZGQgdG8gZGljdCAoaWYgbm90IG5pbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMVwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAyXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDNcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkRmllbGRzVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSwgZmllbGRzOntba2V5OnN0cmluZ106IGFueX0pOnZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGZpZWxkcyAmJiBPYmplY3Qua2V5cyhmaWVsZHMpLmxlbmd0aCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fZmllbGRzXCJdID0gZmllbGRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU291cmNlIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5Tb3VyY2VdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU291cmNlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rIHx8IHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGVbRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNpbmtcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9ncmVzc2lvblN0YXR1c1RvU3RyaW5nKHZhbHVlOmFueSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0IHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0XSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlN0YXJ0XCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUgfHwgdmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNbRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29tcGxldGVcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWxdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiRmFpbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGVycm9yU2V2ZXJpdHlUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkRlYnVnIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5EZWJ1Z10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkZWJ1Z1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuSW5mbyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuSW5mb10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbmZvXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5XYXJuaW5nXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndhcm5pbmdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkVycm9yIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5FcnJvcl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJlcnJvclwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuQ3JpdGljYWwgfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcImNyaXRpY2FsXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0aHJlYWRpbmdcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG4gICAgICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVRocmVhZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVRocmVhZGluZyA9IG5ldyBHQVRocmVhZGluZygpO1xuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGJsb2NrczpQcmlvcml0eVF1ZXVlPFRpbWVkQmxvY2s+ID0gbmV3IFByaW9yaXR5UXVldWU8VGltZWRCbG9jaz4oPElDb21wYXJlcjxudW1iZXI+PntcbiAgICAgICAgICAgICAgICBjb21wYXJlOiAoeDpudW1iZXIsIHk6bnVtYmVyKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB4IC0geTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHByaXZhdGUgcmVhZG9ubHkgaWQyVGltZWRCbG9ja01hcDp7W2tleTpudW1iZXJdOiBUaW1lZEJsb2NrfSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuVGltZW91dElkOm51bWJlcjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFRocmVhZFdhaXRUaW1lSW5NczpudW1iZXIgPSAxMDAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzOm51bWJlciA9IDguMDtcbiAgICAgICAgICAgIHByaXZhdGUga2VlcFJ1bm5pbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgaXNSdW5uaW5nOmJvb2xlYW47XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbml0aWFsaXppbmcgR0EgdGhyZWFkLi4uXCIpO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0YXJ0VGhyZWFkKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlVGltZWRCbG9jayhkZWxheUluU2Vjb25kczpudW1iZXIgPSAwKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0aW1lOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHRpbWUuc2V0U2Vjb25kcyh0aW1lLmdldFNlY29uZHMoKSArIGRlbGF5SW5TZWNvbmRzKTtcblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBuZXcgVGltZWRCbG9jayh0aW1lKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gdGltZWRCbG9jaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGFza09uR0FUaHJlYWQodGFza0Jsb2NrOigpID0+IHZvaWQsIGRlbGF5SW5TZWNvbmRzOm51bWJlciA9IDApOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRpbWU6RGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgdGltZS5zZXRTZWNvbmRzKHRpbWUuZ2V0U2Vjb25kcygpICsgZGVsYXlJblNlY29uZHMpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IG5ldyBUaW1lZEJsb2NrKHRpbWUpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSB0YXNrQmxvY2s7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFt0aW1lZEJsb2NrLmlkXSA9IHRpbWVkQmxvY2s7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGltZWRCbG9ja09uR0FUaHJlYWQodGltZWRCbG9jazpUaW1lZEJsb2NrKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2NoZWR1bGVUaW1lcihpbnRlcnZhbDpudW1iZXIsIGNhbGxiYWNrOigpID0+IHZvaWQpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdGltZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICB0aW1lLnNldFNlY29uZHModGltZS5nZXRTZWNvbmRzKCkgKyBpbnRlcnZhbCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSk7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9IGNhbGxiYWNrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRUaW1lZEJsb2NrQnlJZChibG9ja0lkZW50aWZpZXI6bnVtYmVyKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChibG9ja0lkZW50aWZpZXIgaW4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW2Jsb2NrSWRlbnRpZmllcl1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nID0gdHJ1ZTtcblxuICAgICAgICAgICAgICAgIGlmKCFHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zY2hlZHVsZVRpbWVyKEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcywgR0FUaHJlYWRpbmcucHJvY2Vzc0V2ZW50UXVldWUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uQW5kU3RvcFF1ZXVlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFbmRpbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnN0b3BFdmVudFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uRW5kRXZlbnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdG9wRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2Uua2VlcFJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpZ25vcmVUaW1lcihibG9ja0lkZW50aWZpZXI6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChibG9ja0lkZW50aWZpZXIgaW4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbYmxvY2tJZGVudGlmaWVyXS5pZ25vcmUgPSB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGludGVydmFsID4gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLlByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kcyA9IGludGVydmFsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2s6VGltZWRCbG9jayk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmJsb2Nrcy5lbnF1ZXVlKHRpbWVkQmxvY2suZGVhZGxpbmUuZ2V0VGltZSgpLCB0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVuKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBjbGVhclRpbWVvdXQoR0FUaHJlYWRpbmcucnVuVGltZW91dElkKTtcblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jaztcblxuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoKHRpbWVkQmxvY2sgPSBHQVRocmVhZGluZy5nZXROZXh0QmxvY2soKSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghdGltZWRCbG9jay5pZ25vcmUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodGltZWRCbG9jay5hc3luYylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF0aW1lZEJsb2NrLnJ1bm5pbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVkQmxvY2sucnVubmluZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucnVuVGltZW91dElkID0gc2V0VGltZW91dChHQVRocmVhZGluZy5ydW4sIEdBVGhyZWFkaW5nLlRocmVhZFdhaXRUaW1lSW5Ncyk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3Igb24gR0EgdGhyZWFkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRW5kaW5nIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnRUaHJlYWQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdGFydGluZyBHQSB0aHJlYWRcIik7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucnVuVGltZW91dElkID0gc2V0VGltZW91dChHQVRocmVhZGluZy5ydW4sIDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXROZXh0QmxvY2soKTogVGltZWRCbG9ja1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBub3c6RGF0ZSA9IG5ldyBEYXRlKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmhhc0l0ZW1zKCkgJiYgR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLnBlZWsoKS5kZWFkbGluZS5nZXRUaW1lKCkgPD0gbm93LmdldFRpbWUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkuYXN5bmMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkucnVubmluZylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLnBlZWsoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmRlcXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MuZGVxdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudFF1ZXVlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIHRydWUpO1xuICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2NoZWR1bGVUaW1lcihHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMsIEdBVGhyZWFkaW5nLnByb2Nlc3NFdmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBpbXBvcnQgR0FUaHJlYWRpbmcgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5HQVRocmVhZGluZztcbiAgICBpbXBvcnQgVGltZWRCbG9jayA9IGdhbWVhbmFseXRpY3MudGhyZWFkaW5nLlRpbWVkQmxvY2s7XG4gICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgIGltcG9ydCBHQURldmljZSA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLkdBRGV2aWNlO1xuICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICBpbXBvcnQgRUdBSFRUUEFwaVJlc3BvbnNlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcbiAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICBpbXBvcnQgR0FFdmVudHMgPSBnYW1lYW5hbHl0aWNzLmV2ZW50cy5HQUV2ZW50cztcblxuICAgIGV4cG9ydCBjbGFzcyBHYW1lQW5hbHl0aWNzXG4gICAge1xuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbml0VGltZWRCbG9ja0lkOm51bWJlciA9IC0xO1xuICAgICAgICBwdWJsaWMgc3RhdGljIG1ldGhvZE1hcDp7W2lkOnN0cmluZ106ICguLi5hcmdzOiBhbnlbXSkgPT4gdm9pZH0gPSB7fTtcblxuICAgICAgICBwdWJsaWMgc3RhdGljIGluaXQoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS50b3VjaCgpO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQnVpbGQnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQnVpbGQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb24nXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlVXNlcklkJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZVVzZXJJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpbml0aWFsaXplJ10gPSBHYW1lQW5hbHl0aWNzLmluaXRpYWxpemU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkQnVzaW5lc3NFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRCdXNpbmVzc0V2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFJlc291cmNlRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkUmVzb3VyY2VFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRQcm9ncmVzc2lvbkV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZFByb2dyZXNzaW9uRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRGVzaWduRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRGVzaWduRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkRXJyb3JFdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRFcnJvckV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEVycm9yRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRXJyb3JFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkSW5mb0xvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkSW5mb0xvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkVmVyYm9zZUxvZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkVmVyYm9zZUxvZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nJ10gPSBHYW1lQW5hbHl0aWNzLnNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDEnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDE7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDInXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0Q3VzdG9tRGltZW5zaW9uMDMnXSA9IEdhbWVBbmFseXRpY3Muc2V0Q3VzdG9tRGltZW5zaW9uMDM7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RmFjZWJvb2tJZCddID0gR2FtZUFuYWx5dGljcy5zZXRGYWNlYm9va0lkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEdlbmRlciddID0gR2FtZUFuYWx5dGljcy5zZXRHZW5kZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0QmlydGhZZWFyJ10gPSBHYW1lQW5hbHl0aWNzLnNldEJpcnRoWWVhcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFdmVudFByb2Nlc3NJbnRlcnZhbCddID0gR2FtZUFuYWx5dGljcy5zZXRFdmVudFByb2Nlc3NJbnRlcnZhbDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzdGFydFNlc3Npb24nXSA9IEdhbWVBbmFseXRpY3Muc3RhcnRTZXNzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2VuZFNlc3Npb24nXSA9IEdhbWVBbmFseXRpY3MuZW5kU2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblN0b3AnXSA9IEdhbWVBbmFseXRpY3Mub25TdG9wO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ29uUmVzdW1lJ10gPSBHYW1lQW5hbHl0aWNzLm9uUmVzdW1lO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZENvbW1hbmRDZW50ZXJMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5hZGRDb21tYW5kQ2VudGVyTGlzdGVuZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsncmVtb3ZlQ29tbWFuZENlbnRlckxpc3RlbmVyJ10gPSBHYW1lQW5hbHl0aWNzLnJlbW92ZUNvbW1hbmRDZW50ZXJMaXN0ZW5lcjtcblxuICAgICAgICAgICAgaWYodHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvd1snR2FtZUFuYWx5dGljcyddICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2Ygd2luZG93WydHYW1lQW5hbHl0aWNzJ11bJ3EnXSAhPT0gJ3VuZGVmaW5lZCcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHE6YW55W10gPSB3aW5kb3dbJ0dhbWVBbmFseXRpY3MnXVsncSddO1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgaW4gcSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuZ2FDb21tYW5kLmFwcGx5KG51bGwsIHFbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FDb21tYW5kKC4uLmFyZ3M6IGFueVtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBpZihhcmdzLmxlbmd0aCA+IDApXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoYXJnc1swXSBpbiBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJncy5sZW5ndGggPiAxKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwW2FyZ3NbMF1dLmFwcGx5KG51bGwsIEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3MsIDEpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbYXJnc1swXV0oKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSByZXNvdXJjZSBjdXJyZW5jaWVzIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSByZXNvdXJjZSBpdGVtIHR5cGVzIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQnVpbGQoYnVpbGQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQnVpbGQgdmVyc2lvbiBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQnVpbGQoYnVpbGQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBidWlsZDogQ2Fubm90IGJlIG51bGwsIGVtcHR5IG9yIGFib3ZlIDMyIGxlbmd0aC4gU3RyaW5nOiBcIiArIGJ1aWxkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEJ1aWxkKGJ1aWxkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbihzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgc2RrIHZlcnNpb246IFNkayB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBzZGtHYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24gPSBzZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUVuZ2luZVZlcnNpb24oZ2FtZUVuZ2luZVZlcnNpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBnYW1lIGVuZ2luZSB2ZXJzaW9uOiBHYW1lIGVuZ2luZSB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBnYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24gPSBnYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVVc2VySWQodUlkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkEgY3VzdG9tIHVzZXIgaWQgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVVzZXJJZCh1SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSB1c2VyX2lkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgNjQgbGVuZ3RoLiBXaWxsIHVzZSBkZWZhdWx0IHVzZXJfaWQgbWV0aG9kLiBVc2VkIHN0cmluZzogXCIgKyB1SWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRVc2VySWQodUlkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0aWFsaXplKGdhbWVLZXk6c3RyaW5nID0gXCJcIiwgZ2FtZVNlY3JldDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuY3JlYXRlVGltZWRCbG9jaygpO1xuICAgICAgICAgICAgdGltZWRCbG9jay5hc3luYyA9IHRydWU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmluaXRUaW1lZEJsb2NrSWQgPSB0aW1lZEJsb2NrLmlkO1xuICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9ICgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGFscmVhZHkgaW5pdGlhbGl6ZWQuIENhbiBvbmx5IGJlIGNhbGxlZCBvbmNlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlS2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTREsgZmFpbGVkIGluaXRpYWxpemUuIEdhbWUga2V5IG9yIHNlY3JldCBrZXkgaXMgaW52YWxpZC4gQ2FuIG9ubHkgY29udGFpbiBjaGFyYWN0ZXJzIEEteiAwLTksIGdhbWVLZXkgaXMgMzIgbGVuZ3RoLCBnYW1lU2VjcmV0IGlzIDQwIGxlbmd0aC4gRmFpbGVkIGtleXMgLSBnYW1lS2V5OiBcIiArIGdhbWVLZXkgKyBcIiwgc2VjcmV0S2V5OiBcIiArIGdhbWVTZWNyZXQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRLZXlzKGdhbWVLZXksIGdhbWVTZWNyZXQpO1xuXG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbnRlcm5hbEluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIsIGNhcnRUeXBlOnN0cmluZyA9IFwiXCIvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBidXNpbmVzcyBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlID0gRUdBUmVzb3VyY2VGbG93VHlwZS5VbmRlZmluZWQsIGN1cnJlbmN5OnN0cmluZyA9IFwiXCIsIGFtb3VudDpudW1iZXIgPSAwLCBpdGVtVHlwZTpzdHJpbmcgPSBcIlwiLCBpdGVtSWQ6c3RyaW5nID0gXCJcIi8qLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30qLyk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIHJlc291cmNlIGV2ZW50XCIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGUsIGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIHt9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzID0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxOnN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDI6c3RyaW5nID0gXCJcIiwgcHJvZ3Jlc3Npb24wMzpzdHJpbmcgPSBcIlwiLCBzY29yZT86YW55LyosIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSovKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBwcm9ncmVzc2lvbiBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIGV2ZW50c1xuICAgICAgICAgICAgICAgIHZhciBzZW5kU2NvcmU6Ym9vbGVhbiA9IHR5cGVvZiBzY29yZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICAvLyBpZih0eXBlb2Ygc2NvcmUgPT09IFwib2JqZWN0XCIpXG4gICAgICAgICAgICAgICAgLy8ge1xuICAgICAgICAgICAgICAgIC8vICAgICBmaWVsZHMgPSBzY29yZSBhcyB7W2lkOnN0cmluZ106IGFueX07XG4gICAgICAgICAgICAgICAgLy8gfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZFByb2dyZXNzaW9uRXZlbnQocHJvZ3Jlc3Npb25TdGF0dXMsIHByb2dyZXNzaW9uMDEsIHByb2dyZXNzaW9uMDIsIHByb2dyZXNzaW9uMDMsIHNlbmRTY29yZSA/IHNjb3JlIDogMCwgc2VuZFNjb3JlLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlPzphbnkvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIHNlbmRWYWx1ZTpib29sZWFuID0gdHlwZW9mIHZhbHVlID09PSBcIm51bWJlclwiO1xuICAgICAgICAgICAgICAgIC8vIGlmKHR5cGVvZiB2YWx1ZSA9PT0gXCJvYmplY3RcIilcbiAgICAgICAgICAgICAgICAvLyB7XG4gICAgICAgICAgICAgICAgLy8gICAgIGZpZWxkcyA9IHZhbHVlIGFzIHtbaWQ6c3RyaW5nXTogYW55fTtcbiAgICAgICAgICAgICAgICAvLyB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGVzaWduRXZlbnQoZXZlbnRJZCwgc2VuZFZhbHVlID8gdmFsdWUgIDogMCwgc2VuZFZhbHVlLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5ID0gRUdBRXJyb3JTZXZlcml0eS5VbmRlZmluZWQsIG1lc3NhZ2U6c3RyaW5nID0gXCJcIi8qLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30qLyk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGVycm9yIGV2ZW50XCIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEluZm9Mb2coZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5mbyBsb2dnaW5nIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRJbmZvTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkVmVyYm9zZUxvZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRWZXJib3NlTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmVyYm9zZSBsb2dnaW5nIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0TWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWcpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAzKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVGYWNlYm9va0lkKGZhY2Vib29rSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRGYWNlYm9va0lkKGZhY2Vib29rSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRHZW5kZXIoZ2VuZGVyOkVHQUdlbmRlciA9IEVHQUdlbmRlci5VbmRlZmluZWQpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUdlbmRlcihnZW5kZXIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRHZW5kZXIoZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QmlydGhZZWFyKGJpcnRoWWVhcjpudW1iZXIgPSAwKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVCaXJ0aHllYXIoYmlydGhZZWFyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QmlydGhZZWFyKGJpcnRoWWVhcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV2ZW50UHJvY2Vzc0ludGVydmFsKGludGVydmFsSW5TZWNvbmRzOm51bWJlcik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWxJblNlY29uZHMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHN0YXJ0U2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKEdBU3RhdGUuZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBHQVRocmVhZGluZy5jcmVhdGVUaW1lZEJsb2NrKCk7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5hc3luYyA9IHRydWU7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrID0gKCkgPT5cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaXNFbmFibGVkKCkgJiYgR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRpbWVkQmxvY2tPbkdBVGhyZWFkKHRpbWVkQmxvY2spO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm9uU3RvcCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKEV4Y2VwdGlvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29tbWFuZENlbnRlclZhbHVlQXNTdHJpbmcoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyA9IG51bGwpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5LCBkZWZhdWx0VmFsdWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpc0NvbW1hbmRDZW50ZXJSZWFkeSgpOmJvb2xlYW5cbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaXNDb21tYW5kQ2VudGVyUmVhZHkoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQ29tbWFuZENlbnRlckxpc3RlbmVyKGxpc3RlbmVyOnsgb25Db21tYW5kQ2VudGVyVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5hZGRDb21tYW5kQ2VudGVyTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVDb21tYW5kQ2VudGVyTGlzdGVuZXIobGlzdGVuZXI6eyBvbkNvbW1hbmRDZW50ZXJVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLnJlbW92ZUNvbW1hbmRDZW50ZXJMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk6c3RyaW5nXG4gICAgICAgIHtcbiAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmdldENvbmZpZ3VyYXRpb25zQ29udGVudEFzU3RyaW5nKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbnRlcm5hbEluaXRpYWxpemUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmVuc3VyZVBlcnNpc3RlZFN0YXRlcygpO1xuICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSwgR0FTdGF0ZS5nZXREZWZhdWx0SWQoKSk7XG5cbiAgICAgICAgICAgIEdBU3RhdGUuc2V0SW5pdGlhbGl6ZWQodHJ1ZSk7XG5cbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xuXG4gICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBuZXdTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FMb2dnZXIuaShcIlN0YXJ0aW5nIGEgbmV3IHNlc3Npb24uXCIpO1xuXG4gICAgICAgICAgICAvLyBtYWtlIHN1cmUgdGhlIGN1cnJlbnQgY3VzdG9tIGRpbWVuc2lvbnMgYXJlIHZhbGlkXG4gICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnJlcXVlc3RJbml0KEdhbWVBbmFseXRpY3Muc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2spO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2soaW5pdFJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwgaW5pdFJlc3BvbnNlRGljdDp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBpbml0IGlzIG9rXG4gICAgICAgICAgICBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiBpbml0UmVzcG9uc2VEaWN0KVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHNldCB0aGUgdGltZSBvZmZzZXQgLSBob3cgbWFueSBzZWNvbmRzIHRoZSBsb2NhbCB0aW1lIGlzIGRpZmZlcmVudCBmcm9tIHNlcnZlcnRpbWVcbiAgICAgICAgICAgICAgICB2YXIgdGltZU9mZnNldFNlY29uZHM6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICBpZihpbml0UmVzcG9uc2VEaWN0W1wic2VydmVyX3RzXCJdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlcnZlclRzOm51bWJlciA9IGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB0aW1lT2Zmc2V0U2Vjb25kcyA9IEdBU3RhdGUuY2FsY3VsYXRlU2VydmVyVGltZU9mZnNldChzZXJ2ZXJUcyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJ0aW1lX29mZnNldFwiXSA9IHRpbWVPZmZzZXRTZWNvbmRzO1xuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IG5ldyBjb25maWcgaW4gc3FsIGxpdGUgY3Jvc3Mgc2Vzc2lvbiBzdG9yYWdlXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5LCBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShpbml0UmVzcG9uc2VEaWN0KSkpO1xuXG4gICAgICAgICAgICAgICAgLy8gc2V0IG5ldyBjb25maWcgYW5kIGNhY2hlIGluIG1lbW9yeVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gaW5pdFJlc3BvbnNlRGljdDtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IGluaXRSZXNwb25zZURpY3Q7XG5cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09IEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkluaXRpYWxpemUgU0RLIGZhaWxlZCAtIFVuYXV0aG9yaXplZFwiKTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbG9nIHRoZSBzdGF0dXMgaWYgbm8gY29ubmVjdGlvblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuUmVxdWVzdFRpbWVvdXQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBubyByZXNwb25zZS4gQ291bGQgYmUgb2ZmbGluZSBvciB0aW1lb3V0LlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVzcG9uc2UuIENvdWxkIGJlIGJhZCByZXNwb25zZSBmcm9tIHByb3h5IG9yIEdBIHNlcnZlcnMuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXF1ZXN0IG9yIHVua25vd24gcmVzcG9uc2UuXCIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGluaXQgY2FsbCBmYWlsZWQgKHBlcmhhcHMgb2ZmbGluZSlcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgY2FjaGVkIGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBsYXN0IGNyb3NzIHNlc3Npb24gc3RvcmVkIGNvbmZpZyBpbml0IHZhbHVlc1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGRlZmF1bHQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgaW5pdCB2YWx1ZXNcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGNhY2hlZCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBzZXQgb2Zmc2V0IGluIHN0YXRlIChtZW1vcnkpIGZyb20gY3VycmVudCBjb25maWcgKGNvbmZpZyBjb3VsZCBiZSBmcm9tIGNhY2hlIGV0Yy4pXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQgPSBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gPyBHQVN0YXRlLmdldFNka0NvbmZpZygpW1widGltZV9vZmZzZXRcIl0gYXMgbnVtYmVyIDogMDtcblxuICAgICAgICAgICAgLy8gcG9wdWxhdGUgY29uZmlndXJhdGlvbnNcbiAgICAgICAgICAgIEdBU3RhdGUucG9wdWxhdGVDb25maWd1cmF0aW9ucyhHQVN0YXRlLmdldFNka0NvbmZpZygpKTtcblxuICAgICAgICAgICAgLy8gaWYgU0RLIGlzIGRpc2FibGVkIGluIGNvbmZpZ1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzdGFydCBzZXNzaW9uOiBTREsgaXMgZGlzYWJsZWQuXCIpO1xuICAgICAgICAgICAgICAgIC8vIHN0b3AgZXZlbnQgcXVldWVcbiAgICAgICAgICAgICAgICAvLyArIG1ha2Ugc3VyZSBpdCdzIGFibGUgdG8gcmVzdGFydCBpZiBhbm90aGVyIHNlc3Npb24gZGV0ZWN0cyBpdCdzIGVuYWJsZWQgYWdhaW5cbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wRXZlbnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIGdlbmVyYXRlIHRoZSBuZXcgc2Vzc2lvblxuICAgICAgICAgICAgdmFyIG5ld1Nlc3Npb25JZDpzdHJpbmcgPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIGlkXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZCA9IG5ld1Nlc3Npb25JZDtcblxuICAgICAgICAgICAgLy8gU2V0IHNlc3Npb24gc3RhcnRcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgIC8vIEFkZCBzZXNzaW9uIHN0YXJ0IGV2ZW50XG4gICAgICAgICAgICBHQUV2ZW50cy5hZGRTZXNzaW9uU3RhcnRFdmVudCgpO1xuXG4gICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuZ2V0VGltZWRCbG9ja0J5SWQoR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkKTtcblxuICAgICAgICAgICAgaWYodGltZWRCbG9jayAhPSBudWxsKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2sucnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmluaXRUaW1lZEJsb2NrSWQgPSAtMTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJSZXN1bWluZyBzZXNzaW9uLlwiKTtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm5ld1Nlc3Npb24oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIGlzU2RrUmVhZHkobmVlZHNJbml0aWFsaXplZDpib29sZWFuLCB3YXJuOmJvb2xlYW4gPSB0cnVlLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIpOiBib29sZWFuXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKG1lc3NhZ2UpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgbWVzc2FnZSA9IG1lc3NhZ2UgKyBcIjogXCI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIElzIFNESyBpbml0aWFsaXplZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBJcyBTREsgZW5hYmxlZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNFbmFibGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNESyBpcyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgc2Vzc2lvbiBzdGFydGVkXG4gICAgICAgICAgICBpZiAobmVlZHNJbml0aWFsaXplZCAmJiAhR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHdhcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNlc3Npb24gaGFzIG5vdCBzdGFydGVkIHlldFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9XG59XG5nYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuaW5pdCgpO1xudmFyIEdhbWVBbmFseXRpY3MgPSBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MuZ2FDb21tYW5kO1xuIl19

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
