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
                if (M[1].toLowerCase() === 'fbav') {
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
        GADevice.sdkWrapperVersion = "javascript 2.1.1";
        GADevice.osVersionPair = GADevice.matchItem([
            navigator.platform,
            navigator.userAgent,
            navigator.appVersion,
            navigator.vendor,
            window.opera
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
            return GAState;
        }());
        GAState.CategorySdkError = "sdk_error";
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
            GAEvents.addBusinessEvent = function (currency, amount, itemType, itemId, cartType) {
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
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addResourceEvent = function (flowType, currency, amount, itemType, itemId) {
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
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score, sendScore) {
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
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addDesignEvent = function (eventId, value, sendValue) {
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
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.addErrorEvent = function (severity, message) {
                var severityString = GAEvents.errorSeverityToString(severity);
                if (!GAValidator.validateErrorEvent(severity, message)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryError;
                eventData["severity"] = severityString;
                eventData["message"] = message;
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
                GAEvents.updateSessionStore();
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
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType);
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
                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId);
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
                var sendScore = typeof score != "undefined";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore);
            });
        };
        GameAnalytics.addDesignEvent = function (eventId, value) {
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                    return;
                }
                var sendValue = typeof value != "undefined";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue);
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
                GAEvents.addErrorEvent(severity, message);
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
            GAState.instance.clientServerTimeOffset = GAState.instance.sdkConfig["time_offset"] ? GAState.instance.sdkConfig["time_offset"] : 0;
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

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy90aHJlYWRpbmcvVGltZWRCbG9jay50cyIsInNyYy90aHJlYWRpbmcvUHJpb3JpdHlRdWV1ZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2V2ZW50cy9HQUV2ZW50cy50cyIsInNyYy90aHJlYWRpbmcvR0FUaHJlYWRpbmcudHMiLCJzcmMvR2FtZUFuYWx5dGljcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFPLGFBQWEsQ0EwRG5CO0FBMURELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQVFYO0lBUkQsV0FBWSxnQkFBZ0I7UUFFeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFSVyxnQkFBZ0IsR0FBaEIsOEJBQWdCLEtBQWhCLDhCQUFnQixRQVEzQjtJQUVELElBQVksU0FLWDtJQUxELFdBQVksU0FBUztRQUVqQixtREFBYSxDQUFBO1FBQ2IseUNBQVEsQ0FBQTtRQUNSLDZDQUFVLENBQUE7SUFDZCxDQUFDLEVBTFcsU0FBUyxHQUFULHVCQUFTLEtBQVQsdUJBQVMsUUFLcEI7SUFFRCxJQUFZLG9CQU1YO0lBTkQsV0FBWSxvQkFBb0I7UUFFNUIseUVBQWEsQ0FBQTtRQUNiLGlFQUFTLENBQUE7UUFDVCx1RUFBWSxDQUFBO1FBQ1osK0RBQVEsQ0FBQTtJQUNaLENBQUMsRUFOVyxvQkFBb0IsR0FBcEIsa0NBQW9C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QmtCLDhCQUFnQixHQUFVLENBQUMsQ0FBQyxDQUFDO0lBQzlCLHVCQUFTLEdBQTJDLEVBQUUsQ0FBQztJQUg1RCwyQkFBYSxnQkFxcEJ6QixDQUFBO0FBQ0wsQ0FBQyxFQXBxQk0sYUFBYSxLQUFiLGFBQWEsUUFvcUJuQjtBQUNELGFBQWEsQ0FBQyxhQUFhLENBQUMsSUFBSSxFQUFFLENBQUM7QUFDbkMsSUFBSSxhQUFhLEdBQUcsYUFBYSxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUMiLCJmaWxlIjoiZGlzdC9HYW1lQW5hbHl0aWNzLmRlYnVnLmpzIiwic291cmNlc0NvbnRlbnQiOlsibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgZW51bSBFR0FFcnJvclNldmVyaXR5XG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBEZWJ1ZyA9IDEsXG4gICAgICAgIEluZm8gPSAyLFxuICAgICAgICBXYXJuaW5nID0gMyxcbiAgICAgICAgRXJyb3IgPSA0LFxuICAgICAgICBDcml0aWNhbCA9IDVcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FHZW5kZXJcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIE1hbGUgPSAxLFxuICAgICAgICBGZW1hbGUgPSAyXG4gICAgfVxuXG4gICAgZXhwb3J0IGVudW0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFN0YXJ0ID0gMSxcbiAgICAgICAgQ29tcGxldGUgPSAyLFxuICAgICAgICBGYWlsID0gM1xuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVJlc291cmNlRmxvd1R5cGVcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIFNvdXJjZSA9IDEsXG4gICAgICAgIFNpbmsgPSAyXG4gICAgfVxuXG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXG4gICAge1xuICAgICAgICBleHBvcnQgZW51bSBFR0FTZGtFcnJvclR5cGVcbiAgICAgICAge1xuICAgICAgICAgICAgVW5kZWZpbmVkID0gMCxcbiAgICAgICAgICAgIFJlamVjdGVkID0gMVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBSFRUUEFwaVJlc3BvbnNlXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIGNsaWVudFxuICAgICAgICAgICAgTm9SZXNwb25zZSxcbiAgICAgICAgICAgIEJhZFJlc3BvbnNlLFxuICAgICAgICAgICAgUmVxdWVzdFRpbWVvdXQsIC8vIDQwOFxuICAgICAgICAgICAgSnNvbkVuY29kZUZhaWxlZCxcbiAgICAgICAgICAgIEpzb25EZWNvZGVGYWlsZWQsXG4gICAgICAgICAgICAvLyBzZXJ2ZXJcbiAgICAgICAgICAgIEludGVybmFsU2VydmVyRXJyb3IsXG4gICAgICAgICAgICBCYWRSZXF1ZXN0LCAvLyA0MDBcbiAgICAgICAgICAgIFVuYXV0aG9yaXplZCwgLy8gNDAxXG4gICAgICAgICAgICBVbmtub3duUmVzcG9uc2VDb2RlLFxuICAgICAgICAgICAgT2tcbiAgICAgICAgfVxuICAgIH1cbn1cbnZhciBFR0FFcnJvclNldmVyaXR5ID0gZ2FtZWFuYWx5dGljcy5FR0FFcnJvclNldmVyaXR5O1xudmFyIEVHQUdlbmRlciA9IGdhbWVhbmFseXRpY3MuRUdBR2VuZGVyO1xudmFyIEVHQVByb2dyZXNzaW9uU3RhdHVzID0gZ2FtZWFuYWx5dGljcy5FR0FQcm9ncmVzc2lvblN0YXR1cztcbnZhciBFR0FSZXNvdXJjZUZsb3dUeXBlID0gZ2FtZWFuYWx5dGljcy5FR0FSZXNvdXJjZUZsb3dUeXBlO1xuIiwiLy9HQUxPR0dFUl9TVEFSVFxubW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGxvZ2dpbmdcbiAgICB7XG4gICAgICAgIGVudW0gRUdBTG9nZ2VyTWVzc2FnZVR5cGVcbiAgICAgICAge1xuICAgICAgICAgICAgRXJyb3IgPSAwLFxuICAgICAgICAgICAgV2FybmluZyA9IDEsXG4gICAgICAgICAgICBJbmZvID0gMixcbiAgICAgICAgICAgIERlYnVnID0gM1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBTG9nZ2VyXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIEZpZWxkcyBhbmQgcHJvcGVydGllczogU1RBUlRcblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FMb2dnZXIgPSBuZXcgR0FMb2dnZXIoKTtcbiAgICAgICAgICAgIHByaXZhdGUgaW5mb0xvZ0VuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgaW5mb0xvZ1ZlcmJvc2VFbmFibGVkOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBkZWJ1Z0VuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFRhZzpzdHJpbmcgPSBcIkdhbWVBbmFseXRpY3NcIjtcblxuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBFTkRcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZGVidWdFbmFibGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gTWV0aG9kczogU1RBUlRcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbmZvTG9nKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ0VuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRWZXJib3NlTG9nKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ1ZlcmJvc2VFbmFibGVkID0gdmFsdWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkluZm8vXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdyhmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiV2FybmluZy9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJFcnJvci9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaWkoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuaW5zdGFuY2UuaW5mb0xvZ1ZlcmJvc2VFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiVmVyYm9zZS9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmRlYnVnRW5hYmxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkRlYnVnL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlOnN0cmluZywgdHlwZTpFR0FMb2dnZXJNZXNzYWdlVHlwZSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2godHlwZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRXJyb3I6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4obWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5EZWJ1ZzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYodHlwZW9mIGNvbnNvbGUuZGVidWcgPT09IFwiZnVuY3Rpb25cIilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbzpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBFTkRcbiAgICAgICAgfVxuICAgIH1cbn1cbi8vR0FMT0dHRVJfRU5EXG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdXRpbGl0aWVzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBVXRpbGl0aWVzXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SG1hYyhrZXk6c3RyaW5nLCBkYXRhOnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBlbmNyeXB0ZWRNZXNzYWdlID0gQ3J5cHRvSlMuSG1hY1NIQTI1NihkYXRhLCBrZXkpO1xuICAgICAgICAgICAgICAgIHJldHVybiBDcnlwdG9KUy5lbmMuQmFzZTY0LnN0cmluZ2lmeShlbmNyeXB0ZWRNZXNzYWdlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdHJpbmdNYXRjaChzOnN0cmluZywgcGF0dGVybjpSZWdFeHApOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIXMgfHwgIXBhdHRlcm4pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBhdHRlcm4udGVzdChzKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBqb2luU3RyaW5nQXJyYXkodjpBcnJheTxzdHJpbmc+LCBkZWxpbWl0ZXI6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcIlwiO1xuXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDAsIGlsID0gdi5sZW5ndGg7IGkgPCBpbDsgaSsrKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGkgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQgKz0gZGVsaW1pdGVyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSB2W2ldO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXJyYXk6QXJyYXk8c3RyaW5nPiwgc2VhcmNoOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYXJyYXkubGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBhcnJheSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGFycmF5W3NdID09PSBzZWFyY2gpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkga2V5U3RyOnN0cmluZyA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz1cIjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpbnB1dCA9IGVuY29kZVVSSShpbnB1dCk7XG4gICAgICAgICAgICAgICAgdmFyIG91dHB1dDpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciBjaHIxOm51bWJlciwgY2hyMjpudW1iZXIsIGNocjM6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgZW5jMTpudW1iZXIsIGVuYzI6bnVtYmVyLCBlbmMzOm51bWJlciwgZW5jNDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBpID0gMDtcblxuICAgICAgICAgICAgICAgIGRvXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgIGNocjEgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuXG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGNocjEgPj4gMjtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gKChjaHIxICYgMykgPDwgNCkgfCAoY2hyMiA+PiA0KTtcbiAgICAgICAgICAgICAgICAgICBlbmMzID0gKChjaHIyICYgMTUpIDw8IDIpIHwgKGNocjMgPj4gNik7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IGNocjMgJiA2MztcblxuICAgICAgICAgICAgICAgICAgIGlmIChpc05hTihjaHIyKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jMyA9IGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoaXNOYU4oY2hyMykpXG4gICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIGVuYzQgPSA2NDtcbiAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMSkgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMikgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMykgK1xuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkZWNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVtb3ZlIGFsbCBjaGFyYWN0ZXJzIHRoYXQgYXJlIG5vdCBBLVosIGEteiwgMC05LCArLCAvLCBvciA9XG4gICAgICAgICAgICAgICAgdmFyIGJhc2U2NHRlc3QgPSAvW15BLVphLXowLTlcXCtcXC9cXD1dL2c7XG4gICAgICAgICAgICAgICAgaWYgKGJhc2U2NHRlc3QuZXhlYyhpbnB1dCkpIHtcbiAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVGhlcmUgd2VyZSBpbnZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGluIHRoZSBpbnB1dCB0ZXh0LiBWYWxpZCBiYXNlNjQgY2hhcmFjdGVycyBhcmUgQS1aLCBhLXosIDAtOSwgJysnLCAnLycsYW5kICc9Jy4gRXhwZWN0IGVycm9ycyBpbiBkZWNvZGluZy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlucHV0ID0gaW5wdXQucmVwbGFjZSgvW15BLVphLXowLTlcXCtcXC9cXD1dL2csIFwiXCIpO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSAoZW5jMSA8PCAyKSB8IChlbmMyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGNocjIgPSAoKGVuYzIgJiAxNSkgPDwgNCkgfCAoZW5jMyA+PiAyKTtcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gKChlbmMzICYgMykgPDwgNikgfCBlbmM0O1xuXG4gICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIxKTtcblxuICAgICAgICAgICAgICAgICAgIGlmIChlbmMzICE9IDY0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIyKTtcbiAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzQgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjMpO1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIGNocjEgPSBjaHIyID0gY2hyMyA9IDA7XG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IGVuYzIgPSBlbmMzID0gZW5jNCA9IDA7XG5cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGRlY29kZVVSSShvdXRwdXQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZGF0ZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gTWF0aC5yb3VuZChkYXRlLmdldFRpbWUoKSAvIDEwMDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZUd1aWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIChHQVV0aWxpdGllcy5zNCgpICsgR0FVdGlsaXRpZXMuczQoKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIFwiLTRcIiArIEdBVXRpbGl0aWVzLnM0KCkuc3Vic3RyKDAsMykgKyBcIi1cIiArIEdBVXRpbGl0aWVzLnM0KCkgKyBcIi1cIiArIEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpICsgR0FVdGlsaXRpZXMuczQoKSkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgczQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICgoKDErTWF0aC5yYW5kb20oKSkqMHgxMDAwMCl8MCkudG9TdHJpbmcoMTYpLnN1YnN0cmluZygxKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB2YWxpZGF0b3JzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvclR5cGUgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBU2RrRXJyb3JUeXBlO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FWYWxpZGF0b3JcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBjYXJ0VHlwZTpzdHJpbmcsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW5jeVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBjdXJyZW5jeTogQ2Fubm90IGJlIChudWxsKSBhbmQgbmVlZCB0byBiZSBBLVosIDMgY2hhcmFjdGVycyBhbmQgaW4gdGhlIHN0YW5kYXJkIGF0IG9wZW5leGNoYW5nZXJhdGVzLm9yZy4gRmFpbGVkIGN1cnJlbmN5OiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGRvIG5vdCB2YWxpZGF0ZSBhbW91bnQgLSBpbnRlZ2VyIGlzIG5ldmVyIG51bGwgIVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY2FydFR5cGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY2FydFR5cGUuIENhbm5vdCBiZSBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBjYXJ0VHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGNoYXJzXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbUlkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZC4gQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGF2YWlsYWJsZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiwgYXZhaWxhYmxlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsb3dUeXBlID09IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gZmxvd1R5cGU6IEludmFsaWQgZmxvdyB0eXBlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUN1cnJlbmNpZXMsIGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGN1cnJlbmN5OiBOb3QgZm91bmQgaW4gbGlzdCBvZiBwcmUtZGVmaW5lZCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcy4gU3RyaW5nOiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIShhbW91bnQgPiAwKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGFtb3VudDogRmxvYXQgYW1vdW50IGNhbm5vdCBiZSAwIG9yIG5lZ2F0aXZlLiBWYWx1ZTogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghaXRlbVR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUl0ZW1UeXBlcywgaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IE5vdCBmb3VuZCBpbiBsaXN0IG9mIHByZS1kZWZpbmVkIGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtVHlwZXMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiBJbnZhbGlkIHByb2dyZXNzaW9uIHN0YXR1cy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBNYWtlIHN1cmUgcHJvZ3Jlc3Npb25zIGFyZSBkZWZpbmVkIGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiAwMyBmb3VuZCBidXQgMDErMDIgYXJlIGludmFsaWQuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHByb2dyZXNzaW9uMDIgJiYgIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAyIGZvdW5kIGJ1dCBub3QgMDEuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDEgKHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAyXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDIsIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgYmUgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDIpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMywgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGRlc2lnbiBldmVudCAtIGV2ZW50SWQ6IENhbm5vdCBiZSAobnVsbCkgb3IgZW1wdHkuIE9ubHkgNSBldmVudCBwYXJ0cyBhbGxvd2VkIHNlcGVyYXRlZCBieSA6LiBFYWNoIHBhcnQgbmVlZCB0byBiZSAzMiBjaGFyYWN0ZXJzIG9yIGxlc3MuIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZGVzaWduIGV2ZW50IC0gZXZlbnRJZDogTm9uIHZhbGlkIGNoYXJhY3RlcnMuIE9ubHkgYWxsb3dlZCBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsdWU6IGFsbG93IDAsIG5lZ2F0aXZlIGFuZCBuaWwgKG5vdCByZXF1aXJlZClcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHNldmVyaXR5ID09IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGVycm9yIGV2ZW50IC0gc2V2ZXJpdHk6IFNldmVyaXR5IHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUxvbmdTdHJpbmcobWVzc2FnZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBtZXNzYWdlOiBNZXNzYWdlIGNhbm5vdCBiZSBhYm92ZSA4MTkyIGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHR5cGUgPT09IEVHQVNka0Vycm9yVHlwZS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogVHlwZSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlS2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVLZXksIC9eW0EtejAtOV17MzJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVTZWNyZXQsIC9eW0EtejAtOV17NDB9JC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFjdXJyZW5jeSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjdXJyZW5jeSwgL15bQS1aXXszfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoZXZlbnRQYXJ0OnN0cmluZywgYWxsb3dOdWxsOmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGFsbG93TnVsbCAmJiAhZXZlbnRQYXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50UGFydC5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGV2ZW50UGFydDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudFBhcnQsIC9eW0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRMZW5ndGgoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bXjpdezEsNjR9KD86OlteOl17MSw2NH0pezAsNH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0oOltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UoaW5pdFJlc3BvbnNlOntba2V5OnN0cmluZ106IGFueX0pOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbWFrZSBzdXJlIHdlIGhhdmUgYSB2YWxpZCBkaWN0XG4gICAgICAgICAgICAgICAgaWYgKGluaXRSZXNwb25zZSA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBubyByZXNwb25zZSBkaWN0aW9uYXJ5LlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRlZERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZW5hYmxlZCBmaWVsZFxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImVuYWJsZWRcIl0gPSBpbml0UmVzcG9uc2VbXCJlbmFibGVkXCJdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdlbmFibGVkJyBmaWVsZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHNlcnZlcl90c1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlcnZlclRzTnVtYmVyOm51bWJlciA9IGluaXRSZXNwb25zZVtcInNlcnZlcl90c1wiXTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlclRzTnVtYmVyID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcInNlcnZlcl90c1wiXSA9IHNlcnZlclRzTnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHZhbHVlIGluICdzZXJ2ZXJfdHMnIGZpZWxkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ3NlcnZlcl90cycgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZWREaWN0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVpbGQoYnVpbGQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhidWlsZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHdyYXBwZXJWZXJzaW9uOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHdyYXBwZXJWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZCkgWzAtOV17MCw1fShcXC5bMC05XXswLDV9KXswLDJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVuZ2luZVZlcnNpb24oZW5naW5lVmVyc2lvbjpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFlbmdpbmVWZXJzaW9uIHx8ICFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChlbmdpbmVWZXJzaW9uLCAvXih1bml0eXx1bnJlYWx8Z2FtZW1ha2VyfGNvY29zMmR8Y29uc3RydWN0fGRlZm9sZCkgWzAtOV17MCw1fShcXC5bMC05XXswLDV9KXswLDJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVVzZXJJZCh1SWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcodUlkLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gdXNlciBpZDogaWQgY2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTaG9ydFN0cmluZyhzaG9ydFN0cmluZzpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eSBvciBuaWxcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhc2hvcnRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIXNob3J0U3RyaW5nIHx8IHNob3J0U3RyaW5nLmxlbmd0aCA+IDMyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVN0cmluZyhzOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5IG9yIG5pbFxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFzIHx8IHMubGVuZ3RoID4gNjQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlTG9uZ1N0cmluZyhsb25nU3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFN0cmluZyBpcyBhbGxvd2VkIHRvIGJlIGVtcHR5XG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIWxvbmdTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIWxvbmdTdHJpbmcgfHwgbG9uZ1N0cmluZy5sZW5ndGggPiA4MTkyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25UeXBlOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goY29ubmVjdGlvblR5cGUsIC9eKHd3YW58d2lmaXxsYW58b2ZmbGluZSkkLyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgMzIsIGZhbHNlLCBcImN1c3RvbSBkaW1lbnNpb25zXCIsIGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgNjQsIGZhbHNlLCBcInJlc291cmNlIGN1cnJlbmNpZXNcIiwgcmVzb3VyY2VDdXJyZW5jaWVzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHN0cmluZyBmb3IgcmVnZXhcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc291cmNlQ3VycmVuY2llcy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2gocmVzb3VyY2VDdXJyZW5jaWVzW2ldLCAvXltBLVphLXpdKyQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcInJlc291cmNlIGN1cnJlbmNpZXMgdmFsaWRhdGlvbiBmYWlsZWQ6IGEgcmVzb3VyY2UgY3VycmVuY3kgY2FuIG9ubHkgYmUgQS1aLCBhLXouIFN0cmluZyB3YXM6IFwiICsgcmVzb3VyY2VDdXJyZW5jaWVzW2ldKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwicmVzb3VyY2UgaXRlbSB0eXBlc1wiLCByZXNvdXJjZUl0ZW1UeXBlcykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCByZXNvdXJjZUl0ZW1UeXBlIGZvciBldmVudHBhcnQgdmFsaWRhdGlvblxuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzb3VyY2VJdGVtVHlwZXMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhyZXNvdXJjZUl0ZW1UeXBlc1tpXSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJyZXNvdXJjZSBpdGVtIHR5cGVzIHZhbGlkYXRpb24gZmFpbGVkOiBhIHJlc291cmNlIGl0ZW0gdHlwZSBjYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUl0ZW1UeXBlc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24wMTpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDIoZGltZW5zaW9uMDI6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAzKGRpbWVuc2lvbjAzOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAzKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBcnJheU9mU3RyaW5ncyhtYXhDb3VudDpudW1iZXIsIG1heFN0cmluZ0xlbmd0aDpudW1iZXIsIGFsbG93Tm9WYWx1ZXM6Ym9vbGVhbiwgbG9nVGFnOnN0cmluZywgYXJyYXlPZlN0cmluZ3M6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXJyYXlUYWc6c3RyaW5nID0gbG9nVGFnO1xuXG4gICAgICAgICAgICAgICAgLy8gdXNlIGFycmF5VGFnIHRvIGFubm90YXRlIHdhcm5pbmcgbG9nXG4gICAgICAgICAgICAgICAgaWYgKCFhcnJheVRhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFycmF5VGFnID0gXCJBcnJheVwiO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKCFhcnJheU9mU3RyaW5ncylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIG51bGwuIFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGVtcHR5XG4gICAgICAgICAgICAgICAgaWYgKGFsbG93Tm9WYWx1ZXMgPT0gZmFsc2UgJiYgYXJyYXlPZlN0cmluZ3MubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBiZSBlbXB0eS4gXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZXhjZWVkaW5nIG1heCBjb3VudFxuICAgICAgICAgICAgICAgIGlmIChtYXhDb3VudCA+IDAgJiYgYXJyYXlPZlN0cmluZ3MubGVuZ3RoID4gbWF4Q291bnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBleGNlZWQgXCIgKyBtYXhDb3VudCArIFwiIHZhbHVlcy4gSXQgaGFzIFwiICsgYXJyYXlPZlN0cmluZ3MubGVuZ3RoICsgXCIgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBhcnJheU9mU3RyaW5ncy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdHJpbmdMZW5ndGg6bnVtYmVyID0gIWFycmF5T2ZTdHJpbmdzW2ldID8gMCA6IGFycmF5T2ZTdHJpbmdzW2ldLmxlbmd0aDtcbiAgICAgICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHkgKG5vdCBhbGxvd2VkKVxuICAgICAgICAgICAgICAgICAgICBpZiAoc3RyaW5nTGVuZ3RoID09PSAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGNvbnRhaW5lZCBhbiBlbXB0eSBzdHJpbmcuIEFycmF5PVwiICsgSlNPTi5zdHJpbmdpZnkoYXJyYXlPZlN0cmluZ3MpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggbGVuZ3RoXG4gICAgICAgICAgICAgICAgICAgIGlmIChtYXhTdHJpbmdMZW5ndGggPiAwICYmIHN0cmluZ0xlbmd0aCA+IG1heFN0cmluZ0xlbmd0aClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhIHN0cmluZyBleGNlZWRlZCBtYXggYWxsb3dlZCBsZW5ndGggKHdoaWNoIGlzOiBcIiArIG1heFN0cmluZ0xlbmd0aCArIFwiKS4gU3RyaW5nIHdhczogXCIgKyBhcnJheU9mU3RyaW5nc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVGYWNlYm9va0lkKGZhY2Vib29rSWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcoZmFjZWJvb2tJZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGZhY2Vib29rIGlkOiBpZCBjYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUdlbmRlcihnZW5kZXI6YW55KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGlzTmFOKE51bWJlcihFR0FHZW5kZXJbZ2VuZGVyXSkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGdlbmRlciA9PSBFR0FHZW5kZXIuVW5kZWZpbmVkIHx8ICEoZ2VuZGVyID09IEVHQUdlbmRlci5NYWxlIHx8IGdlbmRlciA9PSBFR0FHZW5kZXIuRmVtYWxlKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGdlbmRlcjogSGFzIHRvIGJlICdtYWxlJyBvciAnZmVtYWxlJy4gV2FzOiBcIiArIGdlbmRlcik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGdlbmRlciA9PSBFR0FHZW5kZXJbRUdBR2VuZGVyLlVuZGVmaW5lZF0gfHwgIShnZW5kZXIgPT0gRUdBR2VuZGVyW0VHQUdlbmRlci5NYWxlXSB8fCBnZW5kZXIgPT0gRUdBR2VuZGVyW0VHQUdlbmRlci5GZW1hbGVdKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGdlbmRlcjogSGFzIHRvIGJlICdtYWxlJyBvciAnZmVtYWxlJy4gV2FzOiBcIiArIGdlbmRlcik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCaXJ0aHllYXIoYmlydGhZZWFyOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmlydGhZZWFyIDwgMCB8fCBiaXJ0aFllYXIgPiA5OTk5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJpcnRoWWVhcjogQ2Fubm90IGJlIChudWxsKSBvciBpbnZhbGlkIHJhbmdlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzOm51bWJlcik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoY2xpZW50VHMgPCAoLTQyOTQ5NjcyOTUrMSkgfHwgY2xpZW50VHMgPiAoNDI5NDk2NzI5NS0xKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgZGV2aWNlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIE5hbWVWYWx1ZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZhbHVlOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKG5hbWU6c3RyaW5nLCB2YWx1ZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52YWx1ZSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZlcnNpb25cbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMubmFtZSA9IG5hbWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQURldmljZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBzZGtXcmFwcGVyVmVyc2lvbjpzdHJpbmcgPSBcImphdmFzY3JpcHQgMi4xLjFcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IG9zVmVyc2lvblBhaXI6TmFtZVZlcnNpb24gPSBHQURldmljZS5tYXRjaEl0ZW0oW1xuICAgICAgICAgICAgICAgIG5hdmlnYXRvci5wbGF0Zm9ybSxcbiAgICAgICAgICAgICAgICBuYXZpZ2F0b3IudXNlckFnZW50LFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci5hcHBWZXJzaW9uLFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci52ZW5kb3IsXG4gICAgICAgICAgICAgICAgd2luZG93Lm9wZXJhXG4gICAgICAgICAgICBdLmpvaW4oJyAnKSwgW1xuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwid2luZG93c19waG9uZVwiLCBcIldpbmRvd3MgUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIndpbmRvd3NcIiwgXCJXaW5cIiwgXCJOVFwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQaG9uZVwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBhZFwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiaW9zXCIsIFwiaVBvZFwiLCBcIk9TXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYW5kcm9pZFwiLCBcIkFuZHJvaWRcIiwgXCJBbmRyb2lkXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYmxhY2tCZXJyeVwiLCBcIkJsYWNrQmVycnlcIiwgXCIvXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwibWFjX29zeFwiLCBcIk1hY1wiLCBcIk9TIFhcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ0aXplblwiLCBcIlRpemVuXCIsIFwiVGl6ZW5cIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJsaW51eFwiLCBcIkxpbnV4XCIsIFwicnZcIilcbiAgICAgICAgICAgIF0pO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGJ1aWxkUGxhdGZvcm06c3RyaW5nID0gR0FEZXZpY2UucnVudGltZVBsYXRmb3JtVG9TdHJpbmcoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgZGV2aWNlTW9kZWw6c3RyaW5nID0gR0FEZXZpY2UuZ2V0RGV2aWNlTW9kZWwoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgZGV2aWNlTWFudWZhY3R1cmVyOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1hbnVmYWN0dXJlcigpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBvc1ZlcnNpb246c3RyaW5nID0gR0FEZXZpY2UuZ2V0T1NWZXJzaW9uU3RyaW5nKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGJyb3dzZXJWZXJzaW9uOnN0cmluZyA9IEdBRGV2aWNlLmdldEJyb3dzZXJWZXJzaW9uU3RyaW5nKCk7XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2RrR2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjb25uZWN0aW9uVHlwZTpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBtYXhTYWZlSW50ZWdlcjpudW1iZXIgPSBNYXRoLnBvdygyLCA1MykgLSAxO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRvdWNoKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRSZWxldmFudFNka1ZlcnNpb24oKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5zZGtXcmFwcGVyVmVyc2lvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDb25uZWN0aW9uVHlwZSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UuY29ubmVjdGlvblR5cGU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdXBkYXRlQ29ubmVjdGlvblR5cGUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKG5hdmlnYXRvci5vbkxpbmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQURldmljZS5idWlsZFBsYXRmb3JtID09PSBcImlvc1wiIHx8IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiYW5kcm9pZFwiKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwid3dhblwiO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcImxhblwiO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIC8vIFRPRE86IERldGVjdCB3aWZpIHVzYWdlXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gXCJvZmZsaW5lXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRPU1ZlcnNpb25TdHJpbmcoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gKyBcIiBcIiArIEdBRGV2aWNlLm9zVmVyc2lvblBhaXIudmVyc2lvbjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcnVudGltZVBsYXRmb3JtVG9TdHJpbmcoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLm9zVmVyc2lvblBhaXIubmFtZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0QnJvd3NlclZlcnNpb25TdHJpbmcoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHVhOnN0cmluZyA9IG5hdmlnYXRvci51c2VyQWdlbnQ7XG4gICAgICAgICAgICAgICAgdmFyIHRlbTpSZWdFeHBNYXRjaEFycmF5O1xuICAgICAgICAgICAgICAgIHZhciBNOlJlZ0V4cE1hdGNoQXJyYXkgPSB1YS5tYXRjaCgvKG9wZXJhfGNocm9tZXxzYWZhcml8ZmlyZWZveHx1YnJvd3Nlcnxtc2llfHRyaWRlbnR8ZmJhdig/PVxcLykpXFwvP1xccyooXFxkKykvaSkgfHwgW107XG5cbiAgICAgICAgICAgICAgICBpZigvdHJpZGVudC9pLnRlc3QoTVsxXSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0ZW0gPSAvXFxicnZbIDpdKyhcXGQrKS9nLmV4ZWModWEpIHx8IFtdO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gJ0lFICcgKyAodGVtWzFdIHx8ICcnKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihNWzFdID09PSAnQ2hyb21lJylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IHVhLm1hdGNoKC9cXGIoT1BSfEVkZ2V8VUJyb3dzZXIpXFwvKFxcZCspLyk7XG4gICAgICAgICAgICAgICAgICAgIGlmKHRlbSE9IG51bGwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0ZW0uc2xpY2UoMSkuam9pbignICcpLnJlcGxhY2UoJ09QUicsICdPcGVyYScpLnJlcGxhY2UoJ1VCcm93c2VyJywgJ1VDJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0udG9Mb3dlckNhc2UoKSA9PT0gJ2ZiYXYnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVsxXSA9IFwiZmFjZWJvb2tcIjtcblxuICAgICAgICAgICAgICAgICAgICBpZihNWzJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJmYWNlYm9vayBcIiArIE1bMl07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgTVN0cmluZzpzdHJpbmdbXSA9IE1bMl0/IFtNWzFdLCBNWzJdXTogW25hdmlnYXRvci5hcHBOYW1lLCBuYXZpZ2F0b3IuYXBwVmVyc2lvbiwgJy0/J107XG5cbiAgICAgICAgICAgICAgICBpZigodGVtID0gdWEubWF0Y2goL3ZlcnNpb25cXC8oXFxkKykvaSkpICE9IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBNU3RyaW5nLnNwbGljZSgxLCAxLCB0ZW1bMV0pO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBNU3RyaW5nLmpvaW4oJyAnKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXREZXZpY2VNb2RlbCgpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6c3RyaW5nID0gXCJ1bmtub3duXCI7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXREZXZpY2VNYW51ZmFjdHVyZXIoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwidW5rbm93blwiO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWF0Y2hJdGVtKGFnZW50OnN0cmluZywgZGF0YTpBcnJheTxOYW1lVmFsdWVWZXJzaW9uPik6TmFtZVZlcnNpb25cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0Ok5hbWVWZXJzaW9uID0gbmV3IE5hbWVWZXJzaW9uKFwidW5rbm93blwiLCBcIjAuMC4wXCIpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGk6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgajpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciByZWdleDpSZWdFeHA7XG4gICAgICAgICAgICAgICAgdmFyIHJlZ2V4djpSZWdFeHA7XG4gICAgICAgICAgICAgICAgdmFyIG1hdGNoOmJvb2xlYW47XG4gICAgICAgICAgICAgICAgdmFyIG1hdGNoZXM6UmVnRXhwTWF0Y2hBcnJheTtcbiAgICAgICAgICAgICAgICB2YXIgbWF0aGNlc1Jlc3VsdDpzdHJpbmc7XG4gICAgICAgICAgICAgICAgdmFyIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgZm9yIChpID0gMDsgaSA8IGRhdGEubGVuZ3RoOyBpICs9IDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZWdleCA9IG5ldyBSZWdFeHAoZGF0YVtpXS52YWx1ZSwgJ2knKTtcbiAgICAgICAgICAgICAgICAgICAgbWF0Y2ggPSByZWdleC50ZXN0KGFnZW50KTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGNoKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZWdleHYgPSBuZXcgUmVnRXhwKGRhdGFbaV0udmVyc2lvbiArICdbLSAvOjtdKFtcXFxcZC5fXSspJywgJ2knKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIG1hdGNoZXMgPSBhZ2VudC5tYXRjaChyZWdleHYpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmVyc2lvbiA9ICcnO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGNoZXMpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGNoZXNbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXRoY2VzUmVzdWx0ID0gbWF0Y2hlc1sxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0aGNlc1Jlc3VsdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbWF0Y2hlc0FycmF5OnN0cmluZ1tdID0gbWF0aGNlc1Jlc3VsdC5zcGxpdCgvWy5fXSsvKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGogPSAwOyBqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMyk7IGogKz0gMSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gKz0gbWF0Y2hlc0FycmF5W2pdICsgKGogPCBNYXRoLm1pbihtYXRjaGVzQXJyYXkubGVuZ3RoLCAzKSAtIDEgPyAnLicgOiAnJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gPSAnMC4wLjAnO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQubmFtZSA9IGRhdGFbaV0ubmFtZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC52ZXJzaW9uID0gdmVyc2lvbjtcblxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIMKgwqDCoMKgwqDCoMKgwqB9XG4gICAgICAgICAgICDCoMKgwqDCoH1cblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGhyZWFkaW5nXG4gICAge1xuICAgICAgICBleHBvcnQgY2xhc3MgVGltZWRCbG9ja1xuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgcmVhZG9ubHkgZGVhZGxpbmU6RGF0ZTtcbiAgICAgICAgICAgIHB1YmxpYyBibG9jazooKSA9PiB2b2lkO1xuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGlkOm51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBpZ25vcmU6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBhc3luYzpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHJ1bm5pbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGlkQ291bnRlcjpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IoZGVhZGxpbmU6RGF0ZSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlYWRsaW5lID0gZGVhZGxpbmU7XG4gICAgICAgICAgICAgICAgdGhpcy5pZ25vcmUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICB0aGlzLmFzeW5jID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgdGhpcy5ydW5uaW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgdGhpcy5pZCA9ICsrVGltZWRCbG9jay5pZENvdW50ZXI7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGhyZWFkaW5nXG4gICAge1xuICAgICAgICBleHBvcnQgaW50ZXJmYWNlIElDb21wYXJlcjxUPlxuICAgICAgICB7XG4gICAgICAgICAgICBjb21wYXJlKHg6VCwgeTpUKTogbnVtYmVyO1xuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFByaW9yaXR5UXVldWU8VEl0ZW0+XG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBfc3ViUXVldWVzOntba2V5Om51bWJlcl06IEFycmF5PFRJdGVtPn07XG4gICAgICAgICAgICBwdWJsaWMgX3NvcnRlZEtleXM6QXJyYXk8bnVtYmVyPjtcbiAgICAgICAgICAgIHByaXZhdGUgY29tcGFyZXI6SUNvbXBhcmVyPG51bWJlcj47XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3Rvcihwcmlvcml0eUNvbXBhcmVyOklDb21wYXJlcjxudW1iZXI+KVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuY29tcGFyZXIgPSBwcmlvcml0eUNvbXBhcmVyO1xuICAgICAgICAgICAgICAgIHRoaXMuX3N1YlF1ZXVlcyA9IHt9O1xuICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMgPSBbXTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGVucXVldWUocHJpb3JpdHk6bnVtYmVyLCBpdGVtOlRJdGVtKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHRoaXMuX3NvcnRlZEtleXMuaW5kZXhPZihwcmlvcml0eSkgPT09IC0xKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hZGRRdWV1ZU9mUHJpb3JpdHkocHJpb3JpdHkpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRoaXMuX3N1YlF1ZXVlc1twcmlvcml0eV0ucHVzaChpdGVtKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhZGRRdWV1ZU9mUHJpb3JpdHkocHJpb3JpdHk6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMucHVzaChwcmlvcml0eSk7XG4gICAgICAgICAgICAgICAgdGhpcy5fc29ydGVkS2V5cy5zb3J0KCh4Om51bWJlciwgeTpudW1iZXIpID0+IHRoaXMuY29tcGFyZXIuY29tcGFyZSh4LCB5KSk7XG4gICAgICAgICAgICAgICAgdGhpcy5fc3ViUXVldWVzW3ByaW9yaXR5XSA9IFtdO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgcGVlaygpOiBUSXRlbVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHRoaXMuaGFzSXRlbXMoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLl9zdWJRdWV1ZXNbdGhpcy5fc29ydGVkS2V5c1swXV1bMF07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlRoZSBxdWV1ZSBpcyBlbXB0eVwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBoYXNJdGVtcygpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3NvcnRlZEtleXMubGVuZ3RoID4gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIGRlcXVldWUoKTogVEl0ZW1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih0aGlzLmhhc0l0ZW1zKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5kZXF1ZXVlRnJvbUhpZ2hQcmlvcml0eVF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlRoZSBxdWV1ZSBpcyBlbXB0eVwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZGVxdWV1ZUZyb21IaWdoUHJpb3JpdHlRdWV1ZSgpOiBUSXRlbVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBmaXJzdEtleTpudW1iZXIgPSB0aGlzLl9zb3J0ZWRLZXlzWzBdO1xuICAgICAgICAgICAgICAgIHZhciBuZXh0SXRlbTpUSXRlbSA9IHRoaXMuX3N1YlF1ZXVlc1tmaXJzdEtleV0uc2hpZnQoKTtcbiAgICAgICAgICAgICAgICBpZih0aGlzLl9zdWJRdWV1ZXNbZmlyc3RLZXldLmxlbmd0aCA9PT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgZGVsZXRlIHRoaXMuX3N1YlF1ZXVlc1tmaXJzdEtleV07XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIG5leHRJdGVtO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0b3JlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVBcmdzT3BlcmF0b3JcbiAgICAgICAge1xuICAgICAgICAgICAgRXF1YWwsXG4gICAgICAgICAgICBMZXNzT3JFcXVhbCxcbiAgICAgICAgICAgIE5vdEVxdWFsXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgZW51bSBFR0FTdG9yZVxuICAgICAgICB7XG4gICAgICAgICAgICBFdmVudHMgPSAwLFxuICAgICAgICAgICAgU2Vzc2lvbnMgPSAxLFxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24gPSAyXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdG9yZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0b3JlID0gbmV3IEdBU3RvcmUoKTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3JhZ2VBdmFpbGFibGU6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heE51bWJlck9mRW50cmllczpudW1iZXIgPSAyMDAwO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBzZXNzaW9uc1N0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHByb2dyZXNzaW9uU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RvcmVJdGVtczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBLZXlQcmVmaXg6c3RyaW5nID0gXCJHQTo6XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBFdmVudHNTdG9yZUtleTpzdHJpbmcgPSBcImdhX2V2ZW50XCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBTZXNzaW9uc1N0b3JlS2V5OnN0cmluZyA9IFwiZ2Ffc2Vzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgUHJvZ3Jlc3Npb25TdG9yZUtleTpzdHJpbmcgPSBcImdhX3Byb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBJdGVtc1N0b3JlS2V5OnN0cmluZyA9IFwiZ2FfaXRlbXNcIjtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGxvY2FsU3RvcmFnZSA9PT0gJ29iamVjdCcpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJywgJ3llcycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ3Rlc3RpbmdMb2NhbFN0b3JhZ2UnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZSA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlN0b3JhZ2UgaXMgYXZhaWxhYmxlPzogXCIgKyBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzU3RvcmFnZUF2YWlsYWJsZSgpOmJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUubGVuZ3RoICsgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlLmxlbmd0aCA+IEdBU3RvcmUuTWF4TnVtYmVyT2ZFbnRyaWVzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNlbGVjdChzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSwgc29ydDpib29sZWFuID0gZmFsc2UsIG1heENvdW50Om51bWJlciA9IDApOiBBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGFkZDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhZGQgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFhZGQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihhZGQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5wdXNoKGVudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHNvcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXN1bHQuc29ydCgoYTp7W2tleTpzdHJpbmddOiBhbnl9LCBiOntba2V5OnN0cmluZ106IGFueX0pID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiAoYVtcImNsaWVudF90c1wiXSBhcyBudW1iZXIpIC0gKGJbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKVxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihtYXhDb3VudCA+IDAgJiYgcmVzdWx0Lmxlbmd0aCA+IG1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gcmVzdWx0LnNsaWNlKDAsIG1heENvdW50ICsgMSlcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVwZGF0ZShzdG9yZTpFR0FTdG9yZSwgc2V0QXJnczpBcnJheTxbc3RyaW5nLCBhbnldPiwgd2hlcmVBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldPiA9IFtdKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGU6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCB3aGVyZUFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSB3aGVyZUFyZ3Nbal07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXVwZGF0ZSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKHVwZGF0ZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IHNldEFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNldEFyZ3NFbnRyeTpbc3RyaW5nLCBhbnldID0gc2V0QXJnc1tqXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzZXRBcmdzRW50cnlbMF1dID0gc2V0QXJnc0VudHJ5WzFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZGVsZXRlKHN0b3JlOkVHQVN0b3JlLCBhcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgZGVsOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgYXJncy5sZW5ndGg7ICsrailcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFyZ3NFbnRyeTpbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XSA9IGFyZ3Nbal07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWRlbClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGRlbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnNwbGljZShpLCAxKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC0taTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbnNlcnQoc3RvcmU6RUdBU3RvcmUsIG5ld0VudHJ5Ontba2V5OnN0cmluZ106IGFueX0sIHJlcGxhY2U6Ym9vbGVhbiA9IGZhbHNlLCByZXBsYWNlS2V5OnN0cmluZyA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZXBsYWNlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoIXJlcGxhY2VLZXkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHZhciByZXBsYWNlZDpib29sZWFuID0gZmFsc2U7XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W3JlcGxhY2VLZXldID09IG5ld0VudHJ5W3JlcGxhY2VLZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBuZXdFbnRyeSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudHJ5W3NdID0gbmV3RW50cnlbc107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcGxhY2VkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnB1c2gobmV3RW50cnkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2F2ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3Qgc2F2ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuRXZlbnRzU3RvcmVLZXksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlByb2dyZXNzaW9uU3RvcmVLZXksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSkpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5JdGVtc1N0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBsb2FkKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTdG9yYWdlIGlzIG5vdCBhdmFpbGFibGUsIGNhbm5vdCBsb2FkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnZXZlbnRzJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ3Nlc3Npb25zJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlByb2dyZXNzaW9uU3RvcmVLZXkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAncHJvZ3Jlc3Npb24nIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuSXRlbXNTdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcyA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdpdGVtcycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEl0ZW0oa2V5OnN0cmluZywgdmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuS2V5UHJlZml4ICsga2V5O1xuXG4gICAgICAgICAgICAgICAgaWYoIXZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoa2V5V2l0aFByZWZpeCBpbiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEl0ZW0oa2V5OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuS2V5UHJlZml4ICsga2V5O1xuICAgICAgICAgICAgICAgIGlmKGtleVdpdGhQcmVmaXggaW4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XSBhcyBzdHJpbmc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0U3RvcmUoc3RvcmU6RUdBU3RvcmUpOiBBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaChzdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuRXZlbnRzOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuU2Vzc2lvbnM6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlByb2dyZXNzaW9uOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkdBU3RvcmUuZ2V0U3RvcmUoKTogQ2Fubm90IGZpbmQgc3RvcmU6IFwiICsgc3RvcmUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgc3RhdGVcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVZhbGlkYXRvciA9IGdhbWVhbmFseXRpY3MudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkdBU3RvcmU7XG4gICAgICAgIGltcG9ydCBHQURldmljZSA9IGdhbWVhbmFseXRpY3MuZGV2aWNlLkdBRGV2aWNlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVN0YXRlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2RrRXJyb3I6c3RyaW5nID0gXCJzZGtfZXJyb3JcIjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0YXRlID0gbmV3IEdBU3RhdGUoKTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgdXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0VXNlcklkKHVzZXJJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQgPSB1c2VySWQ7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBpZGVudGlmaWVyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SWRlbnRpZmllcigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGluaXRpYWxpemVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzSW5pdGlhbGl6ZWQoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbml0aWFsaXplZCh2YWx1ZTpib29sZWFuKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25TdGFydDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25TdGFydCgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB0cmFuc2FjdGlvbk51bTpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFRyYW5zYWN0aW9uTnVtKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvbklkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbklkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAzOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lS2V5OnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZUtleSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVTZWNyZXQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lU2VjcmV0KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMzpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGJ1aWxkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QnVpbGQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEJ1aWxkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBidWlsZCB2ZXJzaW9uOiBcIiArIHZhbHVlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZmFjZWJvb2tJZDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGdlbmRlcjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGJpcnRoWWVhcjpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnQ2FjaGVkOntba2V5OnN0cmluZ106IGFueX07XG4gICAgICAgICAgICBwdWJsaWMgaW5pdEF1dGhvcml6ZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBjbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0Om51bWJlcjtcblxuICAgICAgICAgICAgcHJpdmF0ZSBkZWZhdWx0VXNlcklkOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgc2V0RGVmYXVsdElkKHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmRlZmF1bHRVc2VySWQgPSAhdmFsdWUgPyBcIlwiIDogdmFsdWU7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5jYWNoZUlkZW50aWZpZXIoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RGVmYXVsdElkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWdEZWZhdWx0Ontba2V5OnN0cmluZ106IHN0cmluZ30gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRTZGtDb25maWcoKToge1trZXk6c3RyaW5nXTogYW55fVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0O1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqc29uIGluIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZmlyc3QgJiYgY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWc7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZmlyc3Q7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGpzb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0ID0ganNvbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihmaXJzdCAmJiBjb3VudCA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0RlZmF1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25Ucmllczp7W2tleTpzdHJpbmddOiBudW1iZXJ9ID0ge307XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IERlZmF1bHRVc2VySWRLZXk6c3RyaW5nID0gXCJkZWZhdWx0X3VzZXJfaWRcIjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbk51bUtleTpzdHJpbmcgPSBcInNlc3Npb25fbnVtXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFRyYW5zYWN0aW9uTnVtS2V5OnN0cmluZyA9IFwidHJhbnNhY3Rpb25fbnVtXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBGYWNlYm9va0lkS2V5OnN0cmluZyA9IFwiZmFjZWJvb2tfaWRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEdlbmRlcktleTpzdHJpbmcgPSBcImdlbmRlclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQmlydGhZZWFyS2V5OnN0cmluZyA9IFwiYmlydGhfeWVhclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDFLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDJLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDNLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wM1wiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZGtDb25maWdDYWNoZWRLZXk6c3RyaW5nID0gXCJzZGtfY29uZmlnX2NhY2hlZFwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XG5cbiAgICAgICAgICAgICAgICBpZiAoY3VycmVudFNka0NvbmZpZ1tcImVuYWJsZWRcIl0gJiYgY3VycmVudFNka0NvbmZpZ1tcImVuYWJsZWRcIl0gPT0gXCJmYWxzZVwiKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDMoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkID0gZmFjZWJvb2tJZDtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5GYWNlYm9va0lkS2V5LCBmYWNlYm9va0lkKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGZhY2Vib29rIGlkOiBcIiArIGZhY2Vib29rSWQpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEdlbmRlcihnZW5kZXI6RUdBR2VuZGVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyID0gaXNOYU4oTnVtYmVyKEVHQUdlbmRlcltnZW5kZXJdKSkgPyBFR0FHZW5kZXJbZ2VuZGVyXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCkgOiBFR0FHZW5kZXJbRUdBR2VuZGVyW2dlbmRlcl1dLnRvU3RyaW5nKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXksIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGdlbmRlcjogXCIgKyBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QmlydGhZZWFyKGJpcnRoWWVhcjpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5iaXJ0aFllYXIgPSBiaXJ0aFllYXI7XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5LCBiaXJ0aFllYXIudG9TdHJpbmcoKSk7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBiaXJ0aCB5ZWFyOiBcIiArIGJpcnRoWWVhcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50U2Vzc2lvbk51bSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IHNlc3Npb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0cmFuc2FjdGlvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSB0cmFuc2FjdGlvbk51bUludDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJpZXM6bnVtYmVyID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXSA9IHRyaWVzO1xuXG4gICAgICAgICAgICAgICAgLy8gUGVyc2lzdFxuICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInByb2dyZXNzaW9uXCJdID0gcHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgdmFsdWVzW1widHJpZXNcIl0gPSB0cmllcztcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgdmFsdWVzLCB0cnVlLCBcInByb2dyZXNzaW9uXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIERlbGV0ZVxuICAgICAgICAgICAgICAgIHZhciBwYXJtczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBwYXJtcy5wdXNoKFtcInByb2dyZXNzaW9uXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBwcm9ncmVzc2lvbl0pO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlByb2dyZXNzaW9uLCBwYXJtcyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0S2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5ID0gZ2FtZUtleTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQgPSBnYW1lU2VjcmV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmcgPSBmbGFnO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgbWFudWFsIHNlc3Npb24gaGFuZGxpbmc6IFwiICsgZmxhZyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gUkVRVUlSRUQgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJ2XCJdID0gMjtcbiAgICAgICAgICAgICAgICAvLyBVc2VyIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG5cbiAgICAgICAgICAgICAgICAvLyBDbGllbnQgVGltZXN0YW1wICh0aGUgYWRqdXN0ZWQgdGltZXN0YW1wKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2xpZW50X3RzXCJdID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSBtYWtlIChoYXJkY29kZWQgdG8gYXBwbGUpXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImRldmljZVwiXSA9IEdBRGV2aWNlLmRldmljZU1vZGVsO1xuICAgICAgICAgICAgICAgIC8vIEJyb3dzZXIgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnJvd3Nlcl92ZXJzaW9uXCJdID0gR0FEZXZpY2UuYnJvd3NlclZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBpZGVudGlmaWVyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBudW1iZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLlNlc3Npb25OdW1LZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uX3R5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIC0tLS0gQ09ORElUSU9OQUwgLS0tLSAvL1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwIGJ1aWxkIHZlcnNpb24gKHVzZSBpZiBub3QgbmlsKVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJ1aWxkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBPUFRJT05BTCBjcm9zcy1zZXNzaW9uIC0tLS0gLy9cblxuICAgICAgICAgICAgICAgIC8vIGZhY2Vib29rIGlkIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbR0FTdGF0ZS5GYWNlYm9va0lkS2V5XSA9IEdBU3RhdGUuaW5zdGFuY2UuZmFjZWJvb2tJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gZ2VuZGVyIChvcHRpb25hbClcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkdlbmRlcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gYmlydGhfeWVhciAob3B0aW9uYWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkJpcnRoWWVhcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmJpcnRoWWVhcjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGluaXRBbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnRUc0FkanVzdGVkKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHNBZGp1c3RlZEludGVnZXI6bnVtYmVyID0gY2xpZW50VHMgKyBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQ7XG5cbiAgICAgICAgICAgICAgICBpZihHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUc0FkanVzdGVkSW50ZWdlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXNzaW9uSXNTdGFydGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQgIT0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2FjaGVJZGVudGlmaWVyKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UudXNlcklkO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiaWRlbnRpZmllciwge2NsZWFuOlwiICsgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyICsgXCJ9XCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZVBlcnNpc3RlZFN0YXRlcygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gZ2V0IGFuZCBleHRyYWN0IHN0b3JlZCBzdGF0ZXNcbiAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5sb2FkKCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGludG8gR0FTdGF0ZSBpbnN0YW5jZVxuICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZTpHQVN0YXRlID0gR0FTdGF0ZS5pbnN0YW5jZTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNldERlZmF1bHRJZChHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgOiBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCkpO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuU2Vzc2lvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkgIT0gbnVsbCA/IE51bWJlcihHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBjcm9zcyBzZXNzaW9uIHVzZXIgdmFsdWVzXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZmFjZWJvb2tJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXksIGluc3RhbmNlLmZhY2Vib29rSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5mYWNlYm9va0lkID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRmFjZWJvb2tJZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZmFjZWJvb2tJZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZhY2Vib29raWQgZm91bmQgaW4gREI6IFwiICsgaW5zdGFuY2UuZmFjZWJvb2tJZCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXksIGluc3RhbmNlLmdlbmRlcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmdlbmRlciA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkdlbmRlcktleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkdlbmRlcktleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5nZW5kZXIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJnZW5kZXIgZm91bmQgaW4gREI6IFwiICsgaW5zdGFuY2UuZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmJpcnRoWWVhciAmJiBpbnN0YW5jZS5iaXJ0aFllYXIgIT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkJpcnRoWWVhcktleSwgaW5zdGFuY2UuYmlydGhZZWFyLnRvU3RyaW5nKCkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5iaXJ0aFllYXIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5KSkgOiAwO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5iaXJ0aFllYXIgIT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImJpcnRoWWVhciBmb3VuZCBpbiBEQjogXCIgKyBpbnN0YW5jZS5iaXJ0aFllYXIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBkaW1lbnNpb24gc2V0dGluZ3NcbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMSBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDIgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAzIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBnZXQgY2FjaGVkIGluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkU3RyaW5nOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChzZGtDb25maWdDYWNoZWRTdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb246QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5Qcm9ncmVzc2lvbik7XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzdWx0c19nYV9wcm9ncmVzc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzdWx0c19nYV9wcm9ncmVzc2lvbi5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlc3VsdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gcmVzdWx0c19nYV9wcm9ncmVzc2lvbltpXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1tyZXN1bHRbXCJwcm9ncmVzc2lvblwiXSBhcyBzdHJpbmddID0gcmVzdWx0W1widHJpZXNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHM6bnVtYmVyKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudFRzOm51bWJlciA9IEdBVXRpbGl0aWVzLnRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXJ2ZXJUcyAtIGNsaWVudFRzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDEgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMSBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAyIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDIgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMyBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMyhHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAzIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDMoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRhc2tzXG4gICAge1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JUeXBlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQVNka0Vycm9yVHlwZTtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgU2RrRXJyb3JUYXNrXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heENvdW50Om51bWJlciA9IDEwO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgY291bnRNYXA6e1trZXk6bnVtYmVyXTogbnVtYmVyfSA9IHt9O1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGV4ZWN1dGUodXJsOnN0cmluZywgdHlwZTpFR0FTZGtFcnJvclR5cGUsIHBheWxvYWREYXRhOnN0cmluZywgc2VjcmV0S2V5OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPj0gU2RrRXJyb3JUYXNrLk1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2YXIgaGFzaEhtYWM6c3RyaW5nID0gR0FVdGlsaXRpZXMuZ2V0SG1hYyhzZWNyZXRLZXksIHBheWxvYWREYXRhKTtcblxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZighcmVxdWVzdC5yZXNwb25zZVRleHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNkayBlcnJvciBmYWlsZWQuIE1pZ2h0IGJlIG5vIGNvbm5lY3Rpb24uIERlc2NyaXB0aW9uOiBcIiArIHJlcXVlc3Quc3RhdHVzVGV4dCArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByZXF1ZXN0LnN0YXR1cyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihyZXF1ZXN0LnN0YXR1cyAhPSAyMDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNkayBlcnJvciBmYWlsZWQuIHJlc3BvbnNlIGNvZGUgbm90IDIwMC4gc3RhdHVzIGNvZGU6IFwiICsgcmVxdWVzdC5zdGF0dXMgKyBcIiwgZGVzY3JpcHRpb246IFwiICsgcmVxdWVzdC5zdGF0dXNUZXh0ICsgXCIsIGJvZHk6IFwiICsgcmVxdWVzdC5yZXNwb25zZVRleHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gKyAxO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIHJlcXVlc3Qub3BlbihcIlBPU1RcIiwgdXJsLCB0cnVlKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uXCIpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkF1dGhvcml6YXRpb25cIiwgaGFzaEhtYWMpO1xuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnNlbmQocGF5bG9hZERhdGEpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhbWVhbmFseXRpY3Muc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XG4gICAgICAgIGltcG9ydCBTZGtFcnJvclRhc2sgPSBnYW1lYW5hbHl0aWNzLnRhc2tzLlNka0Vycm9yVGFzaztcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIVFRQQXBpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm90b2NvbDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGhvc3ROYW1lOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGJhc2VVcmw6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbml0aWFsaXplVXJsUGF0aDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGV2ZW50c1VybFBhdGg6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSB1c2VHemlwOmJvb2xlYW47XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGJhc2UgdXJsIHNldHRpbmdzXG4gICAgICAgICAgICAgICAgdGhpcy5wcm90b2NvbCA9IFwiaHR0cHNcIjtcbiAgICAgICAgICAgICAgICB0aGlzLmhvc3ROYW1lID0gXCJhcGkuZ2FtZWFuYWx5dGljcy5jb21cIjtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSBcInYyXCI7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYmFzZSB1cmxcbiAgICAgICAgICAgICAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLnByb3RvY29sICsgXCI6Ly9cIiArIHRoaXMuaG9zdE5hbWUgKyBcIi9cIiArIHRoaXMudmVyc2lvbjtcblxuICAgICAgICAgICAgICAgIHRoaXMuaW5pdGlhbGl6ZVVybFBhdGggPSBcImluaXRcIjtcbiAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1VybFBhdGggPSBcImV2ZW50c1wiO1xuXG4gICAgICAgICAgICAgICAgdGhpcy51c2VHemlwID0gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyByZXF1ZXN0SW5pdChjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0pID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5pbml0aWFsaXplVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnaW5pdCcgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldEluaXRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBKU09OIHN0cmluZyBmcm9tIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShpbml0QW5ub3RhdGlvbnMpO1xuXG4gICAgICAgICAgICAgICAgaWYoIUpTT05zdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCwgbnVsbCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGE6c3RyaW5nID0gdGhpcy5jcmVhdGVQYXlsb2FkRGF0YShKU09Oc3RyaW5nLCB0aGlzLnVzZUd6aXApO1xuICAgICAgICAgICAgICAgIHZhciBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5zZW5kUmVxdWVzdCh1cmwsIHBheWxvYWREYXRhLCBleHRyYUFyZ3MsIHRoaXMudXNlR3ppcCwgR0FIVFRQQXBpLmluaXRSZXF1ZXN0Q2FsbGJhY2ssIGNhbGxiYWNrKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNlbmRFdmVudHNJbkFycmF5KGV2ZW50QXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4sIHJlcXVlc3RJZDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoZXZlbnRBcnJheS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBjYWxsZWQgd2l0aCBtaXNzaW5nIGV2ZW50QXJyYXlcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmV2ZW50c1VybFBhdGg7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICAvLyBtYWtlIEpTT04gc3RyaW5nIGZyb20gZGF0YVxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2ZW50QXJyYXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIUpTT05zdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZEV2ZW50c0luQXJyYXkgSlNPTiBlbmNvZGluZyBmYWlsZWQgb2YgZXZlbnRBcnJheVwiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQsIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRBcnJheS5sZW5ndGgpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhID0gdGhpcy5jcmVhdGVQYXlsb2FkRGF0YShKU09Oc3RyaW5nLCB0aGlzLnVzZUd6aXApO1xuICAgICAgICAgICAgICAgIHZhciBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKHJlcXVlc3RJZCk7XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goZXZlbnRBcnJheS5sZW5ndGgudG9TdHJpbmcoKSk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnNlbmRSZXF1ZXN0KHVybCwgcGF5bG9hZERhdGEsIGV4dHJhQXJncywgdGhpcy51c2VHemlwLCBHQUhUVFBBcGkuc2VuZEV2ZW50SW5BcnJheVJlcXVlc3RDYWxsYmFjaywgY2FsbGJhY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZFNka0Vycm9yRXZlbnQodHlwZTpFR0FTZGtFcnJvclR5cGUpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XG4gICAgICAgICAgICAgICAgdmFyIHNlY3JldEtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKTtcblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka0Vycm9yRXZlbnQoZ2FtZUtleSwgc2VjcmV0S2V5LCB0eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBVUkxcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5ldmVudHNVcmxQYXRoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdldmVudHMnIFVSTDogXCIgKyB1cmwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWRKU09OU3RyaW5nOnN0cmluZyA9IFwiXCI7XG5cbiAgICAgICAgICAgICAgICB2YXIganNvbjp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRTZGtFcnJvckV2ZW50QW5ub3RhdGlvbnMoKTtcblxuICAgICAgICAgICAgICAgIHZhciB0eXBlU3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvclR5cGVUb1N0cmluZyh0eXBlKTtcbiAgICAgICAgICAgICAgICBqc29uW1widHlwZVwiXSA9IHR5cGVTdHJpbmc7XG5cbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgICAgIGV2ZW50QXJyYXkucHVzaChqc29uKTtcbiAgICAgICAgICAgICAgICBwYXlsb2FkSlNPTlN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2ZW50QXJyYXkpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXBheWxvYWRKU09OU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNlbmRTZGtFcnJvckV2ZW50OiBKU09OIGVuY29kaW5nIGZhaWxlZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2VuZFNka0Vycm9yRXZlbnQganNvbjogXCIgKyBwYXlsb2FkSlNPTlN0cmluZyk7XG4gICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmV4ZWN1dGUodXJsLCB0eXBlLCBwYXlsb2FkSlNPTlN0cmluZywgc2VjcmV0S2V5KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2VuZEV2ZW50SW5BcnJheVJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+ID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBleHRyYVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkOnN0cmluZyA9IGV4dHJhWzJdO1xuICAgICAgICAgICAgICAgIHZhciBldmVudENvdW50Om51bWJlciA9IHBhcnNlSW50KGV4dHJhWzNdKTtcbiAgICAgICAgICAgICAgICB2YXIgYm9keTpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIGJvZHkgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJldmVudHMgcmVxdWVzdCBjb250ZW50OiBcIiArIGJvZHkpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RSZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlID0gR0FIVFRQQXBpLmluc3RhbmNlLnByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlLCByZXF1ZXN0LnN0YXR1c1RleHQsIGJvZHksIFwiRXZlbnRzXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiByZXF1ZXN0UmVzcG9uc2VFbnVtICE9IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBldmVudHMgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGRlY29kZSBKU09OXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcblxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RKc29uRGljdCA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBwcmludCByZWFzb24gaWYgYmFkIHJlcXVlc3RcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtID09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBFdmVudHMgQ2FsbC4gQmFkIHJlcXVlc3QuIFJlc3BvbnNlOiBcIiArIEpTT04uc3RyaW5naWZ5KHJlcXVlc3RKc29uRGljdCkpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHJldHVybiByZXNwb25zZVxuICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIHJlcXVlc3RKc29uRGljdCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2VuZFJlcXVlc3QodXJsOnN0cmluZywgcGF5bG9hZERhdGE6c3RyaW5nLCBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiwgZ3ppcDpib29sZWFuLCBjYWxsYmFjazoocmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPikgPT4gdm9pZCwgY2FsbGJhY2syOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcblxuICAgICAgICAgICAgICAgIC8vIGNyZWF0ZSBhdXRob3JpemF0aW9uIGhhc2hcbiAgICAgICAgICAgICAgICB2YXIga2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpO1xuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoa2V5LCBwYXlsb2FkRGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKGF1dGhvcml6YXRpb24pO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGV4dHJhQXJncylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFyZ3MucHVzaChleHRyYUFyZ3Nbc10pO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJlcXVlc3Qub25yZWFkeXN0YXRlY2hhbmdlID0gKCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBpZihyZXF1ZXN0LnJlYWR5U3RhdGUgPT09IDQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3QsIHVybCwgY2FsbGJhY2syLCBhcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwidGV4dC9wbGFpblwiKTtcblxuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkF1dGhvcml6YXRpb25cIiwgYXV0aG9yaXphdGlvbik7XG5cbiAgICAgICAgICAgICAgICBpZihnemlwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICAvL3JlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtRW5jb2RpbmdcIiwgXCJnemlwXCIpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5zZW5kKHBheWxvYWREYXRhKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBpbml0UmVxdWVzdENhbGxiYWNrKHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSkgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGF1dGhvcml6YXRpb246c3RyaW5nID0gZXh0cmFbMF07XG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgcmVzcG9uc2VDb2RlOm51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XG4gICAgICAgICAgICAgICAgcmVzcG9uc2VDb2RlID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgICAvLyBwcm9jZXNzIHRoZSByZXNwb25zZVxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJpbml0IHJlcXVlc3QgY29udGVudCA6IFwiICsgYm9keSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdEpzb25EaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSBib2R5ID8gSlNPTi5wYXJzZShib2R5KSA6IHt9O1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0UmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSA9IEdBSFRUUEFwaS5pbnN0YW5jZS5wcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZSwgcmVxdWVzdC5zdGF0dXNUZXh0LCBib2R5LCBcIkluaXRcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBpZiBub3QgMjAwIHJlc3VsdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgSW5pdCBDYWxsLiBKc29uIGRlY29kaW5nIGZhaWxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25EZWNvZGVGYWlsZWQsIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gQmFkIHJlcXVlc3QuIFJlc3BvbnNlOiBcIiArIEpTT04uc3RyaW5naWZ5KHJlcXVlc3RKc29uRGljdCkpO1xuICAgICAgICAgICAgICAgICAgICAvLyByZXR1cm4gYmFkIHJlcXVlc3QgcmVzdWx0XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgSW5pdCBjYWxsIHZhbHVlc1xuICAgICAgICAgICAgICAgIHZhciB2YWxpZGF0ZWRJbml0VmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSBHQVZhbGlkYXRvci52YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShyZXF1ZXN0SnNvbkRpY3QpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXZhbGlkYXRlZEluaXRWYWx1ZXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVzcG9uc2UsIG51bGwpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gYWxsIG9rXG4gICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLk9rLCB2YWxpZGF0ZWRJbml0VmFsdWVzKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjcmVhdGVQYXlsb2FkRGF0YShwYXlsb2FkOnN0cmluZywgZ3ppcDpib29sZWFuKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmKGd6aXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBwYXlsb2FkRGF0YSA9IEdBVXRpbGl0aWVzLkd6aXBDb21wcmVzcyhwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gR0FMb2dnZXIuRChcIkd6aXAgc3RhdHMuIFNpemU6IFwiICsgRW5jb2RpbmcuVVRGOC5HZXRCeXRlcyhwYXlsb2FkKS5MZW5ndGggKyBcIiwgQ29tcHJlc3NlZDogXCIgKyBwYXlsb2FkRGF0YS5MZW5ndGggKyBcIiwgQ29udGVudDogXCIgKyBwYXlsb2FkKTtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBwYXlsb2FkRGF0YSA9IHBheWxvYWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHBheWxvYWREYXRhO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlOm51bWJlciwgcmVzcG9uc2VNZXNzYWdlOnN0cmluZywgYm9keTpzdHJpbmcsIHJlcXVlc3RJZDpzdHJpbmcpOiBFR0FIVFRQQXBpUmVzcG9uc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBpZiBubyByZXN1bHQgLSBvZnRlbiBubyBjb25uZWN0aW9uXG4gICAgICAgICAgICAgICAgaWYoIWJvZHkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgcmVzcG9uc2VNZXNzYWdlICsgXCIsIFN0YXR1cyBjb2RlOiBcIiArIHJlc3BvbnNlQ29kZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBva1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDIwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuT2s7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gNDAxIGNhbiByZXR1cm4gMCBzdGF0dXNcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSAwIHx8IHJlc3BvbnNlQ29kZSA9PT0gNDAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA0MDEgLSBVbmF1dGhvcml6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLlVuYXV0aG9yaXplZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSA0MDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMCAtIEJhZCBSZXF1ZXN0LlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0O1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZUNvZGUgPT09IDUwMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNTAwIC0gSW50ZXJuYWwgU2VydmVyIEVycm9yLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5JbnRlcm5hbFNlcnZlckVycm9yO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2RrRXJyb3JUeXBlVG9TdHJpbmcodmFsdWU6RUdBU2RrRXJyb3JUeXBlKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgc3dpdGNoKHZhbHVlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQ6XG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwicmVqZWN0ZWRcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmUgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlO1xuICAgICAgICBpbXBvcnQgRUdBU3RvcmVBcmdzT3BlcmF0b3IgPSBnYW1lYW5hbHl0aWNzLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xuICAgICAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYW1lYW5hbHl0aWNzLnV0aWxpdGllcy5HQVV0aWxpdGllcztcbiAgICAgICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FIVFRQQXBpUmVzcG9uc2U7XG4gICAgICAgIGltcG9ydCBHQUhUVFBBcGkgPSBnYW1lYW5hbHl0aWNzLmh0dHAuR0FIVFRQQXBpO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvclR5cGUgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBU2RrRXJyb3JUeXBlO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUV2ZW50c1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUV2ZW50cyA9IG5ldyBHQUV2ZW50cygpO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ6c3RyaW5nID0gXCJ1c2VyXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNlc3Npb25FbmQ6c3RyaW5nID0gXCJzZXNzaW9uX2VuZFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlEZXNpZ246c3RyaW5nID0gXCJkZXNpZ25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QnVzaW5lc3M6c3RyaW5nID0gXCJidXNpbmVzc1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlQcm9ncmVzc2lvbjpzdHJpbmcgPSBcInByb2dyZXNzaW9uXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVJlc291cmNlOnN0cmluZyA9IFwicmVzb3VyY2VcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RXJyb3I6c3RyaW5nID0gXCJlcnJvclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4RXZlbnRDb3VudDpudW1iZXIgPSA1MDA7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIEV2ZW50IHNwZWNpZmljIGRhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0O1xuXG4gICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IHNlc3Npb24gbnVtYmVyICBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50U2Vzc2lvbk51bSgpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXksIEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBTRVNTSU9OIFNUQVJUIGV2ZW50XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBldmVudCByaWdodCBhd2F5XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydCwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25FbmRFdmVudCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25fc3RhcnRfdHM6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50X3RzX2FkanVzdGVkOm51bWJlciA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uTGVuZ3RoOm51bWJlciA9IGNsaWVudF90c19hZGp1c3RlZCAtIHNlc3Npb25fc3RhcnRfdHM7XG5cbiAgICAgICAgICAgICAgICBpZihzZXNzaW9uTGVuZ3RoIDwgMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFNob3VsZCBuZXZlciBoYXBwZW4uXG4gICAgICAgICAgICAgICAgICAgIC8vIENvdWxkIGJlIGJlY2F1c2Ugb2YgZWRnZSBjYXNlcyByZWdhcmRpbmcgdGltZSBhbHRlcmluZyBvbiBkZXZpY2UuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTZXNzaW9uIGxlbmd0aCB3YXMgY2FsY3VsYXRlZCB0byBiZSBsZXNzIHRoZW4gMC4gU2hvdWxkIG5vdCBiZSBwb3NzaWJsZS4gUmVzZXR0aW5nIHRvIDAuXCIpO1xuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uTGVuZ3RoID0gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wibGVuZ3RoXCJdID0gc2Vzc2lvbkxlbmd0aDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBFTkQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBhbGwgZXZlbnQgcmlnaHQgYXdheVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoXCJcIiwgZmFsc2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGNhcnRUeXBlOnN0cmluZyA9IG51bGwpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3ksIGFtb3VudCwgY2FydFR5cGUsIGl0ZW1UeXBlLCBpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgdHJhbnNhY3Rpb24gbnVtYmVyIGFuZCBwZXJzaXN0XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRUcmFuc2FjdGlvbk51bSgpO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5LCBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkudG9TdHJpbmcoKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBSZXF1aXJlZFxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QnVzaW5lc3M7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY3VycmVuY3lcIl0gPSBjdXJyZW5jeTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhbW91bnRcIl0gPSBhbW91bnQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W0dBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXldID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gT3B0aW9uYWxcbiAgICAgICAgICAgICAgICBpZiAoY2FydFR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXJ0X3R5cGVcIl0gPSBjYXJ0VHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBCVVNJTkVTUyBldmVudDoge2N1cnJlbmN5OlwiICsgY3VycmVuY3kgKyBcIiwgYW1vdW50OlwiICsgYW1vdW50ICsgXCIsIGl0ZW1UeXBlOlwiICsgaXRlbVR5cGUgKyBcIiwgaXRlbUlkOlwiICsgaXRlbUlkICsgXCIsIGNhcnRUeXBlOlwiICsgY2FydFR5cGUgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlLCBjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgR0FTdGF0ZS5nZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gSWYgZmxvdyB0eXBlIGlzIHNpbmsgcmV2ZXJzZSBhbW91bnRcbiAgICAgICAgICAgICAgICBpZiAoZmxvd1R5cGUgPT09IEVHQVJlc291cmNlRmxvd1R5cGUuU2luaylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFtb3VudCAqPSAtMTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgZXZlbnQgc3BlY2lmaWMgdmFsdWVzXG4gICAgICAgICAgICAgICAgdmFyIGZsb3dUeXBlU3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLnJlc291cmNlRmxvd1R5cGVUb1N0cmluZyhmbG93VHlwZSk7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiZXZlbnRfaWRcIl0gPSBmbG93VHlwZVN0cmluZyArIFwiOlwiICsgY3VycmVuY3kgKyBcIjpcIiArIGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVJlc291cmNlO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImFtb3VudFwiXSA9IGFtb3VudDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFJFU09VUkNFIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZywgc2NvcmU6bnVtYmVyLCBzZW5kU2NvcmU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyhwcm9ncmVzc2lvblN0YXR1cyk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIFByb2dyZXNzaW9uIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25JZGVudGlmaWVyOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmICghcHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKCFwcm9ncmVzc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVByb2dyZXNzaW9uO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIjpcIiArIHByb2dyZXNzaW9uSWRlbnRpZmllcjtcblxuICAgICAgICAgICAgICAgIC8vIEF0dGVtcHRcbiAgICAgICAgICAgICAgICB2YXIgYXR0ZW1wdF9udW06bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBzY29yZSBpZiBzcGVjaWZpZWQgYW5kIHN0YXR1cyBpcyBub3Qgc3RhcnRcbiAgICAgICAgICAgICAgICBpZiAoc2VuZFNjb3JlICYmIHByb2dyZXNzaW9uU3RhdHVzICE9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wic2NvcmVcIl0gPSBzY29yZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDb3VudCBhdHRlbXB0cyBvbiBlYWNoIHByb2dyZXNzaW9uIGZhaWwgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgYXR0ZW1wdCBudW1iZXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5jcmVtZW50IGFuZCBhZGQgYXR0ZW1wdF9udW0gb24gY29tcGxldGUgYW5kIGRlbGV0ZSBwZXJzaXN0ZWRcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBldmVudFxuICAgICAgICAgICAgICAgICAgICBhdHRlbXB0X251bSA9IEdBU3RhdGUuZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhdHRlbXB0X251bVwiXSA9IGF0dGVtcHRfbnVtO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUFJPR1JFU1NJT04gZXZlbnQ6IHtzdGF0dXM6XCIgKyBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiLCBwcm9ncmVzc2lvbjAxOlwiICsgcHJvZ3Jlc3Npb24wMSArIFwiLCBwcm9ncmVzc2lvbjAyOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiLCBwcm9ncmVzc2lvbjAzOlwiICsgcHJvZ3Jlc3Npb24wMyArIFwiLCBzY29yZTpcIiArIHNjb3JlICsgXCIsIGF0dGVtcHQ6XCIgKyBhdHRlbXB0X251bSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyLCBzZW5kVmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkLCB2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5RGVzaWduO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImV2ZW50X2lkXCJdID0gZXZlbnRJZDtcblxuICAgICAgICAgICAgICAgIGlmKHNlbmRWYWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInZhbHVlXCJdID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBERVNJR04gZXZlbnQ6IHtldmVudElkOlwiICsgZXZlbnRJZCArIFwiLCB2YWx1ZTpcIiArIHZhbHVlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNldmVyaXR5U3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmVycm9yU2V2ZXJpdHlUb1N0cmluZyhzZXZlcml0eSk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlFcnJvcjtcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJzZXZlcml0eVwiXSA9IHNldmVyaXR5U3RyaW5nO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcIm1lc3NhZ2VcIl0gPSBtZXNzYWdlO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBFUlJPUiBldmVudDoge3NldmVyaXR5OlwiICsgc2V2ZXJpdHlTdHJpbmcgKyBcIiwgbWVzc2FnZTpcIiArIG1lc3NhZ2UgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcHJvY2Vzc0V2ZW50cyhjYXRlZ29yeTpzdHJpbmcsIHBlcmZvcm1DbGVhblVwOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gdGhyb3cgbmV3IEVycm9yKFwicHJvY2Vzc0V2ZW50cyBub3QgaW1wbGVtZW50ZWRcIik7XG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkZW50aWZpZXI6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFudXBcbiAgICAgICAgICAgICAgICAgICAgaWYocGVyZm9ybUNsZWFuVXApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmNsZWFudXBFdmVudHMoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBQcmVwYXJlIFNRTFxuICAgICAgICAgICAgICAgICAgICB2YXIgc2VsZWN0QXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcInN0YXR1c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgXCJuZXdcIl0pO1xuICAgICAgICAgICAgICAgICAgICBpZihjYXRlZ29yeSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlU2V0QXJnczpBcnJheTxbc3RyaW5nLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVTZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIHJlcXVlc3RJZGVudGlmaWVyXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gR2V0IGV2ZW50cyB0byBwcm9jZXNzXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudHM6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGZvciBlcnJvcnMgb3IgZW1wdHlcbiAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cyB8fCBldmVudHMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogTm8gZXZlbnRzIHRvIHNlbmRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBudW1iZXIgb2YgZXZlbnRzIGFuZCB0YWtlIHNvbWUgYWN0aW9uIGlmIHRoZXJlIGFyZSB0b28gbWFueT9cbiAgICAgICAgICAgICAgICAgICAgaWYoZXZlbnRzLmxlbmd0aCA+IEdBRXZlbnRzLk1heEV2ZW50Q291bnQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIE1ha2UgYSBsaW1pdCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgICAgICAgICBldmVudHMgPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MsIHRydWUsIEdBRXZlbnRzLk1heEV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIEdldCBsYXN0IHRpbWVzdGFtcFxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RJdGVtOntba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbZXZlbnRzLmxlbmd0aCAtIDFdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RUaW1lc3RhbXA6c3RyaW5nID0gbGFzdEl0ZW1bXCJjbGllbnRfdHNcIl0gYXMgc3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIFNlbGVjdCBhZ2FpblxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZXZlbnRzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBTZW5kaW5nIFwiICsgZXZlbnRzLmxlbmd0aCArIFwiIGV2ZW50cy5cIik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gU2V0IHN0YXR1cyBvZiBldmVudHMgdG8gJ3NlbmRpbmcnIChhbHNvIGNoZWNrIGZvciBlcnJvcilcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHVwZGF0ZVNldEFyZ3MsIHVwZGF0ZVdoZXJlQXJncykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBwYXlsb2FkIGRhdGEgZnJvbSBldmVudHNcbiAgICAgICAgICAgICAgICAgICAgdmFyIHBheWxvYWRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGk6bnVtYmVyID0gMDsgaSA8IGV2ZW50cy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2Ontba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbaV07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0ID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChldltcImV2ZW50XCJdKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoZXZlbnREaWN0Lmxlbmd0aCAhPSAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBheWxvYWRBcnJheS5wdXNoKGV2ZW50RGljdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZEV2ZW50c0luQXJyYXkocGF5bG9hZEFycmF5LCByZXF1ZXN0SWRlbnRpZmllciwgR0FFdmVudHMucHJvY2Vzc0V2ZW50c0NhbGxiYWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKFwiRXJyb3IgZHVyaW5nIFByb2Nlc3NFdmVudHMoKTogXCIgKyBlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudHNDYWxsYmFjayhyZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlLCBkYXRhRGljdDp7W2tleTpzdHJpbmddOiBhbnl9LCAgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZFdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0SWRXaGVyZUFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIHJlcXVlc3RJZF0pO1xuXG4gICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuT2spXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBEZWxldGUgZXZlbnRzXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLkV2ZW50cywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFB1dCBldmVudHMgYmFjayAoT25seSBpbiBjYXNlIG9mIG5vIHJlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICBpZihyZXNwb25zZUVudW0gPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgc2V0QXJnczpBcnJheTxbc3RyaW5nLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgc2V0QXJncy5wdXNoKFtcInN0YXR1c1wiLCBcIm5ld1wiXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzIHRvIGNvbGxlY3RvciAtIFJldHJ5aW5nIG5leHQgdGltZVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgc2V0QXJncywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHMgKFdoZW4gZ2V0dGluZyBzb21lIGFud3NlciBiYWNrIGFsd2F5cyBhc3N1bWUgZXZlbnRzIGFyZSBwcm9jZXNzZWQpXG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihkYXRhRGljdClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIganNvbjphbnk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqIGluIGRhdGFEaWN0KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAganNvbiA9IGRhdGFEaWN0W2pdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsrY291bnQ7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdCAmJiBqc29uLmNvbnN0cnVjdG9yID09PSBBcnJheSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogXCIgKyBldmVudENvdW50ICsgXCIgZXZlbnRzIHNlbnQuIFwiICsgY291bnQgKyBcIiBldmVudHMgZmFpbGVkIEdBIHNlcnZlciB2YWxpZGF0aW9uLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLkV2ZW50cywgcmVxdWVzdElkV2hlcmVBcmdzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnVwZGF0ZVNlc3Npb25TdG9yZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjbGVhbnVwRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIFtbXCJzdGF0dXNcIiAsIFwibmV3XCJdXSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBHZXQgYWxsIHNlc3Npb25zIHRoYXQgYXJlIG5vdCBjdXJyZW50XG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKFtcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWwsIEdBU3RhdGUuZ2V0U2Vzc2lvbklkKCldKTtcblxuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uczpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLlNlc3Npb25zLCBhcmdzKTtcblxuICAgICAgICAgICAgICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShzZXNzaW9ucy5sZW5ndGggKyBcIiBzZXNzaW9uKHMpIGxvY2F0ZWQgd2l0aCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50LlwiKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBtaXNzaW5nIHNlc3Npb25fZW5kIGV2ZW50c1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgc2Vzc2lvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkVuZEV2ZW50Ontba2V5OnN0cmluZ106IGFueX0gPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KHNlc3Npb25zW2ldW1wiZXZlbnRcIl0gYXMgc3RyaW5nKSk7XG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudF90czpudW1iZXIgPSBzZXNzaW9uRW5kRXZlbnRbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gc2Vzc2lvbnNbaV1bXCJ0aW1lc3RhbXBcIl0gYXMgbnVtYmVyO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBsZW5ndGg6bnVtYmVyID0gZXZlbnRfdHMgLSBzdGFydF90cztcbiAgICAgICAgICAgICAgICAgICAgbGVuZ3RoID0gTWF0aC5tYXgoMCwgbGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMgbGVuZ3RoIGNhbGN1bGF0ZWQ6IFwiICsgbGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uRW5kRXZlbnRbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvbkVuZDtcbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkVuZEV2ZW50W1wibGVuZ3RoXCJdID0gbGVuZ3RoO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoc2Vzc2lvbkVuZEV2ZW50KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZEV2ZW50VG9TdG9yZShldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBDaGVjayBpZiB3ZSBhcmUgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBhZGQgZXZlbnQ6IFNESyBpcyBub3QgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGRiIHNpemUgbGltaXRzICgxMG1iKVxuICAgICAgICAgICAgICAgICAgICAvLyBJZiBkYXRhYmFzZSBpcyB0b28gbGFyZ2UgYmxvY2sgYWxsIGV4Y2VwdCB1c2VyLCBzZXNzaW9uIGFuZCBidXNpbmVzc1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdG9yZS5pc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKSAmJiAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gYXMgc3RyaW5nLCAvXih1c2VyfHNlc3Npb25fZW5kfGJ1c2luZXNzKSQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkRhdGFiYXNlIHRvbyBsYXJnZS4gRXZlbnQgaGFzIGJlZW4gYmxvY2tlZC5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZGVmYXVsdCBhbm5vdGF0aW9uc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBqc29uIHdpdGggb25seSBkZWZhdWx0IGFubm90YXRpb25zXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uRGVmYXVsdHM6c3RyaW5nID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBNZXJnZSB3aXRoIGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGUgaW4gZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBldltlXSA9IGV2ZW50RGF0YVtlXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBqc29uIHN0cmluZyByZXByZXNlbnRhdGlvblxuICAgICAgICAgICAgICAgICAgICB2YXIganNvbjpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gb3V0cHV0IGlmIFZFUkJPU0UgTE9HIGVuYWJsZWRcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5paShcIkV2ZW50IGFkZGVkIHRvIHF1ZXVlOiBcIiArIGpzb24pO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic3RhdHVzXCJdID0gXCJuZXdcIjtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiY2F0ZWdvcnlcIl0gPSBldltcImNhdGVnb3J5XCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gZXZbXCJzZXNzaW9uX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjbGllbnRfdHNcIl0gPSBldltcImNsaWVudF90c1wiXTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShldikpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLkV2ZW50cywgdmFsdWVzKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc2Vzc2lvbiBzdG9yZSBpZiBub3QgbGFzdFxuICAgICAgICAgICAgICAgICAgICBpZiAoZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPT0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5TZXNzaW9ucywgW1tcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGV2W1wic2Vzc2lvbl9pZFwiXSBhcyBzdHJpbmddXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0aW1lc3RhbXBcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBqc29uRGVmYXVsdHM7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5TZXNzaW9ucywgdmFsdWVzLCB0cnVlLCBcInNlc3Npb25faWRcIik7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNhdmUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRFdmVudFRvU3RvcmU6IGVycm9yXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgdXBkYXRlU2Vzc2lvblN0b3JlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInRpbWVzdGFtcFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCkpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuU2Vzc2lvbnMsIHZhbHVlcywgdHJ1ZSwgXCJzZXNzaW9uX2lkXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50RGF0YSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gYWRkIHRvIGRpY3QgKGlmIG5vdCBuaWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDFcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMlwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAzXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlc291cmNlRmxvd1R5cGVUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlNvdXJjZSB8fCB2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlW0VHQVJlc291cmNlRmxvd1R5cGUuU291cmNlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNvdXJjZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU2luayB8fCB2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlW0VHQVJlc291cmNlRmxvd1R5cGUuU2lua10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTaW5rXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydCB8fCB2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1c1tFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTdGFydFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIkNvbXBsZXRlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuRmFpbCB8fCB2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1c1tFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIkZhaWxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBlcnJvclNldmVyaXR5VG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5EZWJ1ZyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuRGVidWddKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGVidWdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkluZm8gfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkluZm9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW5mb1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuV2FybmluZyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuV2FybmluZ10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3YXJuaW5nXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5FcnJvciB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuRXJyb3JdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXJyb3JcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5Dcml0aWNhbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjcml0aWNhbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGhyZWFkaW5nXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUV2ZW50cyA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkdBRXZlbnRzO1xuICAgICAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FUaHJlYWRpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FUaHJlYWRpbmcgPSBuZXcgR0FUaHJlYWRpbmcoKTtcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBibG9ja3M6UHJpb3JpdHlRdWV1ZTxUaW1lZEJsb2NrPiA9IG5ldyBQcmlvcml0eVF1ZXVlPFRpbWVkQmxvY2s+KDxJQ29tcGFyZXI8bnVtYmVyPj57XG4gICAgICAgICAgICAgICAgY29tcGFyZTogKHg6bnVtYmVyLCB5Om51bWJlcikgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4geCAtIHk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBwcml2YXRlIHJlYWRvbmx5IGlkMlRpbWVkQmxvY2tNYXA6e1trZXk6bnVtYmVyXTogVGltZWRCbG9ja30gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1blRpbWVvdXRJZDpudW1iZXI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBUaHJlYWRXYWl0VGltZUluTXM6bnVtYmVyID0gMTAwMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIFByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kczpudW1iZXIgPSA4LjA7XG4gICAgICAgICAgICBwcml2YXRlIGtlZXBSdW5uaW5nOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIGlzUnVubmluZzpib29sZWFuO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW5pdGlhbGl6aW5nIEdBIHRocmVhZC4uLlwiKTtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdGFydFRocmVhZCgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZVRpbWVkQmxvY2soZGVsYXlJblNlY29uZHM6bnVtYmVyID0gMCk6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdGltZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICB0aW1lLnNldFNlY29uZHModGltZS5nZXRTZWNvbmRzKCkgKyBkZWxheUluU2Vjb25kcyk7XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRpbWVkQmxvY2s7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRhc2tPbkdBVGhyZWFkKHRhc2tCbG9jazooKSA9PiB2b2lkLCBkZWxheUluU2Vjb25kczpudW1iZXIgPSAwKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0aW1lOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHRpbWUuc2V0U2Vjb25kcyh0aW1lLmdldFNlY29uZHMoKSArIGRlbGF5SW5TZWNvbmRzKTtcblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBuZXcgVGltZWRCbG9jayh0aW1lKTtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrID0gdGFza0Jsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRpbWVkQmxvY2tPbkdBVGhyZWFkKHRpbWVkQmxvY2s6VGltZWRCbG9jayk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW3RpbWVkQmxvY2suaWRdID0gdGltZWRCbG9jaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5hZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNjaGVkdWxlVGltZXIoaW50ZXJ2YWw6bnVtYmVyLCBjYWxsYmFjazooKSA9PiB2b2lkKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRpbWU6RGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgdGltZS5zZXRTZWNvbmRzKHRpbWUuZ2V0U2Vjb25kcygpICsgaW50ZXJ2YWwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IG5ldyBUaW1lZEJsb2NrKHRpbWUpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSBjYWxsYmFjaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW3RpbWVkQmxvY2suaWRdID0gdGltZWRCbG9jaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5hZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2spO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRpbWVkQmxvY2suaWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VGltZWRCbG9ja0J5SWQoYmxvY2tJZGVudGlmaWVyOm51bWJlcik6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmxvY2tJZGVudGlmaWVyIGluIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFtibG9ja0lkZW50aWZpZXJdXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5rZWVwUnVubmluZyA9IHRydWU7XG5cbiAgICAgICAgICAgICAgICBpZighR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2NoZWR1bGVUaW1lcihHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMsIEdBVGhyZWFkaW5nLnByb2Nlc3NFdmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRW5kaW5nIHNlc3Npb24uXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wRXZlbnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvbkVuZEV2ZW50KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IDA7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RvcEV2ZW50UXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nID0gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaWdub3JlVGltZXIoYmxvY2tJZGVudGlmaWVyOm51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmxvY2tJZGVudGlmaWVyIGluIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW2Jsb2NrSWRlbnRpZmllcl0uaWdub3JlID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWw6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMgPSBpbnRlcnZhbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrOlRpbWVkQmxvY2spOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5ibG9ja3MuZW5xdWV1ZSh0aW1lZEJsb2NrLmRlYWRsaW5lLmdldFRpbWUoKSwgdGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1bigpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgY2xlYXJUaW1lb3V0KEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCk7XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2s7XG5cbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCh0aW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuZ2V0TmV4dEJsb2NrKCkpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIXRpbWVkQmxvY2suaWdub3JlKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHRpbWVkQmxvY2suYXN5bmMpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZighdGltZWRCbG9jay5ydW5uaW5nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLnJ1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jaygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jaygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCA9IHNldFRpbWVvdXQoR0FUaHJlYWRpbmcucnVuLCBHQVRocmVhZGluZy5UaHJlYWRXYWl0VGltZUluTXMpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIG9uIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkVuZGluZyBHQSB0aHJlYWRcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0YXJ0VGhyZWFkKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU3RhcnRpbmcgR0EgdGhyZWFkXCIpO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCA9IHNldFRpbWVvdXQoR0FUaHJlYWRpbmcucnVuLCAwKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0TmV4dEJsb2NrKCk6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbm93OkRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICAgICAgICAgICAgaWYgKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5oYXNJdGVtcygpICYmIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkuZGVhZGxpbmUuZ2V0VGltZSgpIDw9IG5vdy5nZXRUaW1lKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MucGVlaygpLmFzeW5jKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MucGVlaygpLnJ1bm5pbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5kZXF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmRlcXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCB0cnVlKTtcbiAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5rZWVwUnVubmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNjaGVkdWxlVGltZXIoR0FUaHJlYWRpbmcuUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzLCBHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgaW1wb3J0IEdBVGhyZWFkaW5nID0gZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmc7XG4gICAgaW1wb3J0IFRpbWVkQmxvY2sgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5UaW1lZEJsb2NrO1xuICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcbiAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYW1lYW5hbHl0aWNzLmRldmljZS5HQURldmljZTtcbiAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FIVFRQQXBpUmVzcG9uc2U7XG4gICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG5cbiAgICBleHBvcnQgY2xhc3MgR2FtZUFuYWx5dGljc1xuICAgIHtcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFRpbWVkQmxvY2tJZDpudW1iZXIgPSAtMTtcbiAgICAgICAgcHVibGljIHN0YXRpYyBtZXRob2RNYXA6e1tpZDpzdHJpbmddOiAoLi4uYXJnczogYW55W10pID0+IHZvaWR9ID0ge307XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0KCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudG91Y2goKTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUJ1aWxkJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUJ1aWxkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZVVzZXJJZCddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVVc2VySWQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnaW5pdGlhbGl6ZSddID0gR2FtZUFuYWx5dGljcy5pbml0aWFsaXplO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEJ1c2luZXNzRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkQnVzaW5lc3NFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRSZXNvdXJjZUV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZFJlc291cmNlRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkUHJvZ3Jlc3Npb25FdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRQcm9ncmVzc2lvbkV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZERlc2lnbkV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZERlc2lnbkV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEVycm9yRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRXJyb3JFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRFcnJvckV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEVycm9yRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZEluZm9Mb2cnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZEluZm9Mb2c7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZFZlcmJvc2VMb2cnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZFZlcmJvc2VMb2c7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAxJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAxO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAyJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEN1c3RvbURpbWVuc2lvbjAzJ10gPSBHYW1lQW5hbHl0aWNzLnNldEN1c3RvbURpbWVuc2lvbjAzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEZhY2Vib29rSWQnXSA9IEdhbWVBbmFseXRpY3Muc2V0RmFjZWJvb2tJZDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRHZW5kZXInXSA9IEdhbWVBbmFseXRpY3Muc2V0R2VuZGVyO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEJpcnRoWWVhciddID0gR2FtZUFuYWx5dGljcy5zZXRCaXJ0aFllYXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwnXSA9IEdhbWVBbmFseXRpY3Muc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWw7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc3RhcnRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLnN0YXJ0U2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydlbmRTZXNzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmVuZFNlc3Npb247XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnb25TdG9wJ10gPSBHYW1lQW5hbHl0aWNzLm9uU3RvcDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblJlc3VtZSddID0gR2FtZUFuYWx5dGljcy5vblJlc3VtZTtcblxuICAgICAgICAgICAgaWYodHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvd1snR2FtZUFuYWx5dGljcyddICE9PSAndW5kZWZpbmVkJyAmJiB0eXBlb2Ygd2luZG93WydHYW1lQW5hbHl0aWNzJ11bJ3EnXSAhPT0gJ3VuZGVmaW5lZCcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHE6YW55W10gPSB3aW5kb3dbJ0dhbWVBbmFseXRpY3MnXVsncSddO1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgaW4gcSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuZ2FDb21tYW5kLmFwcGx5KG51bGwsIHFbaV0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FDb21tYW5kKC4uLmFyZ3M6IGFueVtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBpZihhcmdzLmxlbmd0aCA+IDApXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoYXJnc1swXSBpbiBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJncy5sZW5ndGggPiAxKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwW2FyZ3NbMF1dLmFwcGx5KG51bGwsIEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3MsIDEpKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGdhbWVhbmFseXRpY3MuR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbYXJnc1swXV0oKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSByZXNvdXJjZSBjdXJyZW5jaWVzIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSByZXNvdXJjZSBpdGVtIHR5cGVzIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQnVpbGQoYnVpbGQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQnVpbGQgdmVyc2lvbiBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQnVpbGQoYnVpbGQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBidWlsZDogQ2Fubm90IGJlIG51bGwsIGVtcHR5IG9yIGFib3ZlIDMyIGxlbmd0aC4gU3RyaW5nOiBcIiArIGJ1aWxkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEJ1aWxkKGJ1aWxkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVTZGtHYW1lRW5naW5lVmVyc2lvbihzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgc2RrIHZlcnNpb246IFNkayB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBzZGtHYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24gPSBzZGtHYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUVuZ2luZVZlcnNpb24oZ2FtZUVuZ2luZVZlcnNpb24pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBnYW1lIGVuZ2luZSB2ZXJzaW9uOiBHYW1lIGVuZ2luZSB2ZXJzaW9uIG5vdCBzdXBwb3J0ZWQuIFN0cmluZzogXCIgKyBnYW1lRW5naW5lVmVyc2lvbik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24gPSBnYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVVc2VySWQodUlkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkEgY3VzdG9tIHVzZXIgaWQgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVVzZXJJZCh1SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSB1c2VyX2lkOiBDYW5ub3QgYmUgbnVsbCwgZW1wdHkgb3IgYWJvdmUgNjQgbGVuZ3RoLiBXaWxsIHVzZSBkZWZhdWx0IHVzZXJfaWQgbWV0aG9kLiBVc2VkIHN0cmluZzogXCIgKyB1SWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRVc2VySWQodUlkKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0aWFsaXplKGdhbWVLZXk6c3RyaW5nID0gXCJcIiwgZ2FtZVNlY3JldDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuY3JlYXRlVGltZWRCbG9jaygpO1xuICAgICAgICAgICAgdGltZWRCbG9jay5hc3luYyA9IHRydWU7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmluaXRUaW1lZEJsb2NrSWQgPSB0aW1lZEJsb2NrLmlkO1xuICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9ICgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGFscmVhZHkgaW5pdGlhbGl6ZWQuIENhbiBvbmx5IGJlIGNhbGxlZCBvbmNlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlS2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTREsgZmFpbGVkIGluaXRpYWxpemUuIEdhbWUga2V5IG9yIHNlY3JldCBrZXkgaXMgaW52YWxpZC4gQ2FuIG9ubHkgY29udGFpbiBjaGFyYWN0ZXJzIEEteiAwLTksIGdhbWVLZXkgaXMgMzIgbGVuZ3RoLCBnYW1lU2VjcmV0IGlzIDQwIGxlbmd0aC4gRmFpbGVkIGtleXMgLSBnYW1lS2V5OiBcIiArIGdhbWVLZXkgKyBcIiwgc2VjcmV0S2V5OiBcIiArIGdhbWVTZWNyZXQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRLZXlzKGdhbWVLZXksIGdhbWVTZWNyZXQpO1xuXG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbnRlcm5hbEluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIsIGNhcnRUeXBlOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBidXNpbmVzcyBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUgPSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZCwgY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgcmVzb3VyY2UgZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cyA9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZCwgcHJvZ3Jlc3Npb24wMTpzdHJpbmcgPSBcIlwiLCBwcm9ncmVzc2lvbjAyOnN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDM6c3RyaW5nID0gXCJcIiwgc2NvcmU/Om51bWJlcik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgcHJvZ3Jlc3Npb24gZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOmJvb2xlYW4gPSB0eXBlb2Ygc2NvcmUgIT0gXCJ1bmRlZmluZWRcIjtcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzLCBzZW5kU2NvcmUgPyBzY29yZSA6IDAsIHNlbmRTY29yZSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlPzpudW1iZXIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIHNlbmRWYWx1ZTpib29sZWFuID0gdHlwZW9mIHZhbHVlICE9IFwidW5kZWZpbmVkXCI7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGVzaWduRXZlbnQoZXZlbnRJZCwgc2VuZFZhbHVlID8gdmFsdWUgOiAwLCBzZW5kVmFsdWUpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSA9IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXJyb3JFdmVudChzZXZlcml0eSwgbWVzc2FnZSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEluZm9Mb2coZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5mbyBsb2dnaW5nIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRJbmZvTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkVmVyYm9zZUxvZyhmbGFnOmJvb2xlYW4gPSBmYWxzZSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRWZXJib3NlTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmVyYm9zZSBsb2dnaW5nIGVuYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0TWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWcpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAxKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAzKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMyBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVGYWNlYm9va0lkKGZhY2Vib29rSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRGYWNlYm9va0lkKGZhY2Vib29rSWQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRHZW5kZXIoZ2VuZGVyOkVHQUdlbmRlciA9IEVHQUdlbmRlci5VbmRlZmluZWQpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUdlbmRlcihnZW5kZXIpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRHZW5kZXIoZ2VuZGVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QmlydGhZZWFyKGJpcnRoWWVhcjpudW1iZXIgPSAwKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVCaXJ0aHllYXIoYmlydGhZZWFyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QmlydGhZZWFyKGJpcnRoWWVhcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEV2ZW50UHJvY2Vzc0ludGVydmFsKGludGVydmFsSW5TZWNvbmRzOm51bWJlcik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWxJblNlY29uZHMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHN0YXJ0U2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKEdBU3RhdGUuZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBHQVRocmVhZGluZy5jcmVhdGVUaW1lZEJsb2NrKCk7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5hc3luYyA9IHRydWU7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrID0gKCkgPT5cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaXNFbmFibGVkKCkgJiYgR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRpbWVkQmxvY2tPbkdBVGhyZWFkKHRpbWVkQmxvY2spO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBlbmRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm9uU3RvcCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKEV4Y2VwdGlvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIGludGVybmFsSW5pdGlhbGl6ZSgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBU3RhdGUuZW5zdXJlUGVyc2lzdGVkU3RhdGVzKCk7XG4gICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5LCBHQVN0YXRlLmdldERlZmF1bHRJZCgpKTtcblxuICAgICAgICAgICAgR0FTdGF0ZS5zZXRJbml0aWFsaXplZCh0cnVlKTtcblxuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5uZXdTZXNzaW9uKCk7XG5cbiAgICAgICAgICAgIGlmIChHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHByaXZhdGUgc3RhdGljIG5ld1Nlc3Npb24oKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiU3RhcnRpbmcgYSBuZXcgc2Vzc2lvbi5cIik7XG5cbiAgICAgICAgICAgIC8vIG1ha2Ugc3VyZSB0aGUgY3VycmVudCBjdXN0b20gZGltZW5zaW9ucyBhcmUgdmFsaWRcbiAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2UucmVxdWVzdEluaXQoR2FtZUFuYWx5dGljcy5zdGFydE5ld1Nlc3Npb25DYWxsYmFjayk7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBzdGFydE5ld1Nlc3Npb25DYWxsYmFjayhpbml0UmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBpbml0UmVzcG9uc2VEaWN0Ontba2V5OnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vIGluaXQgaXMgb2tcbiAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIGluaXRSZXNwb25zZURpY3QpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gc2V0IHRoZSB0aW1lIG9mZnNldCAtIGhvdyBtYW55IHNlY29uZHMgdGhlIGxvY2FsIHRpbWUgaXMgZGlmZmVyZW50IGZyb20gc2VydmVydGltZVxuICAgICAgICAgICAgICAgIHZhciB0aW1lT2Zmc2V0U2Vjb25kczpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyVHM6bnVtYmVyID0gaW5pdFJlc3BvbnNlRGljdFtcInNlcnZlcl90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIHRpbWVPZmZzZXRTZWNvbmRzID0gR0FTdGF0ZS5jYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcInRpbWVfb2Zmc2V0XCJdID0gdGltZU9mZnNldFNlY29uZHM7XG5cbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgbmV3IGNvbmZpZyBpbiBzcWwgbGl0ZSBjcm9zcyBzZXNzaW9uIHN0b3JhZ2VcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5TZGtDb25maWdDYWNoZWRLZXksIEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGluaXRSZXNwb25zZURpY3QpKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBzZXQgbmV3IGNvbmZpZyBhbmQgY2FjaGUgaW4gbWVtb3J5XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgPSBpbml0UmVzcG9uc2VEaWN0O1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gaW5pdFJlc3BvbnNlRGljdDtcblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT0gRUdBSFRUUEFwaVJlc3BvbnNlLlVuYXV0aG9yaXplZClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiSW5pdGlhbGl6ZSBTREsgZmFpbGVkIC0gVW5hdXRob3JpemVkXCIpO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaW5pdEF1dGhvcml6ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBsb2cgdGhlIHN0YXR1cyBpZiBubyBjb25uZWN0aW9uXG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5SZXF1ZXN0VGltZW91dClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIG5vIHJlc3BvbnNlLiBDb3VsZCBiZSBvZmZsaW5lIG9yIHRpbWVvdXQuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkpzb25FbmNvZGVGYWlsZWQgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkRlY29kZUZhaWxlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXNwb25zZS4gQ291bGQgYmUgYmFkIHJlc3BvbnNlIGZyb20gcHJveHkgb3IgR0Egc2VydmVycy5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdCB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Vbmtub3duUmVzcG9uc2VDb2RlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gYmFkIHJlcXVlc3Qgb3IgdW5rbm93biByZXNwb25zZS5cIik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5pdCBjYWxsIGZhaWxlZCAocGVyaGFwcyBvZmZsaW5lKVxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID09IG51bGwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCAhPSBudWxsKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGxhc3QgY3Jvc3Mgc2Vzc2lvbiBzdG9yZWQgY29uZmlnIGluaXQgdmFsdWVzXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgZGVmYXVsdCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBpbml0IHZhbHVlc1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0RlZmF1bHQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgY2FjaGVkIGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIHNldCBvZmZzZXQgaW4gc3RhdGUgKG1lbW9yeSkgZnJvbSBjdXJyZW50IGNvbmZpZyAoY29uZmlnIGNvdWxkIGJlIGZyb20gY2FjaGUgZXRjLilcbiAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY2xpZW50U2VydmVyVGltZU9mZnNldCA9IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnW1widGltZV9vZmZzZXRcIl0gPyBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ1tcInRpbWVfb2Zmc2V0XCJdIGFzIG51bWJlciA6IDA7XG5cbiAgICAgICAgICAgIC8vIGlmIFNESyBpcyBkaXNhYmxlZCBpbiBjb25maWdcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc3RhcnQgc2Vzc2lvbjogU0RLIGlzIGRpc2FibGVkLlwiKTtcbiAgICAgICAgICAgICAgICAvLyBzdG9wIGV2ZW50IHF1ZXVlXG4gICAgICAgICAgICAgICAgLy8gKyBtYWtlIHN1cmUgaXQncyBhYmxlIHRvIHJlc3RhcnQgaWYgYW5vdGhlciBzZXNzaW9uIGRldGVjdHMgaXQncyBlbmFibGVkIGFnYWluXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBnZW5lcmF0ZSB0aGUgbmV3IHNlc3Npb25cbiAgICAgICAgICAgIHZhciBuZXdTZXNzaW9uSWQ6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAvLyBTZXQgc2Vzc2lvbiBpZFxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQgPSBuZXdTZXNzaW9uSWQ7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIHN0YXJ0XG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuXG4gICAgICAgICAgICAvLyBBZGQgc2Vzc2lvbiBzdGFydCBldmVudFxuICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTtcblxuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmdldFRpbWVkQmxvY2tCeUlkKEdhbWVBbmFseXRpY3MuaW5pdFRpbWVkQmxvY2tJZCk7XG5cbiAgICAgICAgICAgIGlmKHRpbWVkQmxvY2sgIT0gbnVsbClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLnJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyByZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiUmVzdW1pbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICBpZighR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5uZXdTZXNzaW9uKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpc1Nka1JlYWR5KG5lZWRzSW5pdGlhbGl6ZWQ6Ym9vbGVhbiwgd2Fybjpib29sZWFuID0gdHJ1ZSwgbWVzc2FnZTpzdHJpbmcgPSBcIlwiKTogYm9vbGVhblxuICAgICAgICB7XG4gICAgICAgICAgICBpZihtZXNzYWdlKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlICsgXCI6IFwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBJcyBTREsgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAod2FybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU0RLIGlzIG5vdCBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgU0RLIGVuYWJsZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgfVxufVxuZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmluaXQoKTtcbnZhciBHYW1lQW5hbHl0aWNzID0gZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmdhQ29tbWFuZDtcbiJdfQ==

scope.gameanalytics=gameanalytics;
scope.GameAnalytics=GameAnalytics;
})(this);
