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

var ga;
(function (ga) {
    var EGAErrorSeverity;
    (function (EGAErrorSeverity) {
        EGAErrorSeverity[EGAErrorSeverity["Undefined"] = 0] = "Undefined";
        EGAErrorSeverity[EGAErrorSeverity["Debug"] = 1] = "Debug";
        EGAErrorSeverity[EGAErrorSeverity["Info"] = 2] = "Info";
        EGAErrorSeverity[EGAErrorSeverity["Warning"] = 3] = "Warning";
        EGAErrorSeverity[EGAErrorSeverity["Error"] = 4] = "Error";
        EGAErrorSeverity[EGAErrorSeverity["Critical"] = 5] = "Critical";
    })(EGAErrorSeverity = ga.EGAErrorSeverity || (ga.EGAErrorSeverity = {}));
    var EGAGender;
    (function (EGAGender) {
        EGAGender[EGAGender["Undefined"] = 0] = "Undefined";
        EGAGender[EGAGender["Male"] = 1] = "Male";
        EGAGender[EGAGender["Female"] = 2] = "Female";
    })(EGAGender = ga.EGAGender || (ga.EGAGender = {}));
    var EGAProgressionStatus;
    (function (EGAProgressionStatus) {
        EGAProgressionStatus[EGAProgressionStatus["Undefined"] = 0] = "Undefined";
        EGAProgressionStatus[EGAProgressionStatus["Start"] = 1] = "Start";
        EGAProgressionStatus[EGAProgressionStatus["Complete"] = 2] = "Complete";
        EGAProgressionStatus[EGAProgressionStatus["Fail"] = 3] = "Fail";
    })(EGAProgressionStatus = ga.EGAProgressionStatus || (ga.EGAProgressionStatus = {}));
    var EGAResourceFlowType;
    (function (EGAResourceFlowType) {
        EGAResourceFlowType[EGAResourceFlowType["Undefined"] = 0] = "Undefined";
        EGAResourceFlowType[EGAResourceFlowType["Source"] = 1] = "Source";
        EGAResourceFlowType[EGAResourceFlowType["Sink"] = 2] = "Sink";
    })(EGAResourceFlowType = ga.EGAResourceFlowType || (ga.EGAResourceFlowType = {}));
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
    })(http = ga.http || (ga.http = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
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
    })(logging = ga.logging || (ga.logging = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var utilities;
    (function (utilities) {
        var GALogger = ga.logging.GALogger;
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
    })(utilities = ga.utilities || (ga.utilities = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var validators;
    (function (validators) {
        var GALogger = ga.logging.GALogger;
        var EGASdkErrorType = ga.http.EGASdkErrorType;
        var GAUtilities = ga.utilities.GAUtilities;
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
                if (flowType == ga.EGAResourceFlowType.Undefined) {
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
                if (progressionStatus === ga.EGAProgressionStatus.Undefined) {
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
                if (severity === ga.EGAErrorSeverity.Undefined) {
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
                if (!GAUtilities.stringMatch(wrapperVersion, /^(unity|unreal) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEngineVersion = function (engineVersion) {
                if (!engineVersion || !GAUtilities.stringMatch(engineVersion, /^(unity|unreal) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
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
                for (var i in resourceCurrencies) {
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
                for (var i in resourceItemTypes) {
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
                for (var i in arrayOfStrings) {
                    var stringLength = !arrayOfStrings[i] ? 0 : arrayOfStrings[i].length;
                    if (stringLength === 0) {
                        GALogger.i(arrayTag + " validation failed: contained an empty string.");
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
                if (gender === ga.EGAGender.Undefined || !(gender === ga.EGAGender.Male || gender === ga.EGAGender.Female)) {
                    GALogger.i("Validation fail - gender: Has to be 'male' or 'female'.");
                    return false;
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
    })(validators = ga.validators || (ga.validators = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
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
                var M = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident(?=\/))\/?\s*(\d+)/i) || [];
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
                console.log("AGENT: " + agent);
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
        GADevice.sdkWrapperVersion = "javascript 1.0.5";
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
    })(device = ga.device || (ga.device = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var threading;
    (function (threading) {
        var TimedBlock = (function () {
            function TimedBlock(deadline, block) {
                this.deadline = deadline;
                this.block = block;
                this.ignore = false;
                this.id = ++TimedBlock.idCounter;
            }
            return TimedBlock;
        }());
        TimedBlock.idCounter = 0;
        threading.TimedBlock = TimedBlock;
    })(threading = ga.threading || (ga.threading = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
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
    })(threading = ga.threading || (ga.threading = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var store;
    (function (store_1) {
        var GALogger = ga.logging.GALogger;
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
    })(store = ga.store || (ga.store = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var state;
    (function (state) {
        var GAValidator = ga.validators.GAValidator;
        var GAUtilities = ga.utilities.GAUtilities;
        var GALogger = ga.logging.GALogger;
        var GAStore = ga.store.GAStore;
        var GADevice = ga.device.GADevice;
        var EGAStore = ga.store.EGAStore;
        var EGAStoreArgsOperator = ga.store.EGAStoreArgsOperator;
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
                GAState.instance.gender = ga.EGAGender[gender].toString().toLowerCase();
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
    })(state = ga.state || (ga.state = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var tasks;
    (function (tasks) {
        var GAUtilities = ga.utilities.GAUtilities;
        var GALogger = ga.logging.GALogger;
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
    })(tasks = ga.tasks || (ga.tasks = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var http;
    (function (http) {
        var GAState = ga.state.GAState;
        var GALogger = ga.logging.GALogger;
        var GAUtilities = ga.utilities.GAUtilities;
        var GAValidator = ga.validators.GAValidator;
        var SdkErrorTask = ga.tasks.SdkErrorTask;
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
    })(http = ga.http || (ga.http = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var events;
    (function (events_1) {
        var GAStore = ga.store.GAStore;
        var EGAStore = ga.store.EGAStore;
        var EGAStoreArgsOperator = ga.store.EGAStoreArgsOperator;
        var GAState = ga.state.GAState;
        var GALogger = ga.logging.GALogger;
        var GAUtilities = ga.utilities.GAUtilities;
        var EGAHTTPApiResponse = ga.http.EGAHTTPApiResponse;
        var GAHTTPApi = ga.http.GAHTTPApi;
        var GAValidator = ga.validators.GAValidator;
        var EGASdkErrorType = ga.http.EGASdkErrorType;
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
                if (flowType === ga.EGAResourceFlowType.Sink) {
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
                if (sendScore && progressionStatus != ga.EGAProgressionStatus.Start) {
                    eventDict["score"] = score;
                }
                if (progressionStatus === ga.EGAProgressionStatus.Fail) {
                    GAState.incrementProgressionTries(progressionIdentifier);
                }
                if (progressionStatus === ga.EGAProgressionStatus.Complete) {
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
                    if (!events) {
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
                for (var i in sessions) {
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
                var values = {};
                values["session_id"] = GAState.instance.sessionId;
                values["timestamp"] = GAState.getSessionStart();
                values["event"] = GAUtilities.encode64(JSON.stringify(GAState.getEventAnnotations()));
                GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                if (GAStore.isStorageAvailable()) {
                    GAStore.save();
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
                switch (value) {
                    case ga.EGAResourceFlowType.Source:
                        {
                            return "Source";
                        }
                    case ga.EGAResourceFlowType.Sink:
                        {
                            return "Sink";
                        }
                    default:
                        {
                            return "";
                        }
                }
            };
            GAEvents.progressionStatusToString = function (value) {
                switch (value) {
                    case ga.EGAProgressionStatus.Start:
                        {
                            return "Start";
                        }
                    case ga.EGAProgressionStatus.Complete:
                        {
                            return "Complete";
                        }
                    case ga.EGAProgressionStatus.Fail:
                        {
                            return "Fail";
                        }
                    default:
                        {
                            return "";
                        }
                }
            };
            GAEvents.errorSeverityToString = function (value) {
                switch (value) {
                    case ga.EGAErrorSeverity.Debug:
                        {
                            return "debug";
                        }
                    case ga.EGAErrorSeverity.Info:
                        {
                            return "info";
                        }
                    case ga.EGAErrorSeverity.Warning:
                        {
                            return "warning";
                        }
                    case ga.EGAErrorSeverity.Error:
                        {
                            return "error";
                        }
                    case ga.EGAErrorSeverity.Critical:
                        {
                            return "critical";
                        }
                    default:
                        {
                            return "";
                        }
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
    })(events = ga.events || (ga.events = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var threading;
    (function (threading) {
        var GALogger = ga.logging.GALogger;
        var GAState = ga.state.GAState;
        var GAEvents = ga.events.GAEvents;
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
            GAThreading.performTaskOnGAThread = function (taskBlock, delayInSeconds) {
                if (delayInSeconds === void 0) { delayInSeconds = 0; }
                var time = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);
                var timedBlock = new threading.TimedBlock(time, taskBlock);
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            };
            GAThreading.scheduleTimer = function (interval, callback) {
                var time = new Date();
                time.setSeconds(time.getSeconds() + interval);
                var timedBlock = new threading.TimedBlock(time, callback);
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
                return timedBlock.id;
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
            GAThreading.prototype.addTimedBlock = function (timedBlock) {
                this.blocks.enqueue(timedBlock.deadline.getTime(), timedBlock);
            };
            GAThreading.run = function () {
                clearTimeout(GAThreading.runTimeoutId);
                try {
                    var timedBlock;
                    while ((timedBlock = GAThreading.getNextBlock())) {
                        if (!timedBlock.ignore) {
                            timedBlock.block();
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
                    return GAThreading.instance.blocks.dequeue();
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
    })(threading = ga.threading || (ga.threading = {}));
})(ga || (ga = {}));
var ga;
(function (ga) {
    var GAThreading = ga.threading.GAThreading;
    var GALogger = ga.logging.GALogger;
    var GAStore = ga.store.GAStore;
    var GAState = ga.state.GAState;
    var GAHTTPApi = ga.http.GAHTTPApi;
    var GADevice = ga.device.GADevice;
    var GAValidator = ga.validators.GAValidator;
    var EGAHTTPApiResponse = ga.http.EGAHTTPApiResponse;
    var GAUtilities = ga.utilities.GAUtilities;
    var GAEvents = ga.events.GAEvents;
    var GameAnalytics = (function () {
        function GameAnalytics() {
        }
        GameAnalytics.init = function () {
            GADevice.touch();
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
            if (flowType === void 0) { flowType = ga.EGAResourceFlowType.Undefined; }
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
            if (progressionStatus === void 0) { progressionStatus = ga.EGAProgressionStatus.Undefined; }
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
            if (severity === void 0) { severity = ga.EGAErrorSeverity.Undefined; }
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
            if (gender === void 0) { gender = ga.EGAGender.Undefined; }
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
        GameAnalytics.startSession = function () {
            GAThreading.performTaskOnGAThread(function () {
                if (GAState.getUseManualSessionHandling()) {
                    if (!GAState.isInitialized()) {
                        return;
                    }
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAThreading.endSessionAndStopQueue();
                    }
                    GameAnalytics.resumeSessionAndStartQueue();
                }
            });
        };
        GameAnalytics.endSession = function () {
            if (GAState.getUseManualSessionHandling()) {
                GameAnalytics.onStop();
            }
        };
        GameAnalytics.onStop = function () {
            try {
                GAThreading.endSessionAndStopQueue();
            }
            catch (Exception) {
            }
        };
        GameAnalytics.onResume = function () {
            GameAnalytics.resumeSessionAndStartQueue();
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
    ga.GameAnalytics = GameAnalytics;
    GameAnalytics.init();
})(ga || (ga = {}));

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy90aHJlYWRpbmcvVGltZWRCbG9jay50cyIsInNyYy90aHJlYWRpbmcvUHJpb3JpdHlRdWV1ZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2V2ZW50cy9HQUV2ZW50cy50cyIsInNyYy90aHJlYWRpbmcvR0FUaHJlYWRpbmcudHMiLCJzcmMvR2FtZUFuYWx5dGljcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFPLEVBQUUsQ0EwRFI7QUExREQsV0FBTyxFQUFFO0lBRUwsSUFBWSxnQkFRWDtJQVJELFdBQVksZ0JBQWdCO1FBRXhCLGlFQUFhLENBQUE7UUFDYix5REFBUyxDQUFBO1FBQ1QsdURBQVEsQ0FBQTtRQUNSLDZEQUFXLENBQUE7UUFDWCx5REFBUyxDQUFBO1FBQ1QsK0RBQVksQ0FBQTtJQUNoQixDQUFDLEVBUlcsZ0JBQWdCLEdBQWhCLG1CQUFnQixLQUFoQixtQkFBZ0IsUUFRM0I7SUFFRCxJQUFZLFNBS1g7SUFMRCxXQUFZLFNBQVM7UUFFakIsbURBQWEsQ0FBQTtRQUNiLHlDQUFRLENBQUE7UUFDUiw2Q0FBVSxDQUFBO0lBQ2QsQ0FBQyxFQUxXLFNBQVMsR0FBVCxZQUFTLEtBQVQsWUFBUyxRQUtwQjtJQUVELElBQVksb0JBTVg7SUFORCxXQUFZLG9CQUFvQjtRQUU1Qix5RUFBYSxDQUFBO1FBQ2IsaUVBQVMsQ0FBQTtRQUNULHVFQUFZLENBQUE7UUFDWiwrREFBUSxDQUFBO0lBQ1osQ0FBQyxFQU5XLG9CQUFvQixHQUFwQix1QkFBb0IsS0FB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QUFtQjtZQUV4RixFQUFFLENBQUEsQ0FBQyxPQUFPLENBQUMsQ0FDWCxDQUFDO2dCQUNHLE9BQU8sR0FBRyxPQUFPLEdBQUcsSUFBSSxDQUFDO1lBQzdCLENBQUM7WUFHRCxFQUFFLENBQUMsQ0FBQyxnQkFBZ0IsSUFBSSxDQUFDLE9BQU8sQ0FBQyxhQUFhLEVBQUUsQ0FBQyxDQUNqRCxDQUFDO2dCQUNHLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUNULENBQUM7b0JBQ0csUUFBUSxDQUFDLENBQUMsQ0FBQyxPQUFPLEdBQUcsd0JBQXdCLENBQUMsQ0FBQztnQkFDbkQsQ0FBQztnQkFDRCxNQUFNLENBQUMsS0FBSyxDQUFDO1lBQ2pCLENBQUM7WUFFRCxFQUFFLENBQUMsQ0FBQyxnQkFBZ0IsSUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxDQUM3QyxDQUFDO2dCQUNHLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUNULENBQUM7b0JBQ0csUUFBUSxDQUFDLENBQUMsQ0FBQyxPQUFPLEdBQUcsaUJBQWlCLENBQUMsQ0FBQztnQkFDNUMsQ0FBQztnQkFDRCxNQUFNLENBQUMsS0FBSyxDQUFDO1lBQ2pCLENBQUM7WUFDRCxNQUFNLENBQUMsSUFBSSxDQUFDO1FBQ2hCLENBQUM7UUFDTCxvQkFBQztJQUFELENBbmpCQSxBQW1qQkMsSUFBQTtJQW5qQlksZ0JBQWEsZ0JBbWpCekIsQ0FBQTtJQUVELGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUN6QixDQUFDLEVBbmtCTSxFQUFFLEtBQUYsRUFBRSxRQW1rQlIiLCJmaWxlIjoiZGlzdC9HYW1lQW5hbHl0aWNzLmRlYnVnLmpzIiwic291cmNlc0NvbnRlbnQiOlsibW9kdWxlIGdhXHJcbntcclxuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHlcclxuICAgIHtcclxuICAgICAgICBVbmRlZmluZWQgPSAwLFxyXG4gICAgICAgIERlYnVnID0gMSxcclxuICAgICAgICBJbmZvID0gMixcclxuICAgICAgICBXYXJuaW5nID0gMyxcclxuICAgICAgICBFcnJvciA9IDQsXHJcbiAgICAgICAgQ3JpdGljYWwgPSA1XHJcbiAgICB9XHJcblxyXG4gICAgZXhwb3J0IGVudW0gRUdBR2VuZGVyXHJcbiAgICB7XHJcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcclxuICAgICAgICBNYWxlID0gMSxcclxuICAgICAgICBGZW1hbGUgPSAyXHJcbiAgICB9XHJcblxyXG4gICAgZXhwb3J0IGVudW0gRUdBUHJvZ3Jlc3Npb25TdGF0dXNcclxuICAgIHtcclxuICAgICAgICBVbmRlZmluZWQgPSAwLFxyXG4gICAgICAgIFN0YXJ0ID0gMSxcclxuICAgICAgICBDb21wbGV0ZSA9IDIsXHJcbiAgICAgICAgRmFpbCA9IDNcclxuICAgIH1cclxuXHJcbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlXHJcbiAgICB7XHJcbiAgICAgICAgVW5kZWZpbmVkID0gMCxcclxuICAgICAgICBTb3VyY2UgPSAxLFxyXG4gICAgICAgIFNpbmsgPSAyXHJcbiAgICB9XHJcblxyXG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXHJcbiAgICB7XHJcbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU2RrRXJyb3JUeXBlXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBVbmRlZmluZWQgPSAwLFxyXG4gICAgICAgICAgICBSZWplY3RlZCA9IDFcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQUhUVFBBcGlSZXNwb25zZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgLy8gY2xpZW50XHJcbiAgICAgICAgICAgIE5vUmVzcG9uc2UsXHJcbiAgICAgICAgICAgIEJhZFJlc3BvbnNlLFxyXG4gICAgICAgICAgICBSZXF1ZXN0VGltZW91dCwgLy8gNDA4XHJcbiAgICAgICAgICAgIEpzb25FbmNvZGVGYWlsZWQsXHJcbiAgICAgICAgICAgIEpzb25EZWNvZGVGYWlsZWQsXHJcbiAgICAgICAgICAgIC8vIHNlcnZlclxyXG4gICAgICAgICAgICBJbnRlcm5hbFNlcnZlckVycm9yLFxyXG4gICAgICAgICAgICBCYWRSZXF1ZXN0LCAvLyA0MDBcclxuICAgICAgICAgICAgVW5hdXRob3JpemVkLCAvLyA0MDFcclxuICAgICAgICAgICAgVW5rbm93blJlc3BvbnNlQ29kZSxcclxuICAgICAgICAgICAgT2tcclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIiwibW9kdWxlIGdhXHJcbntcclxuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xyXG4gICAge1xyXG4gICAgICAgIGVudW0gRUdBTG9nZ2VyTWVzc2FnZVR5cGVcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEVycm9yID0gMCxcclxuICAgICAgICAgICAgV2FybmluZyA9IDEsXHJcbiAgICAgICAgICAgIEluZm8gPSAyLFxyXG4gICAgICAgICAgICBEZWJ1ZyA9IDNcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUxvZ2dlclxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FMb2dnZXIgPSBuZXcgR0FMb2dnZXIoKTtcclxuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xyXG4gICAgICAgICAgICBwcml2YXRlIGluZm9Mb2dWZXJib3NlRW5hYmxlZDpib29sZWFuO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBkZWJ1Z0VuYWJsZWQ6Ym9vbGVhbjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xyXG5cclxuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBFTkRcclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kZWJ1Z0VuYWJsZWQgPSB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBTVEFSVFxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbmZvTG9nKHZhbHVlOmJvb2xlYW4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkID0gdmFsdWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0VmVyYm9zZUxvZyh2YWx1ZTpib29sZWFuKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJJbmZvL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdyhmb3JtYXQ6c3RyaW5nKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIldhcm5pbmcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5XYXJuaW5nKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlKGZvcm1hdDpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRXJyb3IvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcik7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaWkoZm9ybWF0OnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dWZXJib3NlRW5hYmxlZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZChmb3JtYXQ6c3RyaW5nKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkRlYnVnL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBzd2l0Y2godHlwZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yOlxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuV2FybmluZzpcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWc6XHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlb2YgY29uc29sZS5kZWJ1ZyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmRlYnVnKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuSW5mbzpcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgLy8gTWV0aG9kczogRU5EXHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHV0aWxpdGllc1xyXG4gICAge1xyXG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhLmxvZ2dpbmcuR0FMb2dnZXI7XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVV0aWxpdGllc1xyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRIbWFjKGtleTpzdHJpbmcsIGRhdGE6c3RyaW5nKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBlbmNyeXB0ZWRNZXNzYWdlID0gQ3J5cHRvSlMuSG1hY1NIQTI1NihkYXRhLCBrZXkpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGVuY3J5cHRlZE1lc3NhZ2UpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ01hdGNoKHM6c3RyaW5nLCBwYXR0ZXJuOlJlZ0V4cCk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYoIXMgfHwgIXBhdHRlcm4pXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIHJldHVybiBwYXR0ZXJuLnRlc3Qocyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgam9pblN0cmluZ0FycmF5KHY6QXJyYXk8c3RyaW5nPiwgZGVsaW1pdGVyOnN0cmluZyk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwiXCI7XHJcblxyXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDAsIGlsID0gdi5sZW5ndGg7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmIChpID4gMClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSBkZWxpbWl0ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSB2W2ldO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGFycmF5OkFycmF5PHN0cmluZz4sIHNlYXJjaDpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChhcnJheS5sZW5ndGggPT09IDApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBhcnJheSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpZihhcnJheVtzXSA9PT0gc2VhcmNoKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBrZXlTdHI6c3RyaW5nID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiO1xyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbmNvZGU2NChpbnB1dDpzdHJpbmcpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaW5wdXQgPSBlbmNvZGVVUkkoaW5wdXQpO1xyXG4gICAgICAgICAgICAgICAgdmFyIG91dHB1dDpzdHJpbmcgPSBcIlwiO1xyXG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xyXG4gICAgICAgICAgICAgICAgdmFyIGVuYzE6bnVtYmVyLCBlbmMyOm51bWJlciwgZW5jMzpudW1iZXIsIGVuYzQ6bnVtYmVyID0gMDtcclxuICAgICAgICAgICAgICAgIHZhciBpID0gMDtcclxuXHJcbiAgICAgICAgICAgICAgICBkb1xyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcclxuICAgICAgICAgICAgICAgICAgIGNocjIgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XHJcbiAgICAgICAgICAgICAgICAgICBjaHIzID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xyXG5cclxuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBjaHIxID4+IDI7XHJcbiAgICAgICAgICAgICAgICAgICBlbmMyID0gKChjaHIxICYgMykgPDwgNCkgfCAoY2hyMiA+PiA0KTtcclxuICAgICAgICAgICAgICAgICAgIGVuYzMgPSAoKGNocjIgJiAxNSkgPDwgMikgfCAoY2hyMyA+PiA2KTtcclxuICAgICAgICAgICAgICAgICAgIGVuYzQgPSBjaHIzICYgNjM7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgaWYgKGlzTmFOKGNocjIpKVxyXG4gICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgZW5jMyA9IGVuYzQgPSA2NDtcclxuICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKGlzTmFOKGNocjMpKVxyXG4gICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgZW5jNCA9IDY0O1xyXG4gICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArXHJcbiAgICAgICAgICAgICAgICAgICAgICBHQVV0aWxpdGllcy5rZXlTdHIuY2hhckF0KGVuYzEpICtcclxuICAgICAgICAgICAgICAgICAgICAgIEdBVXRpbGl0aWVzLmtleVN0ci5jaGFyQXQoZW5jMikgK1xyXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMzKSArXHJcbiAgICAgICAgICAgICAgICAgICAgICBHQVV0aWxpdGllcy5rZXlTdHIuY2hhckF0KGVuYzQpO1xyXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcclxuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBlbmMyID0gZW5jMyA9IGVuYzQgPSAwO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgd2hpbGUgKGkgPCBpbnB1dC5sZW5ndGgpO1xyXG5cclxuICAgICAgICAgICAgICAgIHJldHVybiBvdXRwdXQ7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZGVjb2RlNjQoaW5wdXQ6c3RyaW5nKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBvdXRwdXQ6c3RyaW5nID0gXCJcIjtcclxuICAgICAgICAgICAgICAgIHZhciBjaHIxOm51bWJlciwgY2hyMjpudW1iZXIsIGNocjM6bnVtYmVyID0gMDtcclxuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XHJcbiAgICAgICAgICAgICAgICB2YXIgaSA9IDA7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gcmVtb3ZlIGFsbCBjaGFyYWN0ZXJzIHRoYXQgYXJlIG5vdCBBLVosIGEteiwgMC05LCArLCAvLCBvciA9XHJcbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0dGVzdCA9IC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZztcclxuICAgICAgICAgICAgICAgIGlmIChiYXNlNjR0ZXN0LmV4ZWMoaW5wdXQpKSB7XHJcbiAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVGhlcmUgd2VyZSBpbnZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGluIHRoZSBpbnB1dCB0ZXh0LiBWYWxpZCBiYXNlNjQgY2hhcmFjdGVycyBhcmUgQS1aLCBhLXosIDAtOSwgJysnLCAnLycsYW5kICc9Jy4gRXhwZWN0IGVycm9ycyBpbiBkZWNvZGluZy5cIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpbnB1dCA9IGlucHV0LnJlcGxhY2UoL1teQS1aYS16MC05XFwrXFwvXFw9XS9nLCBcIlwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICBkb1xyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgZW5jMSA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcclxuICAgICAgICAgICAgICAgICAgIGVuYzIgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XHJcbiAgICAgICAgICAgICAgICAgICBlbmMzID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xyXG4gICAgICAgICAgICAgICAgICAgZW5jNCA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICBjaHIxID0gKGVuYzEgPDwgMikgfCAoZW5jMiA+PiA0KTtcclxuICAgICAgICAgICAgICAgICAgIGNocjIgPSAoKGVuYzIgJiAxNSkgPDwgNCkgfCAoZW5jMyA+PiAyKTtcclxuICAgICAgICAgICAgICAgICAgIGNocjMgPSAoKGVuYzMgJiAzKSA8PCA2KSB8IGVuYzQ7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIxKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICBpZiAoZW5jMyAhPSA2NCkge1xyXG4gICAgICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gb3V0cHV0ICsgU3RyaW5nLmZyb21DaGFyQ29kZShjaHIyKTtcclxuICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgIGlmIChlbmM0ICE9IDY0KSB7XHJcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjMpO1xyXG4gICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgIGNocjEgPSBjaHIyID0gY2hyMyA9IDA7XHJcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcclxuXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGRlY29kZVVSSShvdXRwdXQpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRpbWVJbnRlcnZhbFNpbmNlMTk3MCgpOiBudW1iZXJcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGRhdGU6RGF0ZSA9IG5ldyBEYXRlKCk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gTWF0aC5yb3VuZChkYXRlLmdldFRpbWUoKSAvIDEwMDApO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZUd1aWQoKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiAoR0FVdGlsaXRpZXMuczQoKSArIEdBVXRpbGl0aWVzLnM0KCkgKyBcIi1cIiArIEdBVXRpbGl0aWVzLnM0KCkgKyBcIi00XCIgKyBHQVV0aWxpdGllcy5zNCgpLnN1YnN0cigwLDMpICsgXCItXCIgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItXCIgKyBHQVV0aWxpdGllcy5zNCgpICsgR0FVdGlsaXRpZXMuczQoKSArIEdBVXRpbGl0aWVzLnM0KCkpLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHM0KCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gKCgoMStNYXRoLnJhbmRvbSgpKSoweDEwMDAwKXwwKS50b1N0cmluZygxNikuc3Vic3RyaW5nKDEpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHZhbGlkYXRvcnNcclxuICAgIHtcclxuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYS5sb2dnaW5nLkdBTG9nZ2VyO1xyXG4gICAgICAgIGltcG9ydCBFR0FTZGtFcnJvclR5cGUgPSBnYS5odHRwLkVHQVNka0Vycm9yVHlwZTtcclxuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYS51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVZhbGlkYXRvclxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBjYXJ0VHlwZTpzdHJpbmcsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZyk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVuY3lcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbCkgYW5kIG5lZWQgdG8gYmUgQS1aLCAzIGNoYXJhY3RlcnMgYW5kIGluIHRoZSBzdGFuZGFyZCBhdCBvcGVuZXhjaGFuZ2VyYXRlcy5vcmcuIEZhaWxlZCBjdXJyZW5jeTogXCIgKyBjdXJyZW5jeSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIGRvIG5vdCB2YWxpZGF0ZSBhbW91bnQgLSBpbnRlZ2VyIGlzIG5ldmVyIG51bGwgIVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGNhcnRUeXBlXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGNhcnRUeXBlLiBDYW5ub3QgYmUgYWJvdmUgMzIgbGVuZ3RoLiBTdHJpbmc6IFwiICsgY2FydFR5cGUpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoaXRlbVR5cGUsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbVR5cGUgY2hhcnNcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1UeXBlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1JZFxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtSWQuIENhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBpdGVtSWQpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGF2YWlsYWJsZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiwgYXZhaWxhYmxlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlVuZGVmaW5lZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBmbG93VHlwZTogSW52YWxpZCBmbG93IHR5cGUuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghY3VycmVuY3kpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUN1cnJlbmNpZXMsIGN1cnJlbmN5KSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBjdXJyZW5jeTogTm90IGZvdW5kIGluIGxpc3Qgb2YgcHJlLWRlZmluZWQgYXZhaWxhYmxlIHJlc291cmNlIGN1cnJlbmNpZXMuIFN0cmluZzogXCIgKyBjdXJyZW5jeSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCEoYW1vdW50ID4gMCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gYW1vdW50OiBGbG9hdCBhbW91bnQgY2Fubm90IGJlIDAgb3IgbmVnYXRpdmUuIFZhbHVlOiBcIiArIGFtb3VudCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFpdGVtVHlwZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKVwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbVR5cGUpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1UeXBlOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlSXRlbVR5cGVzLCBpdGVtVHlwZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IE5vdCBmb3VuZCBpbiBsaXN0IG9mIHByZS1kZWZpbmVkIGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtVHlwZXMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtSWQ6IENhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBpdGVtSWQpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGl0ZW1JZCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxOnN0cmluZywgcHJvZ3Jlc3Npb24wMjpzdHJpbmcsIHByb2dyZXNzaW9uMDM6c3RyaW5nKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IEludmFsaWQgcHJvZ3Jlc3Npb24gc3RhdHVzLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gTWFrZSBzdXJlIHByb2dyZXNzaW9ucyBhcmUgZGVmaW5lZCBhcyBlaXRoZXIgMDEsIDAxKzAyIG9yIDAxKzAyKzAzXHJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogMDMgZm91bmQgYnV0IDAxKzAyIGFyZSBpbnZhbGlkLiBQcm9ncmVzc2lvbiBtdXN0IGJlIHNldCBhcyBlaXRoZXIgMDEsIDAxKzAyIG9yIDAxKzAyKzAzLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlIGlmIChwcm9ncmVzc2lvbjAyICYmICFwcm9ncmVzc2lvbjAxKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudDogMDIgZm91bmQgYnV0IG5vdCAwMS4gUHJvZ3Jlc3Npb24gbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlIGlmICghcHJvZ3Jlc3Npb24wMSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gcHJvZ3Jlc3Npb24wMSAocmVxdWlyZWQpXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDEsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAxOiBDYW5ub3QgYmUgKG51bGwpLCBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAxKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAyXHJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDIsIHRydWUpKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMjogQ2Fubm90IGJlIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAyKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAyKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDI6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAzXHJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDMsIHRydWUpKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMzogQ2Fubm90IGJlIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAzKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhwcm9ncmVzc2lvbjAzKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURlc2lnbkV2ZW50KGV2ZW50SWQ6c3RyaW5nLCB2YWx1ZTpudW1iZXIpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBDYW5ub3QgYmUgKG51bGwpIG9yIGVtcHR5LiBPbmx5IDUgZXZlbnQgcGFydHMgYWxsb3dlZCBzZXBlcmF0ZWQgYnkgOi4gRWFjaCBwYXJ0IG5lZWQgdG8gYmUgMzIgY2hhcmFjdGVycyBvciBsZXNzLiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50SWRDaGFyYWN0ZXJzKGV2ZW50SWQpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBkZXNpZ24gZXZlbnQgLSBldmVudElkOiBOb24gdmFsaWQgY2hhcmFjdGVycy4gT25seSBhbGxvd2VkIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBldmVudElkKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAvLyB2YWx1ZTogYWxsb3cgMCwgbmVnYXRpdmUgYW5kIG5pbCAobm90IHJlcXVpcmVkKVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5OkVHQUVycm9yU2V2ZXJpdHksIG1lc3NhZ2U6c3RyaW5nKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoc2V2ZXJpdHkgPT09IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIHNldmVyaXR5OiBTZXZlcml0eSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVMb25nU3RyaW5nKG1lc3NhZ2UsIHRydWUpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBlcnJvciBldmVudCAtIG1lc3NhZ2U6IE1lc3NhZ2UgY2Fubm90IGJlIGFib3ZlIDgxOTIgY2hhcmFjdGVycy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTZGtFcnJvckV2ZW50KGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZywgdHlwZTpFR0FTZGtFcnJvclR5cGUpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmICh0eXBlID09PSBFR0FTZGtFcnJvclR5cGUuVW5kZWZpbmVkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBzZGsgZXJyb3IgZXZlbnQgLSB0eXBlOiBUeXBlIHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVLZXlzKGdhbWVLZXk6c3RyaW5nLCBnYW1lU2VjcmV0OnN0cmluZyk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVLZXksIC9eW0EtejAtOV17MzJ9JC8pKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChnYW1lU2VjcmV0LCAvXltBLXowLTldezQwfSQvKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5OnN0cmluZyk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKCFjdXJyZW5jeSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGN1cnJlbmN5LCAvXltBLVpdezN9JC8pKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGV2ZW50UGFydDpzdHJpbmcsIGFsbG93TnVsbDpib29sZWFuKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoYWxsb3dOdWxsICYmICFldmVudFBhcnQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudFBhcnQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmIChldmVudFBhcnQubGVuZ3RoID4gNjQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGV2ZW50UGFydDpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRQYXJ0LCAvXltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSQvKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRMZW5ndGgoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghZXZlbnRJZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudElkLCAvXlteOl17MSw2NH0oPzo6W146XXsxLDY0fSl7MCw0fSQvKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRDaGFyYWN0ZXJzKGV2ZW50SWQ6c3RyaW5nKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50SWQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0oOltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSl7MCw0fSQvKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuSW5pdFJlcXVlc3RSZXNwb25zZShpbml0UmVzcG9uc2U6e1trZXk6c3RyaW5nXTogYW55fSk6IHtba2V5OnN0cmluZ106IGFueX1cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBzdXJlIHdlIGhhdmUgYSB2YWxpZCBkaWN0XHJcbiAgICAgICAgICAgICAgICBpZiAoaW5pdFJlc3BvbnNlID09IG51bGwpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBubyByZXNwb25zZSBkaWN0aW9uYXJ5LlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgdmFsaWRhdGVkRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZW5hYmxlZCBmaWVsZFxyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImVuYWJsZWRcIl0gPSBpbml0UmVzcG9uc2VbXCJlbmFibGVkXCJdO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2VuYWJsZWQnIGZpZWxkLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBzZXJ2ZXJfdHNcclxuICAgICAgICAgICAgICAgIHRyeVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUc051bWJlcjpudW1iZXIgPSBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl07XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNlcnZlclRzTnVtYmVyID4gMClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJzZXJ2ZXJfdHNcIl0gPSBzZXJ2ZXJUc051bWJlcjtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHZhbHVlIGluICdzZXJ2ZXJfdHMnIGZpZWxkLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ3NlcnZlcl90cycgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIHZhbHVlPVwiICsgaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdICsgXCIsIFwiICsgZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHZhbGlkYXRlZERpY3Q7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVCdWlsZChidWlsZDpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTaG9ydFN0cmluZyhidWlsZCwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrV3JhcHBlclZlcnNpb24od3JhcHBlclZlcnNpb246c3RyaW5nKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHdyYXBwZXJWZXJzaW9uLCAvXih1bml0eXx1bnJlYWwpIFswLTldezAsNX0oXFwuWzAtOV17MCw1fSl7MCwyfSQvKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVuZ2luZVZlcnNpb24oZW5naW5lVmVyc2lvbjpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghZW5naW5lVmVyc2lvbiB8fCAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZW5naW5lVmVyc2lvbiwgL14odW5pdHl8dW5yZWFsKSBbMC05XXswLDV9KFxcLlswLTldezAsNX0pezAsMn0kLykpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVVc2VySWQodUlkOnN0cmluZyk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVN0cmluZyh1SWQsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gdXNlciBpZDogaWQgY2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTaG9ydFN0cmluZyhzaG9ydFN0cmluZzpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXHJcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhc2hvcnRTdHJpbmcpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKCFzaG9ydFN0cmluZyB8fCBzaG9ydFN0cmluZy5sZW5ndGggPiAzMilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVN0cmluZyhzOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eSBvciBuaWxcclxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFzKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmICghcyB8fCBzLmxlbmd0aCA+IDY0KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlTG9uZ1N0cmluZyhsb25nU3RyaW5nOnN0cmluZywgY2FuQmVFbXB0eTpib29sZWFuKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eVxyXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIWxvbmdTdHJpbmcpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKCFsb25nU3RyaW5nIHx8IGxvbmdTdHJpbmcubGVuZ3RoID4gODE5MilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25UeXBlOnN0cmluZyk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGNvbm5lY3Rpb25UeXBlLCAvXih3d2FufHdpZml8bGFufG9mZmxpbmUpJC8pO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVZhbGlkYXRvci52YWxpZGF0ZUFycmF5T2ZTdHJpbmdzKDIwLCAzMiwgZmFsc2UsIFwiY3VzdG9tIGRpbWVuc2lvbnNcIiwgY3VzdG9tRGltZW5zaW9ucyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXMocmVzb3VyY2VDdXJyZW5jaWVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgNjQsIGZhbHNlLCBcInJlc291cmNlIGN1cnJlbmNpZXNcIiwgcmVzb3VyY2VDdXJyZW5jaWVzKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmcgZm9yIHJlZ2V4XHJcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpIGluIHJlc291cmNlQ3VycmVuY2llcylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHJlc291cmNlQ3VycmVuY2llc1tpXSwgL15bQS1aYS16XSskLykpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwicmVzb3VyY2UgY3VycmVuY2llcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBjdXJyZW5jeSBjYW4gb25seSBiZSBBLVosIGEtei4gU3RyaW5nIHdhczogXCIgKyByZXNvdXJjZUN1cnJlbmNpZXNbaV0pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJyZXNvdXJjZSBpdGVtIHR5cGVzXCIsIHJlc291cmNlSXRlbVR5cGVzKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCByZXNvdXJjZUl0ZW1UeXBlIGZvciBldmVudHBhcnQgdmFsaWRhdGlvblxyXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSBpbiByZXNvdXJjZUl0ZW1UeXBlcylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhyZXNvdXJjZUl0ZW1UeXBlc1tpXSkpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwicmVzb3VyY2UgaXRlbSB0eXBlcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBpdGVtIHR5cGUgY2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZyB3YXM6IFwiICsgcmVzb3VyY2VJdGVtVHlwZXNbaV0pO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24wMTpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXHJcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAxKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAxKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbjAyOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcclxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDIpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDIpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uMDM6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxyXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMykpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBcnJheU9mU3RyaW5ncyhtYXhDb3VudDpudW1iZXIsIG1heFN0cmluZ0xlbmd0aDpudW1iZXIsIGFsbG93Tm9WYWx1ZXM6Ym9vbGVhbiwgbG9nVGFnOnN0cmluZywgYXJyYXlPZlN0cmluZ3M6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGFycmF5VGFnOnN0cmluZyA9IGxvZ1RhZztcclxuXHJcbiAgICAgICAgICAgICAgICAvLyB1c2UgYXJyYXlUYWcgdG8gYW5ub3RhdGUgd2FybmluZyBsb2dcclxuICAgICAgICAgICAgICAgIGlmICghYXJyYXlUYWcpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYXJyYXlUYWcgPSBcIkFycmF5XCI7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoIWFycmF5T2ZTdHJpbmdzKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIG51bGwuIFwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgZW1wdHlcclxuICAgICAgICAgICAgICAgIGlmIChhbGxvd05vVmFsdWVzID09IGZhbHNlICYmIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCA9PSAwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYXJyYXkgY2Fubm90IGJlIGVtcHR5LiBcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggY291bnRcclxuICAgICAgICAgICAgICAgIGlmIChtYXhDb3VudCA+IDAgJiYgYXJyYXlPZlN0cmluZ3MubGVuZ3RoID4gbWF4Q291bnQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgZXhjZWVkIFwiICsgbWF4Q291bnQgKyBcIiB2YWx1ZXMuIEl0IGhhcyBcIiArIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCArIFwiIHZhbHVlcy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggc3RyaW5nXHJcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpIGluIGFycmF5T2ZTdHJpbmdzKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBzdHJpbmdMZW5ndGg6bnVtYmVyID0gIWFycmF5T2ZTdHJpbmdzW2ldID8gMCA6IGFycmF5T2ZTdHJpbmdzW2ldLmxlbmd0aDtcclxuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eSAobm90IGFsbG93ZWQpXHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHN0cmluZ0xlbmd0aCA9PT0gMClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogY29udGFpbmVkIGFuIGVtcHR5IHN0cmluZy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggbGVuZ3RoXHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1heFN0cmluZ0xlbmd0aCA+IDAgJiYgc3RyaW5nTGVuZ3RoID4gbWF4U3RyaW5nTGVuZ3RoKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhIHN0cmluZyBleGNlZWRlZCBtYXggYWxsb3dlZCBsZW5ndGggKHdoaWNoIGlzOiBcIiArIG1heFN0cmluZ0xlbmd0aCArIFwiKS4gU3RyaW5nIHdhczogXCIgKyBhcnJheU9mU3RyaW5nc1tpXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUZhY2Vib29rSWQoZmFjZWJvb2tJZDpzdHJpbmcpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTdHJpbmcoZmFjZWJvb2tJZCwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBmYWNlYm9vayBpZDogaWQgY2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVHZW5kZXIoZ2VuZGVyOkVHQUdlbmRlcik6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKGdlbmRlciA9PT0gRUdBR2VuZGVyLlVuZGVmaW5lZCB8fCAhKGdlbmRlciA9PT0gRUdBR2VuZGVyLk1hbGUgfHwgZ2VuZGVyID09PSBFR0FHZW5kZXIuRmVtYWxlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gZ2VuZGVyOiBIYXMgdG8gYmUgJ21hbGUnIG9yICdmZW1hbGUnLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJpcnRoeWVhcihiaXJ0aFllYXI6bnVtYmVyKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoYmlydGhZZWFyIDwgMCB8fCBiaXJ0aFllYXIgPiA5OTk5KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBiaXJ0aFllYXI6IENhbm5vdCBiZSAobnVsbCkgb3IgaW52YWxpZCByYW5nZS5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDbGllbnRUcyhjbGllbnRUczpudW1iZXIpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChjbGllbnRUcyA8ICgtNDI5NDk2NzI5NSsxKSB8fCBjbGllbnRUcyA+ICg0Mjk0OTY3Mjk1LTEpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIGRldmljZVxyXG4gICAge1xyXG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhLmxvZ2dpbmcuR0FMb2dnZXI7XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmFsdWVWZXJzaW9uXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyB2YWx1ZTpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyB2ZXJzaW9uOnN0cmluZztcclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihuYW1lOnN0cmluZywgdmFsdWU6c3RyaW5nLCB2ZXJzaW9uOnN0cmluZylcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcclxuICAgICAgICAgICAgICAgIHRoaXMudmFsdWUgPSB2YWx1ZTtcclxuICAgICAgICAgICAgICAgIHRoaXMudmVyc2lvbiA9IHZlcnNpb247XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmVyc2lvblxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHVibGljIG5hbWU6c3RyaW5nO1xyXG4gICAgICAgICAgICBwdWJsaWMgdmVyc2lvbjpzdHJpbmc7XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZlcnNpb246c3RyaW5nKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLm5hbWUgPSBuYW1lO1xyXG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBRGV2aWNlXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBzZGtXcmFwcGVyVmVyc2lvbjpzdHJpbmcgPSBcImphdmFzY3JpcHQgMS4wLjVcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IG9zVmVyc2lvblBhaXI6TmFtZVZlcnNpb24gPSBHQURldmljZS5tYXRjaEl0ZW0oW1xyXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnBsYXRmb3JtLFxyXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnVzZXJBZ2VudCxcclxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci5hcHBWZXJzaW9uLFxyXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnZlbmRvcixcclxuICAgICAgICAgICAgICAgIHdpbmRvdy5vcGVyYVxyXG4gICAgICAgICAgICBdLmpvaW4oJyAnKSwgW1xyXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzX3Bob25lXCIsIFwiV2luZG93cyBQaG9uZVwiLCBcIk9TXCIpLFxyXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzXCIsIFwiV2luXCIsIFwiTlRcIiksXHJcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQaG9uZVwiLCBcIk9TXCIpLFxyXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGFkXCIsIFwiT1NcIiksXHJcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQb2RcIiwgXCJPU1wiKSxcclxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwiYW5kcm9pZFwiLCBcIkFuZHJvaWRcIiwgXCJBbmRyb2lkXCIpLFxyXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJibGFja0JlcnJ5XCIsIFwiQmxhY2tCZXJyeVwiLCBcIi9cIiksXHJcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIm1hY19vc3hcIiwgXCJNYWNcIiwgXCJPUyBYXCIpLFxyXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ0aXplblwiLCBcIlRpemVuXCIsIFwiVGl6ZW5cIiksXHJcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImxpbnV4XCIsIFwiTGludXhcIiwgXCJydlwiKVxyXG4gICAgICAgICAgICBdKTtcclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgYnVpbGRQbGF0Zm9ybTpzdHJpbmcgPSBHQURldmljZS5ydW50aW1lUGxhdGZvcm1Ub1N0cmluZygpO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1vZGVsOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1vZGVsKCk7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgZGV2aWNlTWFudWZhY3R1cmVyOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1hbnVmYWN0dXJlcigpO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IG9zVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRPU1ZlcnNpb25TdHJpbmcoKTtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBicm93c2VyVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRCcm93c2VyVmVyc2lvblN0cmluZygpO1xyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZGtHYW1lRW5naW5lVmVyc2lvbjpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBjb25uZWN0aW9uVHlwZTpzdHJpbmc7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1heFNhZmVJbnRlZ2VyOm51bWJlciA9IE1hdGgucG93KDIsIDUzKSAtIDE7XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHRvdWNoKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbGV2YW50U2RrVmVyc2lvbigpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYoR0FEZXZpY2Uuc2RrR2FtZUVuZ2luZVZlcnNpb24pXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka1dyYXBwZXJWZXJzaW9uO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldENvbm5lY3Rpb25UeXBlKCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UuY29ubmVjdGlvblR5cGU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdXBkYXRlQ29ubmVjdGlvblR5cGUoKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihuYXZpZ2F0b3Iub25MaW5lKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiaW9zXCIgfHwgR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSA9PT0gXCJhbmRyb2lkXCIpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwid3dhblwiO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwibGFuXCI7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIC8vIFRPRE86IERldGVjdCB3aWZpIHVzYWdlXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcIm9mZmxpbmVcIjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0T1NWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSArIFwiIFwiICsgR0FEZXZpY2Uub3NWZXJzaW9uUGFpci52ZXJzaW9uO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBydW50aW1lUGxhdGZvcm1Ub1N0cmluZygpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLm9zVmVyc2lvblBhaXIubmFtZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0QnJvd3NlclZlcnNpb25TdHJpbmcoKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciB1YTpzdHJpbmcgPSBuYXZpZ2F0b3IudXNlckFnZW50O1xyXG4gICAgICAgICAgICAgICAgdmFyIHRlbTpSZWdFeHBNYXRjaEFycmF5O1xyXG4gICAgICAgICAgICAgICAgdmFyIE06UmVnRXhwTWF0Y2hBcnJheSA9IHVhLm1hdGNoKC8ob3BlcmF8Y2hyb21lfHNhZmFyaXxmaXJlZm94fHVicm93c2VyfG1zaWV8dHJpZGVudCg/PVxcLykpXFwvP1xccyooXFxkKykvaSkgfHwgW107XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoL3RyaWRlbnQvaS50ZXN0KE1bMV0pKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IC9cXGJydlsgOl0rKFxcZCspL2cuZXhlYyh1YSkgfHwgW107XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICdJRSAnICsgKHRlbVsxXSB8fCAnJyk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoTVsxXSA9PT0gJ0Nocm9tZScpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGVtID0gdWEubWF0Y2goL1xcYihPUFJ8RWRnZXxVQnJvd3NlcilcXC8oXFxkKykvKTtcclxuICAgICAgICAgICAgICAgICAgICBpZih0ZW0hPSBudWxsKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRlbS5zbGljZSgxKS5qb2luKCcgJykucmVwbGFjZSgnT1BSJywgJ09wZXJhJykucmVwbGFjZSgnVUJyb3dzZXInLCAnVUMnKS50b0xvd2VyQ2FzZSgpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgTVN0cmluZzpzdHJpbmdbXSA9IE1bMl0/IFtNWzFdLCBNWzJdXTogW25hdmlnYXRvci5hcHBOYW1lLCBuYXZpZ2F0b3IuYXBwVmVyc2lvbiwgJy0/J107XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoKHRlbSA9IHVhLm1hdGNoKC92ZXJzaW9uXFwvKFxcZCspL2kpKSAhPSBudWxsKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIE1TdHJpbmcuc3BsaWNlKDEsIDEsIHRlbVsxXSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIE1TdHJpbmcuam9pbignICcpLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldERldmljZU1vZGVsKCk6c3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6c3RyaW5nID0gXCJ1bmtub3duXCI7XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6c3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6c3RyaW5nID0gXCJ1bmtub3duXCI7XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWF0Y2hJdGVtKGFnZW50OnN0cmluZywgZGF0YTpBcnJheTxOYW1lVmFsdWVWZXJzaW9uPik6TmFtZVZlcnNpb25cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coXCJBR0VOVDogXCIgKyBhZ2VudCk7XHJcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0Ok5hbWVWZXJzaW9uID0gbmV3IE5hbWVWZXJzaW9uKFwidW5rbm93blwiLCBcIjAuMC4wXCIpO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciBpOm51bWJlciA9IDA7XHJcbiAgICAgICAgICAgICAgICB2YXIgajpudW1iZXIgPSAwO1xyXG4gICAgICAgICAgICAgICAgdmFyIHJlZ2V4OlJlZ0V4cDtcclxuICAgICAgICAgICAgICAgIHZhciByZWdleHY6UmVnRXhwO1xyXG4gICAgICAgICAgICAgICAgdmFyIG1hdGNoOmJvb2xlYW47XHJcbiAgICAgICAgICAgICAgICB2YXIgbWF0Y2hlczpSZWdFeHBNYXRjaEFycmF5O1xyXG4gICAgICAgICAgICAgICAgdmFyIG1hdGhjZXNSZXN1bHQ6c3RyaW5nO1xyXG4gICAgICAgICAgICAgICAgdmFyIHZlcnNpb246c3RyaW5nO1xyXG5cclxuICAgICAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSAxKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJlZ2V4ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZhbHVlLCAnaScpO1xyXG4gICAgICAgICAgICAgICAgICAgIG1hdGNoID0gcmVnZXgudGVzdChhZ2VudCk7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGNoKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmVnZXh2ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZlcnNpb24gKyAnWy0gLzo7XShbXFxcXGQuX10rKScsICdpJyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG1hdGNoZXMgPSBhZ2VudC5tYXRjaChyZWdleHYpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJyc7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0Y2hlc1sxXSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYXRoY2VzUmVzdWx0ID0gbWF0Y2hlc1sxXTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAobWF0aGNlc1Jlc3VsdClcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1hdGNoZXNBcnJheTpzdHJpbmdbXSA9IG1hdGhjZXNSZXN1bHQuc3BsaXQoL1suX10rLyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGogPSAwOyBqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMyk7IGogKz0gMSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uICs9IG1hdGNoZXNBcnJheVtqXSArIChqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMykgLSAxID8gJy4nIDogJycpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmVyc2lvbiA9ICcwLjAuMCc7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5uYW1lID0gZGF0YVtpXS5uYW1lO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQudmVyc2lvbiA9IHZlcnNpb247XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICAgICAgICDCoMKgwqDCoMKgwqDCoMKgfVxyXG4gICAgICAgICAgICDCoMKgwqDCoH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xyXG4gICAge1xyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBUaW1lZEJsb2NrXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBwdWJsaWMgcmVhZG9ubHkgZGVhZGxpbmU6RGF0ZTtcclxuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGJsb2NrOigpID0+IHZvaWQ7XHJcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBpZDpudW1iZXI7XHJcbiAgICAgICAgICAgIHB1YmxpYyBpZ25vcmU6Ym9vbGVhbjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaWRDb3VudGVyOm51bWJlciA9IDA7XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IoZGVhZGxpbmU6RGF0ZSwgYmxvY2s6KCkgPT4gdm9pZClcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdGhpcy5kZWFkbGluZSA9IGRlYWRsaW5lO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5ibG9jayA9IGJsb2NrO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5pZ25vcmUgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAgIHRoaXMuaWQgPSArK1RpbWVkQmxvY2suaWRDb3VudGVyO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xyXG4gICAge1xyXG4gICAgICAgIGV4cG9ydCBpbnRlcmZhY2UgSUNvbXBhcmVyPFQ+XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBjb21wYXJlKHg6VCwgeTpUKTogbnVtYmVyO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgZXhwb3J0IGNsYXNzIFByaW9yaXR5UXVldWU8VEl0ZW0+XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBwcml2YXRlIF9zdWJRdWV1ZXM6e1trZXk6bnVtYmVyXTogQXJyYXk8VEl0ZW0+fTtcclxuICAgICAgICAgICAgcHJpdmF0ZSBfc29ydGVkS2V5czpBcnJheTxudW1iZXI+O1xyXG4gICAgICAgICAgICBwcml2YXRlIGNvbXBhcmVyOklDb21wYXJlcjxudW1iZXI+O1xyXG5cclxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKHByaW9yaXR5Q29tcGFyZXI6SUNvbXBhcmVyPG51bWJlcj4pXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuY29tcGFyZXIgPSBwcmlvcml0eUNvbXBhcmVyO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fc3ViUXVldWVzID0ge307XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzID0gW107XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBlbnF1ZXVlKHByaW9yaXR5Om51bWJlciwgaXRlbTpUSXRlbSk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYodGhpcy5fc29ydGVkS2V5cy5pbmRleE9mKHByaW9yaXR5KSA9PT0gLTEpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5hZGRRdWV1ZU9mUHJpb3JpdHkocHJpb3JpdHkpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIHRoaXMuX3N1YlF1ZXVlc1twcmlvcml0eV0ucHVzaChpdGVtKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBhZGRRdWV1ZU9mUHJpb3JpdHkocHJpb3JpdHk6bnVtYmVyKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnB1c2gocHJpb3JpdHkpO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5fc29ydGVkS2V5cy5zb3J0KCh4Om51bWJlciwgeTpudW1iZXIpID0+IHRoaXMuY29tcGFyZXIuY29tcGFyZSh4LCB5KSk7XHJcbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXNbcHJpb3JpdHldID0gW107XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBwZWVrKCk6IFRJdGVtXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKHRoaXMuaGFzSXRlbXMoKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5fc3ViUXVldWVzW3RoaXMuX3NvcnRlZEtleXNbMF1dWzBdO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlRoZSBxdWV1ZSBpcyBlbXB0eVwiKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIGhhc0l0ZW1zKCk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3NvcnRlZEtleXMubGVuZ3RoID4gMDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIGRlcXVldWUoKTogVEl0ZW1cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYodGhpcy5oYXNJdGVtcygpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmRlcXVldWVGcm9tSGlnaFByaW9yaXR5UXVldWUoKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgcXVldWUgaXMgZW1wdHlcIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgZGVxdWV1ZUZyb21IaWdoUHJpb3JpdHlRdWV1ZSgpOiBUSXRlbVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RLZXk6bnVtYmVyID0gdGhpcy5fc29ydGVkS2V5c1swXTtcclxuICAgICAgICAgICAgICAgIHZhciBuZXh0SXRlbTpUSXRlbSA9IHRoaXMuX3N1YlF1ZXVlc1tmaXJzdEtleV0uc2hpZnQoKTtcclxuICAgICAgICAgICAgICAgIGlmKHRoaXMuX3N1YlF1ZXVlc1tmaXJzdEtleV0ubGVuZ3RoID09PSAwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMuc2hpZnQoKTtcclxuICAgICAgICAgICAgICAgICAgICBkZWxldGUgdGhpcy5fc3ViUXVldWVzW2ZpcnN0S2V5XTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gbmV4dEl0ZW07XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIiwibW9kdWxlIGdhXHJcbntcclxuICAgIGV4cG9ydCBtb2R1bGUgc3RvcmVcclxuICAgIHtcclxuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYS5sb2dnaW5nLkdBTG9nZ2VyO1xyXG5cclxuICAgICAgICBleHBvcnQgZW51bSBFR0FTdG9yZUFyZ3NPcGVyYXRvclxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgRXF1YWwsXHJcbiAgICAgICAgICAgIExlc3NPckVxdWFsLFxyXG4gICAgICAgICAgICBOb3RFcXVhbFxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEV2ZW50cyA9IDAsXHJcbiAgICAgICAgICAgIFNlc3Npb25zID0gMSxcclxuICAgICAgICAgICAgUHJvZ3Jlc3Npb24gPSAyXHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdG9yZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdG9yZSA9IG5ldyBHQVN0b3JlKCk7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0b3JhZ2VBdmFpbGFibGU6Ym9vbGVhbjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgTWF4TnVtYmVyT2ZFbnRyaWVzOm51bWJlciA9IDIwMDA7XHJcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzZXNzaW9uc1N0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XHJcbiAgICAgICAgICAgIHByaXZhdGUgcHJvZ3Jlc3Npb25TdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0b3JlSXRlbXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBLZXlQcmVmaXg6c3RyaW5nID0gXCJHQTo6XCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEV2ZW50c1N0b3JlS2V5OnN0cmluZyA9IFwiZ2FfZXZlbnRcIjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbnNTdG9yZUtleTpzdHJpbmcgPSBcImdhX3Nlc3Npb25cIjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgUHJvZ3Jlc3Npb25TdG9yZUtleTpzdHJpbmcgPSBcImdhX3Byb2dyZXNzaW9uXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEl0ZW1zU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9pdGVtc1wiO1xyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHRyeVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgbG9jYWxTdG9yYWdlID09PSAnb2JqZWN0JylcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJywgJ3llcycpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSB0cnVlO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU3RvcmFnZSBpcyBhdmFpbGFibGU/OiBcIiArIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNTdG9yYWdlQXZhaWxhYmxlKCk6Ym9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpOiBib29sZWFuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlLmxlbmd0aCArIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZS5sZW5ndGggPiBHQVN0b3JlLk1heE51bWJlck9mRW50cmllcztcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZWxlY3Qoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10sIHNvcnQ6Ym9vbGVhbiA9IGZhbHNlLCBtYXhDb3VudDpudW1iZXIgPSAwKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xyXG5cclxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHZhciBhZGQ6Ym9vbGVhbiA9IHRydWU7XHJcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGVudHJ5W2FyZ3NFbnRyeVswXV0pXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPT0gYXJnc0VudHJ5WzJdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gPD0gYXJnc0VudHJ5WzJdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGVudHJ5W2FyZ3NFbnRyeVswXV0gIT0gYXJnc0VudHJ5WzJdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighYWRkKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYoYWRkKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnB1c2goZW50cnkpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZihzb3J0KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdC5zb3J0KChhOntba2V5OnN0cmluZ106IGFueX0sIGI6e1trZXk6c3RyaW5nXTogYW55fSkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGFbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKSAtIChiW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcilcclxuICAgICAgICAgICAgICAgICAgICB9KTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZihtYXhDb3VudCA+IDAgJiYgcmVzdWx0Lmxlbmd0aCA+IG1heENvdW50KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHJlc3VsdC5zbGljZSgwLCBtYXhDb3VudCArIDEpXHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGUoc3RvcmU6RUdBU3RvcmUsIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgYW55XT4sIHdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGU6Ym9vbGVhbiA9IHRydWU7XHJcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IHdoZXJlQXJncy5sZW5ndGg7ICsrailcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSB3aGVyZUFyZ3Nbal07XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWw6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTGVzc09yRXF1YWw6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmVBcmdzT3BlcmF0b3IuTm90RXF1YWw6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXVwZGF0ZSlcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmKHVwZGF0ZSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBzZXRBcmdzLmxlbmd0aDsgKytqKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc2V0QXJnc0VudHJ5OltzdHJpbmcsIGFueV0gPSBzZXRBcmdzW2pdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc2V0QXJnc0VudHJ5WzBdXSA9IHNldEFyZ3NFbnRyeVsxXTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBkZWxldGUoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+KTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGRlbDpib29sZWFuID0gdHJ1ZTtcclxuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgYXJncy5sZW5ndGg7ICsrailcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc3dpdGNoKGFyZ3NFbnRyeVsxXSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFkZWwpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBpZihkZWwpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUuc3BsaWNlKGksIDEpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAtLWk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluc2VydChzdG9yZTpFR0FTdG9yZSwgbmV3RW50cnk6e1trZXk6c3RyaW5nXTogYW55fSwgcmVwbGFjZTpib29sZWFuID0gZmFsc2UsIHJlcGxhY2VLZXk6c3RyaW5nID0gbnVsbCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmKHJlcGxhY2UpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYoIXJlcGxhY2VLZXkpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICB2YXIgcmVwbGFjZWQ6Ym9vbGVhbiA9IGZhbHNlO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVtyZXBsYWNlS2V5XSA9PSBuZXdFbnRyeVtyZXBsYWNlS2V5XSlcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIG5ld0VudHJ5KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudHJ5W3NdID0gbmV3RW50cnlbc107XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXBsYWNlZCA9IHRydWU7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYoIXJlcGxhY2VkKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudFN0b3JlLnB1c2gobmV3RW50cnkpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2F2ZSgpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTdG9yYWdlIGlzIG5vdCBhdmFpbGFibGUsIGNhbm5vdCBzYXZlLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKSk7XHJcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlKSk7XHJcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuUHJvZ3Jlc3Npb25TdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlKSk7XHJcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuSXRlbXNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgbG9hZCgpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJTdG9yYWdlIGlzIG5vdCBhdmFpbGFibGUsIGNhbm5vdCBsb2FkLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5KSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnZXZlbnRzJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBbXTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICB0cnlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5TZXNzaW9uc1N0b3JlS2V5KSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUgPSBbXTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBjYXRjaChlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ3Nlc3Npb25zJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIHRyeVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlByb2dyZXNzaW9uU3RvcmVLZXkpKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAncHJvZ3Jlc3Npb24nIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuSXRlbXNTdG9yZUtleSkpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zID0ge307XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdpdGVtcycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJdGVtKGtleTpzdHJpbmcsIHZhbHVlOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGtleVdpdGhQcmVmaXg6c3RyaW5nID0gR0FTdG9yZS5LZXlQcmVmaXggKyBrZXk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoIXZhbHVlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKGtleVdpdGhQcmVmaXggaW4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZGVsZXRlIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdID0gdmFsdWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SXRlbShrZXk6c3RyaW5nKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBrZXlXaXRoUHJlZml4OnN0cmluZyA9IEdBU3RvcmUuS2V5UHJlZml4ICsga2V5O1xyXG4gICAgICAgICAgICAgICAgaWYoa2V5V2l0aFByZWZpeCBpbiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XSBhcyBzdHJpbmc7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldFN0b3JlKHN0b3JlOkVHQVN0b3JlKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgc3dpdGNoKHN0b3JlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuRXZlbnRzOlxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmU7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlNlc3Npb25zOlxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU3RvcmUuUHJvZ3Jlc3Npb246XHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJHQVN0b3JlLmdldFN0b3JlKCk6IENhbm5vdCBmaW5kIHN0b3JlOiBcIiArIHN0b3JlKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHN0YXRlXHJcbiAgICB7XHJcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2EudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcclxuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYS51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XHJcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2EubG9nZ2luZy5HQUxvZ2dlcjtcclxuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhLnN0b3JlLkdBU3RvcmU7XHJcbiAgICAgICAgaW1wb3J0IEdBRGV2aWNlID0gZ2EuZGV2aWNlLkdBRGV2aWNlO1xyXG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhLnN0b3JlLkVHQVN0b3JlO1xyXG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xyXG5cclxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdGF0ZVxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZGtFcnJvcjpzdHJpbmcgPSBcInNka19lcnJvclwiO1xyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0YXRlID0gbmV3IEdBU3RhdGUoKTtcclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgdXNlcklkOnN0cmluZztcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRVc2VySWQodXNlcklkOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VySWQgPSB1c2VySWQ7XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGlkZW50aWZpZXI6c3RyaW5nO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldElkZW50aWZpZXIoKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZWQ6Ym9vbGVhbjtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc0luaXRpYWxpemVkKCk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQ7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJbml0aWFsaXplZCh2YWx1ZTpib29sZWFuKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRpYWxpemVkID0gdmFsdWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzZXNzaW9uU3RhcnQ6bnVtYmVyO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25TdGFydCgpOiBudW1iZXJcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0O1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHNlc3Npb25OdW06bnVtYmVyO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNlc3Npb25OdW0oKTogbnVtYmVyXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW07XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgdHJhbnNhY3Rpb25OdW06bnVtYmVyO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFRyYW5zYWN0aW9uTnVtKCk6IG51bWJlclxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS50cmFuc2FjdGlvbk51bTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHNlc3Npb25JZDpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbklkKCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAxOnN0cmluZztcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDI6c3RyaW5nO1xyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMzpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDM7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgZ2FtZUtleTpzdHJpbmc7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0R2FtZUtleSgpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZUtleTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBnYW1lU2VjcmV0OnN0cmluZztcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lU2VjcmV0KCk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5nYW1lU2VjcmV0O1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTpBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCk6IEFycmF5PHN0cmluZz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXHJcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSA9IHZhbHVlO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjpBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKCk6IEFycmF5PHN0cmluZz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXHJcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMiA9IHZhbHVlO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMzpBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCk6IEFycmF5PHN0cmluZz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXHJcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyA9IHZhbHVlO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llczpBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKCk6IEFycmF5PHN0cmluZz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXHJcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXModmFsdWUpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzID0gdmFsdWU7XHJcblxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXTtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcygpOiBBcnJheTxzdHJpbmc+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXModmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcclxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZVJlc291cmNlSXRlbVR5cGVzKHZhbHVlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzID0gdmFsdWU7XHJcblxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGJ1aWxkOnN0cmluZztcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRCdWlsZCgpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQ7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRCdWlsZCh2YWx1ZTpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQgPSB2YWx1ZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc6Ym9vbGVhbjtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKTogYm9vbGVhblxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmc7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgZmFjZWJvb2tJZDpzdHJpbmc7XHJcbiAgICAgICAgICAgIHByaXZhdGUgZ2VuZGVyOnN0cmluZztcclxuICAgICAgICAgICAgcHJpdmF0ZSBiaXJ0aFllYXI6bnVtYmVyO1xyXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnQ2FjaGVkOntba2V5OnN0cmluZ106IGFueX07XHJcbiAgICAgICAgICAgIHB1YmxpYyBpbml0QXV0aG9yaXplZDpib29sZWFuO1xyXG4gICAgICAgICAgICBwdWJsaWMgY2xpZW50U2VydmVyVGltZU9mZnNldDpudW1iZXI7XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGRlZmF1bHRVc2VySWQ6c3RyaW5nO1xyXG4gICAgICAgICAgICBwcml2YXRlIHNldERlZmF1bHRJZCh2YWx1ZTpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuZGVmYXVsdFVzZXJJZCA9ICF2YWx1ZSA/IFwiXCIgOiB2YWx1ZTtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXREZWZhdWx0SWQoKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQ7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWdEZWZhdWx0Ontba2V5OnN0cmluZ106IHN0cmluZ30gPSB7fTtcclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBnZXRTZGtDb25maWcoKToge1trZXk6c3RyaW5nXTogYW55fVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0O1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xyXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZylcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZztcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0O1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xyXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09PSAwKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnRGVmYXVsdDtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblRyaWVzOntba2V5OnN0cmluZ106IG51bWJlcn0gPSB7fTtcclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBEZWZhdWx0VXNlcklkS2V5OnN0cmluZyA9IFwiZGVmYXVsdF91c2VyX2lkXCI7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbk51bUtleTpzdHJpbmcgPSBcInNlc3Npb25fbnVtXCI7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgVHJhbnNhY3Rpb25OdW1LZXk6c3RyaW5nID0gXCJ0cmFuc2FjdGlvbl9udW1cIjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRmFjZWJvb2tJZEtleTpzdHJpbmcgPSBcImZhY2Vib29rX2lkXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IEdlbmRlcktleTpzdHJpbmcgPSBcImdlbmRlclwiO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBCaXJ0aFllYXJLZXk6c3RyaW5nID0gXCJiaXJ0aF95ZWFyXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IERpbWVuc2lvbjAxS2V5OnN0cmluZyA9IFwiZGltZW5zaW9uMDFcIjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDJLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMlwiO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBEaW1lbnNpb24wM0tleTpzdHJpbmcgPSBcImRpbWVuc2lvbjAzXCI7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgU2RrQ29uZmlnQ2FjaGVkS2V5OnN0cmluZyA9IFwic2RrX2NvbmZpZ19jYWNoZWRcIjtcclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNFbmFibGVkKCk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTZGtDb25maWc6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0U2RrQ29uZmlnKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKGN1cnJlbnRTZGtDb25maWdbXCJlbmFibGVkXCJdICYmIGN1cnJlbnRTZGtDb25maWdbXCJlbmFibGVkXCJdID09IFwiZmFsc2VcIilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlIGlmICghR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEgPSBkaW1lbnNpb247XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgZGltZW5zaW9uKTtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIgPSBkaW1lbnNpb247XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMktleSwgZGltZW5zaW9uKTtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDMoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBkaW1lbnNpb247XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSwgZGltZW5zaW9uKTtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RmFjZWJvb2tJZChmYWNlYm9va0lkOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkID0gZmFjZWJvb2tJZDtcclxuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXksIGZhY2Vib29rSWQpO1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBmYWNlYm9vayBpZDogXCIgKyBmYWNlYm9va0lkKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRHZW5kZXIoZ2VuZGVyOkVHQUdlbmRlcik6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nZW5kZXIgPSBFR0FHZW5kZXJbZ2VuZGVyXS50b1N0cmluZygpLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXksIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyKTtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgZ2VuZGVyOiBcIiArIEdBU3RhdGUuaW5zdGFuY2UuZ2VuZGVyKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRCaXJ0aFllYXIoYmlydGhZZWFyOm51bWJlcik6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5iaXJ0aFllYXIgPSBiaXJ0aFllYXI7XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXksIGJpcnRoWWVhci50b1N0cmluZygpKTtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYmlydGggeWVhcjogXCIgKyBiaXJ0aFllYXIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFNlc3Npb25OdW0oKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKSArIDE7XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW0gPSBzZXNzaW9uTnVtSW50O1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIHRyYW5zYWN0aW9uTnVtSW50Om51bWJlciA9IEdBU3RhdGUuZ2V0VHJhbnNhY3Rpb25OdW0oKSArIDE7XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnRyYW5zYWN0aW9uTnVtID0gdHJhbnNhY3Rpb25OdW1JbnQ7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbjpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciB0cmllczpudW1iZXIgPSBHQVN0YXRlLmdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb24pICsgMTtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl0gPSB0cmllcztcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBQZXJzaXN0XHJcbiAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcclxuICAgICAgICAgICAgICAgIHZhbHVlc1tcInByb2dyZXNzaW9uXCJdID0gcHJvZ3Jlc3Npb247XHJcbiAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0cmllc1wiXSA9IHRyaWVzO1xyXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuUHJvZ3Jlc3Npb24sIHZhbHVlcywgdHJ1ZSwgXCJwcm9ncmVzc2lvblwiKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IG51bWJlclxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihwcm9ncmVzc2lvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXMpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIDA7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIERlbGV0ZVxyXG4gICAgICAgICAgICAgICAgdmFyIHBhcm1zOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xyXG4gICAgICAgICAgICAgICAgcGFybXMucHVzaChbXCJwcm9ncmVzc2lvblwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgcHJvZ3Jlc3Npb25dKTtcclxuICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlByb2dyZXNzaW9uLCBwYXJtcyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0S2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZUtleSA9IGdhbWVLZXk7XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQgPSBnYW1lU2VjcmV0O1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nID0gZmxhZztcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgbWFudWFsIHNlc3Npb24gaGFuZGxpbmc6IFwiICsgZmxhZyk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0RXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBhbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXHJcblxyXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXHJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xyXG4gICAgICAgICAgICAgICAgLy8gVXNlciBpZGVudGlmaWVyXHJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInVzZXJfaWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQ2xpZW50IFRpbWVzdGFtcCAodGhlIGFkanVzdGVkIHRpbWVzdGFtcClcclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY2xpZW50X3RzXCJdID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XHJcbiAgICAgICAgICAgICAgICAvLyBTREsgdmVyc2lvblxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xyXG4gICAgICAgICAgICAgICAgLy8gT3BlcmF0aW9uIHN5c3RlbSB2ZXJzaW9uXHJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XHJcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJtYW51ZmFjdHVyZXJcIl0gPSBHQURldmljZS5kZXZpY2VNYW51ZmFjdHVyZXI7XHJcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgdmVyc2lvblxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcclxuICAgICAgICAgICAgICAgIC8vIEJyb3dzZXIgdmVyc2lvblxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJicm93c2VyX3ZlcnNpb25cIl0gPSBHQURldmljZS5icm93c2VyVmVyc2lvbjtcclxuICAgICAgICAgICAgICAgIC8vIFBsYXRmb3JtIChvcGVyYXRpbmcgc3lzdGVtKVxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XHJcbiAgICAgICAgICAgICAgICAvLyBTZXNzaW9uIGlkZW50aWZpZXJcclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2Vzc2lvbl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xyXG4gICAgICAgICAgICAgICAgLy8gU2Vzc2lvbiBudW1iZXJcclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW0dBU3RhdGUuU2Vzc2lvbk51bUtleV0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW07XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdHlwZSBvZiBjb25uZWN0aW9uIHRoZSB1c2VyIGlzIGN1cnJlbnRseSBvbiAoYWRkIGlmIHZhbGlkKVxyXG4gICAgICAgICAgICAgICAgdmFyIGNvbm5lY3Rpb25fdHlwZTpzdHJpbmcgPSBHQURldmljZS5nZXRDb25uZWN0aW9uVHlwZSgpO1xyXG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbm5lY3Rpb25fdHlwZVwiXSA9IGNvbm5lY3Rpb25fdHlwZTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZiAoR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24pXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJlbmdpbmVfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIC0tLS0gQ09ORElUSU9OQUwgLS0tLSAvL1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFwcCBidWlsZCB2ZXJzaW9uICh1c2UgaWYgbm90IG5pbClcclxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmJ1aWxkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYnVpbGRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLmJ1aWxkO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIC0tLS0gT1BUSU9OQUwgY3Jvc3Mtc2Vzc2lvbiAtLS0tIC8vXHJcblxyXG4gICAgICAgICAgICAgICAgLy8gZmFjZWJvb2sgaWQgKG9wdGlvbmFsKVxyXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuZmFjZWJvb2tJZClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkZhY2Vib29rSWRLZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5mYWNlYm9va0lkO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgLy8gZ2VuZGVyIChvcHRpb25hbClcclxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmluc3RhbmNlLmdlbmRlcilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tHQVN0YXRlLkdlbmRlcktleV0gPSBHQVN0YXRlLmluc3RhbmNlLmdlbmRlcjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIC8vIGJpcnRoX3llYXIgKG9wdGlvbmFsKVxyXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYmlydGhZZWFyICE9IDApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbR0FTdGF0ZS5CaXJ0aFllYXJLZXldID0gR0FTdGF0ZS5pbnN0YW5jZS5iaXJ0aFllYXI7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGFubm90YXRpb25zO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpOiB7W2tleTpzdHJpbmddOiBhbnl9XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBhbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXHJcblxyXG4gICAgICAgICAgICAgICAgLy8gY29sbGVjdG9yIGV2ZW50IEFQSSB2ZXJzaW9uXHJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIENhdGVnb3J5XHJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xyXG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcclxuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxyXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJvc192ZXJzaW9uXCJdID0gR0FEZXZpY2Uub3NWZXJzaW9uO1xyXG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIG1ha2UgKGhhcmRjb2RlZCB0byBhcHBsZSlcclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xyXG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIHZlcnNpb25cclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZGV2aWNlXCJdID0gR0FEZXZpY2UuZGV2aWNlTW9kZWw7XHJcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wicGxhdGZvcm1cIl0gPSBHQURldmljZS5idWlsZFBsYXRmb3JtO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcclxuICAgICAgICAgICAgICAgIHZhciBjb25uZWN0aW9uX3R5cGU6c3RyaW5nID0gR0FEZXZpY2UuZ2V0Q29ubmVjdGlvblR5cGUoKTtcclxuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25fdHlwZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjb25uZWN0aW9uX3R5cGVcIl0gPSBjb25uZWN0aW9uX3R5cGU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGluaXRBbm5vdGF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cclxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcInNka192ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk7XHJcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cclxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gUGxhdGZvcm0gKG9wZXJhdGluZyBzeXN0ZW0pXHJcbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGluaXRBbm5vdGF0aW9ucztcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnRUc0FkanVzdGVkKCk6IG51bWJlclxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XHJcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHNBZGp1c3RlZEludGVnZXI6bnVtYmVyID0gY2xpZW50VHMgKyBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQ7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoR0FWYWxpZGF0b3IudmFsaWRhdGVDbGllbnRUcyhjbGllbnRUc0FkanVzdGVkSW50ZWdlcikpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUcztcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXNzaW9uSXNTdGFydGVkKCk6IGJvb2xlYW5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvblN0YXJ0ICE9IDA7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNhY2hlSWRlbnRpZmllcigpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UudXNlcklkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UudXNlcklkO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZSBpZihHQVN0YXRlLmluc3RhbmNlLmRlZmF1bHRVc2VySWQpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyID0gR0FTdGF0ZS5pbnN0YW5jZS5kZWZhdWx0VXNlcklkO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJpZGVudGlmaWVyLCB7Y2xlYW46XCIgKyBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXIgKyBcIn1cIik7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5zdXJlUGVyc2lzdGVkU3RhdGVzKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gZ2V0IGFuZCBleHRyYWN0IHN0b3JlZCBzdGF0ZXNcclxuICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5sb2FkKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGludG8gR0FTdGF0ZSBpbnN0YW5jZVxyXG4gICAgICAgICAgICAgICAgdmFyIGluc3RhbmNlOkdBU3RhdGUgPSBHQVN0YXRlLmluc3RhbmNlO1xyXG5cclxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNldERlZmF1bHRJZChHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgOiBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCkpO1xyXG5cclxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNlc3Npb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5TZXNzaW9uTnVtS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXkpKSA6IDAuMDtcclxuXHJcbiAgICAgICAgICAgICAgICBpbnN0YW5jZS50cmFuc2FjdGlvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5KSAhPSBudWxsID8gTnVtYmVyKEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5KSkgOiAwLjA7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBjcm9zcyBzZXNzaW9uIHVzZXIgdmFsdWVzXHJcbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5mYWNlYm9va0lkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkZhY2Vib29rSWRLZXksIGluc3RhbmNlLmZhY2Vib29rSWQpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmZhY2Vib29rSWQgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5GYWNlYm9va0lkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRmFjZWJvb2tJZEtleSkgOiBcIlwiO1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmZhY2Vib29rSWQpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZmFjZWJvb2tpZCBmb3VuZCBpbiBEQjogXCIgKyBpbnN0YW5jZS5mYWNlYm9va0lkKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuZ2VuZGVyKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkdlbmRlcktleSwgaW5zdGFuY2UuZ2VuZGVyKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5nZW5kZXIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5HZW5kZXJLZXkpIDogXCJcIjtcclxuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5nZW5kZXIpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZ2VuZGVyIGZvdW5kIGluIERCOiBcIiArIGluc3RhbmNlLmdlbmRlcik7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmJpcnRoWWVhciAmJiBpbnN0YW5jZS5iaXJ0aFllYXIgIT0gMClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXksIGluc3RhbmNlLmJpcnRoWWVhci50b1N0cmluZygpKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5iaXJ0aFllYXIgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5CaXJ0aFllYXJLZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuQmlydGhZZWFyS2V5KSkgOiAwO1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmJpcnRoWWVhciAhPSAwKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImJpcnRoWWVhciBmb3VuZCBpbiBEQjogXCIgKyBpbnN0YW5jZS5iaXJ0aFllYXIpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyByZXN0b3JlIGRpbWVuc2lvbiBzZXR0aW5nc1xyXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAxS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAxS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpIDogXCJcIjtcclxuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDEgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpIDogXCJcIjtcclxuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDIgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDNLZXkpIDogXCJcIjtcclxuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDMgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gZ2V0IGNhY2hlZCBpbml0IGNhbGwgdmFsdWVzXHJcbiAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkU3RyaW5nOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgOiBcIlwiO1xyXG4gICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZFN0cmluZylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxyXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZGtDb25maWdDYWNoZWQgPSBKU09OLnBhcnNlKEdBVXRpbGl0aWVzLmRlY29kZTY0KHNka0NvbmZpZ0NhY2hlZFN0cmluZykpO1xyXG4gICAgICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWQpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5zZGtDb25maWdDYWNoZWQgPSBzZGtDb25maWdDYWNoZWQ7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIHZhciByZXN1bHRzX2dhX3Byb2dyZXNzaW9uOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuUHJvZ3Jlc3Npb24pO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmIChyZXN1bHRzX2dhX3Byb2dyZXNzaW9uKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcmVzdWx0c19nYV9wcm9ncmVzc2lvbi5sZW5ndGg7ICsraSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6e1trZXk6c3RyaW5nXTogYW55fSA9IHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb25baV07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyZXN1bHQpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcmVzdWx0W1wicHJvZ3Jlc3Npb25cIl0gYXMgc3RyaW5nXSA9IHJlc3VsdFtcInRyaWVzXCJdIGFzIG51bWJlcjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzOm51bWJlcik6IG51bWJlclxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHM6bnVtYmVyID0gR0FVdGlsaXRpZXMudGltZUludGVydmFsU2luY2UxOTcwKCk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gc2VydmVyVHMgLSBjbGllbnRUcztcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMSBub3QgaW4gbGlzdFxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAxKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAxIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSk7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMShcIlwiKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDIgbm90IGluIGxpc3RcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMigpKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMiBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCkpO1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoXCJcIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAzIG5vdCBpbiBsaXN0XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDMgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKTtcclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKFwiXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG59XHJcbiIsIm1vZHVsZSBnYVxyXG57XHJcbiAgICBleHBvcnQgbW9kdWxlIHRhc2tzXHJcbiAgICB7XHJcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhLmh0dHAuRUdBU2RrRXJyb3JUeXBlO1xyXG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhLnV0aWxpdGllcy5HQVV0aWxpdGllcztcclxuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYS5sb2dnaW5nLkdBTG9nZ2VyO1xyXG5cclxuICAgICAgICBleHBvcnQgY2xhc3MgU2RrRXJyb3JUYXNrXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhDb3VudDpudW1iZXIgPSAxMDtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgY291bnRNYXA6e1trZXk6bnVtYmVyXTogbnVtYmVyfSA9IHt9O1xyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBleGVjdXRlKHVybDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlLCBwYXlsb2FkRGF0YTpzdHJpbmcsIHNlY3JldEtleTpzdHJpbmcpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0pXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gMDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZihTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPj0gU2RrRXJyb3JUYXNrLk1heENvdW50KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIHZhciBoYXNoSG1hYzpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKHNlY3JldEtleSwgcGF5bG9hZERhdGEpO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XHJcblxyXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXJlcXVlc3QucmVzcG9uc2VUZXh0KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwic2RrIGVycm9yIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgcmVxdWVzdC5zdGF0dXNUZXh0ICsgXCIsIFN0YXR1cyBjb2RlOiBcIiArIHJlcXVlc3Quc3RhdHVzKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5zdGF0dXMgIT0gMjAwKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwic2RrIGVycm9yIGZhaWxlZC4gcmVzcG9uc2UgY29kZSBub3QgMjAwLiBzdGF0dXMgY29kZTogXCIgKyByZXF1ZXN0LnN0YXR1cyArIFwiLCBkZXNjcmlwdGlvbjogXCIgKyByZXF1ZXN0LnN0YXR1c1RleHQgKyBcIiwgYm9keTogXCIgKyByZXF1ZXN0LnJlc3BvbnNlVGV4dCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gPSBTZGtFcnJvclRhc2suY291bnRNYXBbdHlwZV0gKyAxO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfTtcclxuXHJcbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XHJcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LVR5cGVcIiwgXCJhcHBsaWNhdGlvbi9qc29uXCIpO1xyXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQXV0aG9yaXphdGlvblwiLCBoYXNoSG1hYyk7XHJcblxyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5zZW5kKHBheWxvYWREYXRhKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iLCJtb2R1bGUgZ2Fcclxue1xyXG4gICAgZXhwb3J0IG1vZHVsZSBodHRwXHJcbiAgICB7XHJcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYS5zdGF0ZS5HQVN0YXRlO1xyXG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhLmxvZ2dpbmcuR0FMb2dnZXI7XHJcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2EudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xyXG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2Euc3RvcmUuR0FTdG9yZTtcclxuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYS52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xyXG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xyXG4gICAgICAgIGltcG9ydCBTZGtFcnJvclRhc2sgPSBnYS50YXNrcy5TZGtFcnJvclRhc2s7XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUhUVFBBcGlcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xyXG4gICAgICAgICAgICBwcml2YXRlIHByb3RvY29sOnN0cmluZztcclxuICAgICAgICAgICAgcHJpdmF0ZSBob3N0TmFtZTpzdHJpbmc7XHJcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XHJcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XHJcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZVVybFBhdGg6c3RyaW5nO1xyXG4gICAgICAgICAgICBwcml2YXRlIGV2ZW50c1VybFBhdGg6c3RyaW5nO1xyXG4gICAgICAgICAgICBwcml2YXRlIHVzZUd6aXA6Ym9vbGVhbjtcclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBiYXNlIHVybCBzZXR0aW5nc1xyXG4gICAgICAgICAgICAgICAgdGhpcy5wcm90b2NvbCA9IFwiaHR0cHNcIjtcclxuICAgICAgICAgICAgICAgIHRoaXMuaG9zdE5hbWUgPSBcImFwaS5nYW1lYW5hbHl0aWNzLmNvbVwiO1xyXG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gXCJ2MlwiO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIGNyZWF0ZSBiYXNlIHVybFxyXG4gICAgICAgICAgICAgICAgdGhpcy5iYXNlVXJsID0gdGhpcy5wcm90b2NvbCArIFwiOi8vXCIgKyB0aGlzLmhvc3ROYW1lICsgXCIvXCIgKyB0aGlzLnZlcnNpb247XHJcblxyXG4gICAgICAgICAgICAgICAgdGhpcy5pbml0aWFsaXplVXJsUGF0aCA9IFwiaW5pdFwiO1xyXG4gICAgICAgICAgICAgICAgdGhpcy5ldmVudHNVcmxQYXRoID0gXCJldmVudHNcIjtcclxuXHJcbiAgICAgICAgICAgICAgICB0aGlzLnVzZUd6aXAgPSBmYWxzZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHJlcXVlc3RJbml0KGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSkgPT4gdm9pZCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXHJcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5pbml0aWFsaXplVXJsUGF0aDtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdpbml0JyBVUkw6IFwiICsgdXJsKTtcclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldEluaXRBbm5vdGF0aW9ucygpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXHJcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShpbml0QW5ub3RhdGlvbnMpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZyA9IHRoaXMuY3JlYXRlUGF5bG9hZERhdGEoSlNPTnN0cmluZywgdGhpcy51c2VHemlwKTtcclxuICAgICAgICAgICAgICAgIHZhciBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xyXG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XHJcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5pbml0UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzZW5kRXZlbnRzSW5BcnJheShldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+LCByZXF1ZXN0SWQ6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihldmVudEFycmF5Lmxlbmd0aCA9PSAwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBjYWxsZWQgd2l0aCBtaXNzaW5nIGV2ZW50QXJyYXlcIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIGdhbWVLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lS2V5KCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXHJcbiAgICAgICAgICAgICAgICB2YXIgdXJsOnN0cmluZyA9IHRoaXMuYmFzZVVybCArIFwiL1wiICsgZ2FtZUtleSArIFwiL1wiICsgdGhpcy5ldmVudHNVcmxQYXRoO1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gbWFrZSBKU09OIHN0cmluZyBmcm9tIGRhdGFcclxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGV2ZW50QXJyYXkpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKCFKU09Oc3RyaW5nKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBKU09OIGVuY29kaW5nIGZhaWxlZCBvZiBldmVudEFycmF5XCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50QXJyYXkubGVuZ3RoKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhID0gdGhpcy5jcmVhdGVQYXlsb2FkRGF0YShKU09Oc3RyaW5nLCB0aGlzLnVzZUd6aXApO1xyXG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XHJcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChKU09Oc3RyaW5nKTtcclxuICAgICAgICAgICAgICAgIGV4dHJhQXJncy5wdXNoKHJlcXVlc3RJZCk7XHJcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChldmVudEFycmF5Lmxlbmd0aC50b1N0cmluZygpKTtcclxuICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5zZW5kUmVxdWVzdCh1cmwsIHBheWxvYWREYXRhLCBleHRyYUFyZ3MsIHRoaXMudXNlR3ppcCwgR0FIVFRQQXBpLnNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2ssIGNhbGxiYWNrKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHNlbmRTZGtFcnJvckV2ZW50KHR5cGU6RUdBU2RrRXJyb3JUeXBlKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcclxuICAgICAgICAgICAgICAgIHZhciBzZWNyZXRLZXk6c3RyaW5nID0gR0FTdGF0ZS5nZXRHYW1lU2VjcmV0KCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTZGtFcnJvckV2ZW50KGdhbWVLZXksIHNlY3JldEtleSwgdHlwZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxyXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdldmVudHMnIFVSTDogXCIgKyB1cmwpO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkSlNPTlN0cmluZzpzdHJpbmcgPSBcIlwiO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciBqc29uOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciB0eXBlU3RyaW5nOnN0cmluZyA9IEdBSFRUUEFwaS5zZGtFcnJvclR5cGVUb1N0cmluZyh0eXBlKTtcclxuICAgICAgICAgICAgICAgIGpzb25bXCJ0eXBlXCJdID0gdHlwZVN0cmluZztcclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xyXG4gICAgICAgICAgICAgICAgZXZlbnRBcnJheS5wdXNoKGpzb24pO1xyXG4gICAgICAgICAgICAgICAgcGF5bG9hZEpTT05TdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldmVudEFycmF5KTtcclxuXHJcbiAgICAgICAgICAgICAgICBpZighcGF5bG9hZEpTT05TdHJpbmcpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInNlbmRTZGtFcnJvckV2ZW50OiBKU09OIGVuY29kaW5nIGZhaWxlZC5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kU2RrRXJyb3JFdmVudCBqc29uOiBcIiArIHBheWxvYWRKU09OU3RyaW5nKTtcclxuICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5leGVjdXRlKHVybCwgdHlwZSwgcGF5bG9hZEpTT05TdHJpbmcsIHNlY3JldEtleSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRFdmVudEluQXJyYXlSZXF1ZXN0Q2FsbGJhY2socmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPiA9IG51bGwpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IGV4dHJhWzBdO1xyXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gZXh0cmFbMV07XHJcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdElkOnN0cmluZyA9IGV4dHJhWzJdO1xyXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50Q291bnQ6bnVtYmVyID0gcGFyc2VJbnQoZXh0cmFbM10pO1xyXG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcclxuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcclxuXHJcbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XHJcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcclxuXHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiZXZlbnRzIHJlcXVlc3QgY29udGVudDogXCIgKyBib2R5KTtcclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJFdmVudHNcIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gaWYgbm90IDIwMCByZXN1bHRcclxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBldmVudHMgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcclxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxyXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RKc29uRGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0gYm9keSA/IEpTT04ucGFyc2UoYm9keSkgOiB7fTtcclxuXHJcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkRlY29kZUZhaWxlZCwgbnVsbCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XHJcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtID09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgRXZlbnRzIENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyByZXR1cm4gcmVzcG9uc2VcclxuICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIHJlcXVlc3RKc29uRGljdCwgcmVxdWVzdElkLCBldmVudENvdW50KTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc2VuZFJlcXVlc3QodXJsOnN0cmluZywgcGF5bG9hZERhdGE6c3RyaW5nLCBleHRyYUFyZ3M6QXJyYXk8c3RyaW5nPiwgZ3ppcDpib29sZWFuLCBjYWxsYmFjazoocmVxdWVzdDpYTUxIdHRwUmVxdWVzdCwgdXJsOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCwgZXh0cmE6QXJyYXk8c3RyaW5nPikgPT4gdm9pZCwgY2FsbGJhY2syOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gY3JlYXRlIGF1dGhvcml6YXRpb24gaGFzaFxyXG4gICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKTtcclxuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoa2V5LCBwYXlsb2FkRGF0YSk7XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xyXG4gICAgICAgICAgICAgICAgYXJncy5wdXNoKGF1dGhvcml6YXRpb24pO1xyXG5cclxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBleHRyYUFyZ3MpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYXJncy5wdXNoKGV4dHJhQXJnc1tzXSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdCwgdXJsLCBjYWxsYmFjazIsIGFyZ3MpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH07XHJcblxyXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vcGVuKFwiUE9TVFwiLCB1cmwsIHRydWUpO1xyXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwiYXBwbGljYXRpb24vanNvblwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGF1dGhvcml6YXRpb24pO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKGd6aXApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIC8vcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1FbmNvZGluZ1wiLCBcImd6aXBcIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5zZW5kKHBheWxvYWREYXRhKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlLnN0YWNrKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0pID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4gPSBudWxsKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcclxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IGV4dHJhWzFdO1xyXG4gICAgICAgICAgICAgICAgdmFyIGJvZHk6c3RyaW5nID0gXCJcIjtcclxuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcclxuXHJcbiAgICAgICAgICAgICAgICBib2R5ID0gcmVxdWVzdC5yZXNwb25zZVRleHQ7XHJcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBwcm9jZXNzIHRoZSByZXNwb25zZVxyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImluaXQgcmVxdWVzdCBjb250ZW50IDogXCIgKyBib2R5KTtcclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdEpzb25EaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSBib2R5ID8gSlNPTi5wYXJzZShib2R5KSA6IHt9O1xyXG4gICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RSZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlID0gR0FIVFRQQXBpLmluc3RhbmNlLnByb2Nlc3NSZXF1ZXN0UmVzcG9uc2UocmVzcG9uc2VDb2RlLCByZXF1ZXN0LnN0YXR1c1RleHQsIGJvZHksIFwiSW5pdFwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBpZiBub3QgMjAwIHJlc3VsdFxyXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gVVJMOiBcIiArIHVybCArIFwiLCBBdXRob3JpemF0aW9uOiBcIiArIGF1dGhvcml6YXRpb24gKyBcIiwgSlNPTlN0cmluZzogXCIgKyBKU09Oc3RyaW5nKTtcclxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdEpzb25EaWN0ID09IG51bGwpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIEpzb24gZGVjb2RpbmcgZmFpbGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XHJcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRmFpbGVkIEluaXQgQ2FsbC4gQmFkIHJlcXVlc3QuIFJlc3BvbnNlOiBcIiArIEpTT04uc3RyaW5naWZ5KHJlcXVlc3RKc29uRGljdCkpO1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIHJldHVybiBiYWQgcmVxdWVzdCByZXN1bHRcclxuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgSW5pdCBjYWxsIHZhbHVlc1xyXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRlZEluaXRWYWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlQW5kQ2xlYW5Jbml0UmVxdWVzdFJlc3BvbnNlKHJlcXVlc3RKc29uRGljdCk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoIXZhbGlkYXRlZEluaXRWYWx1ZXMpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2soRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlc3BvbnNlLCBudWxsKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gYWxsIG9rXHJcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuT2ssIHZhbGlkYXRlZEluaXRWYWx1ZXMpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIGNyZWF0ZVBheWxvYWREYXRhKHBheWxvYWQ6c3RyaW5nLCBnemlwOmJvb2xlYW4pOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIHBheWxvYWREYXRhOnN0cmluZztcclxuXHJcbiAgICAgICAgICAgICAgICBpZihnemlwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIHBheWxvYWREYXRhID0gR0FVdGlsaXRpZXMuR3ppcENvbXByZXNzKHBheWxvYWQpO1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIEdBTG9nZ2VyLkQoXCJHemlwIHN0YXRzLiBTaXplOiBcIiArIEVuY29kaW5nLlVURjguR2V0Qnl0ZXMocGF5bG9hZCkuTGVuZ3RoICsgXCIsIENvbXByZXNzZWQ6IFwiICsgcGF5bG9hZERhdGEuTGVuZ3RoICsgXCIsIENvbnRlbnQ6IFwiICsgcGF5bG9hZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZ3ppcCBub3Qgc3VwcG9ydGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHBheWxvYWREYXRhID0gcGF5bG9hZDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gcGF5bG9hZERhdGE7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgcHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGU6bnVtYmVyLCByZXNwb25zZU1lc3NhZ2U6c3RyaW5nLCBib2R5OnN0cmluZywgcmVxdWVzdElkOnN0cmluZyk6IEVHQUhUVFBBcGlSZXNwb25zZVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBpZiBubyByZXN1bHQgLSBvZnRlbiBubyBjb25uZWN0aW9uXHJcbiAgICAgICAgICAgICAgICBpZighYm9keSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIGZhaWxlZC4gTWlnaHQgYmUgbm8gY29ubmVjdGlvbi4gRGVzY3JpcHRpb246IFwiICsgcmVzcG9uc2VNZXNzYWdlICsgXCIsIFN0YXR1cyBjb2RlOiBcIiArIHJlc3BvbnNlQ29kZSk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIG9rXHJcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSAyMDApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5PaztcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyA0MDEgY2FuIHJldHVybiAwIHN0YXR1c1xyXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMCB8fCByZXNwb25zZUNvZGUgPT09IDQwMSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDQwMSAtIFVuYXV0aG9yaXplZC5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQ7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNDAwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAwIC0gQmFkIFJlcXVlc3QuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSA1MDApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA1MDAgLSBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3IuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuSW50ZXJuYWxTZXJ2ZXJFcnJvcjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLlVua25vd25SZXNwb25zZUNvZGU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNka0Vycm9yVHlwZVRvU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yVHlwZSk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBzd2l0Y2godmFsdWUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQ6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlamVjdGVkXCI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH1cclxufVxyXG4iLCJtb2R1bGUgZ2Fcclxue1xyXG4gICAgZXhwb3J0IG1vZHVsZSBldmVudHNcclxuICAgIHtcclxuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhLnN0b3JlLkdBU3RvcmU7XHJcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2Euc3RvcmUuRUdBU3RvcmU7XHJcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2Euc3RvcmUuRUdBU3RvcmVBcmdzT3BlcmF0b3I7XHJcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYS5zdGF0ZS5HQVN0YXRlO1xyXG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhLmxvZ2dpbmcuR0FMb2dnZXI7XHJcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2EudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xyXG4gICAgICAgIGltcG9ydCBFR0FIVFRQQXBpUmVzcG9uc2UgPSBnYS5odHRwLkVHQUhUVFBBcGlSZXNwb25zZTtcclxuICAgICAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2EuaHR0cC5HQUhUVFBBcGk7XHJcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2EudmFsaWRhdG9ycy5HQVZhbGlkYXRvcjtcclxuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JUeXBlID0gZ2EuaHR0cC5FR0FTZGtFcnJvclR5cGU7XHJcblxyXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQUV2ZW50c1xyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FFdmVudHMgPSBuZXcgR0FFdmVudHMoKTtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uU3RhcnQ6c3RyaW5nID0gXCJ1c2VyXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2Vzc2lvbkVuZDpzdHJpbmcgPSBcInNlc3Npb25fZW5kXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RGVzaWduOnN0cmluZyA9IFwiZGVzaWduXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5QnVzaW5lc3M6c3RyaW5nID0gXCJidXNpbmVzc1wiO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVByb2dyZXNzaW9uOnN0cmluZyA9IFwicHJvZ3Jlc3Npb25cIjtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlSZXNvdXJjZTpzdHJpbmcgPSBcInJlc291cmNlXCI7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RXJyb3I6c3RyaW5nID0gXCJlcnJvclwiO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhFdmVudENvdW50Om51bWJlciA9IDUwMDtcclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxyXG4gICAgICAgICAgICB7XHJcblxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25TdGFydEV2ZW50KCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgc3BlY2lmaWMgZGF0YVxyXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0O1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBzZXNzaW9uIG51bWJlciAgYW5kIHBlcnNpc3RcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50U2Vzc2lvbk51bSgpO1xyXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuU2Vzc2lvbk51bUtleSwgR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkudG9TdHJpbmcoKSk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gTG9nXHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFNFU1NJT04gU1RBUlQgZXZlbnRcIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU2VuZCBldmVudCByaWdodCBhd2F5XHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKEdBRXZlbnRzLkNhdGVnb3J5U2Vzc2lvblN0YXJ0LCBmYWxzZSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkU2Vzc2lvbkVuZEV2ZW50KCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25fc3RhcnRfdHM6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcclxuICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XHJcbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkxlbmd0aDpudW1iZXIgPSBjbGllbnRfdHNfYWRqdXN0ZWQgLSBzZXNzaW9uX3N0YXJ0X3RzO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKHNlc3Npb25MZW5ndGggPCAwKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIFNob3VsZCBuZXZlciBoYXBwZW4uXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQ291bGQgYmUgYmVjYXVzZSBvZiBlZGdlIGNhc2VzIHJlZ2FyZGluZyB0aW1lIGFsdGVyaW5nIG9uIGRldmljZS5cclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU2Vzc2lvbiBsZW5ndGggd2FzIGNhbGN1bGF0ZWQgdG8gYmUgbGVzcyB0aGVuIDAuIFNob3VsZCBub3QgYmUgcG9zc2libGUuIFJlc2V0dGluZyB0byAwLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uTGVuZ3RoID0gMDtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXHJcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcclxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xyXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wibGVuZ3RoXCJdID0gc2Vzc2lvbkxlbmd0aDtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcclxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBMb2dcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBFTkQgZXZlbnQuXCIpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIFNlbmQgYWxsIGV2ZW50IHJpZ2h0IGF3YXlcclxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoXCJcIiwgZmFsc2UpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGNhcnRUeXBlOnN0cmluZyA9IG51bGwpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUJ1c2luZXNzRXZlbnQoY3VycmVuY3ksIGFtb3VudCwgY2FydFR5cGUsIGl0ZW1UeXBlLCBpdGVtSWQpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXHJcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgdHJhbnNhY3Rpb24gbnVtYmVyIGFuZCBwZXJzaXN0XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFRyYW5zYWN0aW9uTnVtKCk7XHJcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSwgR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpLnRvU3RyaW5nKCkpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIFJlcXVpcmVkXHJcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XHJcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5QnVzaW5lc3M7XHJcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjdXJyZW5jeVwiXSA9IGN1cnJlbmN5O1xyXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xyXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W0dBU3RhdGUuVHJhbnNhY3Rpb25OdW1LZXldID0gR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsXHJcbiAgICAgICAgICAgICAgICBpZiAoY2FydFR5cGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2FydF90eXBlXCJdID0gY2FydFR5cGU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIExvZ1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBCVVNJTkVTUyBldmVudDoge2N1cnJlbmN5OlwiICsgY3VycmVuY3kgKyBcIiwgYW1vdW50OlwiICsgYW1vdW50ICsgXCIsIGl0ZW1UeXBlOlwiICsgaXRlbVR5cGUgKyBcIiwgaXRlbUlkOlwiICsgaXRlbUlkICsgXCIsIGNhcnRUeXBlOlwiICsgY2FydFR5cGUgKyBcIn1cIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZTpFR0FSZXNvdXJjZUZsb3dUeXBlLCBjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGl0ZW1UeXBlOnN0cmluZywgaXRlbUlkOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCwgR0FTdGF0ZS5nZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcygpKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gSWYgZmxvdyB0eXBlIGlzIHNpbmsgcmV2ZXJzZSBhbW91bnRcclxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGFtb3VudCAqPSAtMTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXHJcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBpbnNlcnQgZXZlbnQgc3BlY2lmaWMgdmFsdWVzXHJcbiAgICAgICAgICAgICAgICB2YXIgZmxvd1R5cGVTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKGZsb3dUeXBlKTtcclxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gZmxvd1R5cGVTdHJpbmcgKyBcIjpcIiArIGN1cnJlbmN5ICsgXCI6XCIgKyBpdGVtVHlwZSArIFwiOlwiICsgaXRlbUlkO1xyXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVJlc291cmNlO1xyXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBMb2dcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUkVTT1VSQ0UgZXZlbnQ6IHtjdXJyZW5jeTpcIiArIGN1cnJlbmN5ICsgXCIsIGFtb3VudDpcIiArIGFtb3VudCArIFwiLCBpdGVtVHlwZTpcIiArIGl0ZW1UeXBlICsgXCIsIGl0ZW1JZDpcIiArIGl0ZW1JZCArIFwifVwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxOnN0cmluZywgcHJvZ3Jlc3Npb24wMjpzdHJpbmcsIHByb2dyZXNzaW9uMDM6c3RyaW5nLCBzY29yZTpudW1iZXIsIHNlbmRTY29yZTpib29sZWFuKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyhwcm9ncmVzc2lvblN0YXR1cyk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGUgZXZlbnQgcGFyYW1zXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMykpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcclxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIFByb2dyZXNzaW9uIGlkZW50aWZpZXJcclxuICAgICAgICAgICAgICAgIHZhciBwcm9ncmVzc2lvbklkZW50aWZpZXI6c3RyaW5nO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmICghcHJvZ3Jlc3Npb24wMilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDMpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBwcm9ncmVzc2lvbklkZW50aWZpZXIgPSBwcm9ncmVzc2lvbjAxICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAyICsgXCI6XCIgKyBwcm9ncmVzc2lvbjAzO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcclxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlQcm9ncmVzc2lvbjtcclxuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIjpcIiArIHByb2dyZXNzaW9uSWRlbnRpZmllcjtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBBdHRlbXB0XHJcbiAgICAgICAgICAgICAgICB2YXIgYXR0ZW1wdF9udW06bnVtYmVyID0gMDtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBBZGQgc2NvcmUgaWYgc3BlY2lmaWVkIGFuZCBzdGF0dXMgaXMgbm90IHN0YXJ0XHJcbiAgICAgICAgICAgICAgICBpZiAoc2VuZFNjb3JlICYmIHByb2dyZXNzaW9uU3RhdHVzICE9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0KVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcInNjb3JlXCJdID0gc2NvcmU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQ291bnQgYXR0ZW1wdHMgb24gZWFjaCBwcm9ncmVzc2lvbiBmYWlsIGFuZCBwZXJzaXN0XHJcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWwpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gaW5jcmVtZW50IGFuZCBhZGQgYXR0ZW1wdF9udW0gb24gY29tcGxldGUgYW5kIGRlbGV0ZSBwZXJzaXN0ZWRcclxuICAgICAgICAgICAgICAgIGlmIChwcm9ncmVzc2lvblN0YXR1cyA9PT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuQ29tcGxldGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBldmVudFxyXG4gICAgICAgICAgICAgICAgICAgIGF0dGVtcHRfbnVtID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XHJcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYXR0ZW1wdF9udW1cIl0gPSBhdHRlbXB0X251bTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYXJcclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmNsZWFyUHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBMb2dcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgUFJPR1JFU1NJT04gZXZlbnQ6IHtzdGF0dXM6XCIgKyBwcm9ncmVzc2lvblN0YXR1c1N0cmluZyArIFwiLCBwcm9ncmVzc2lvbjAxOlwiICsgcHJvZ3Jlc3Npb24wMSArIFwiLCBwcm9ncmVzc2lvbjAyOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiLCBwcm9ncmVzc2lvbjAzOlwiICsgcHJvZ3Jlc3Npb24wMyArIFwiLCBzY29yZTpcIiArIHNjb3JlICsgXCIsIGF0dGVtcHQ6XCIgKyBhdHRlbXB0X251bSArIFwifVwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGREZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyLCBzZW5kVmFsdWU6Ym9vbGVhbik6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkLCB2YWx1ZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcclxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIEFwcGVuZCBldmVudCBzcGVjaWZpY3NcclxuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlEZXNpZ247XHJcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJldmVudF9pZFwiXSA9IGV2ZW50SWQ7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoc2VuZFZhbHVlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcInZhbHVlXCJdID0gdmFsdWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gTG9nXHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIERFU0lHTiBldmVudDoge2V2ZW50SWQ6XCIgKyBldmVudElkICsgXCIsIHZhbHVlOlwiICsgdmFsdWUgKyBcIn1cIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRXJyb3JFdmVudChzZXZlcml0eTpFR0FFcnJvclNldmVyaXR5LCBtZXNzYWdlOnN0cmluZyk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdmFyIHNldmVyaXR5U3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmVycm9yU2V2ZXJpdHlUb1N0cmluZyhzZXZlcml0eSk7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxyXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xyXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUVycm9yO1xyXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wic2V2ZXJpdHlcIl0gPSBzZXZlcml0eVN0cmluZztcclxuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcIm1lc3NhZ2VcIl0gPSBtZXNzYWdlO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIExvZ1xyXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBFUlJPUiBldmVudDoge3NldmVyaXR5OlwiICsgc2V2ZXJpdHlTdHJpbmcgKyBcIiwgbWVzc2FnZTpcIiArIG1lc3NhZ2UgKyBcIn1cIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YSk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcHJvY2Vzc0V2ZW50cyhjYXRlZ29yeTpzdHJpbmcsIHBlcmZvcm1DbGVhblVwOmJvb2xlYW4pOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIC8vIHRocm93IG5ldyBFcnJvcihcInByb2Nlc3NFdmVudHMgbm90IGltcGxlbWVudGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIHJlcXVlc3RJZGVudGlmaWVyOnN0cmluZyA9IEdBVXRpbGl0aWVzLmNyZWF0ZUd1aWQoKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYW51cFxyXG4gICAgICAgICAgICAgICAgICAgIGlmKHBlcmZvcm1DbGVhblVwKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY2xlYW51cEV2ZW50cygpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUV2ZW50cy5maXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cygpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gUHJlcGFyZSBTUUxcclxuICAgICAgICAgICAgICAgICAgICB2YXIgc2VsZWN0QXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcclxuICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XHJcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYoY2F0ZWdvcnkpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcImNhdGVnb3J5XCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBjYXRlZ29yeV0pO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZVNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcclxuICAgICAgICAgICAgICAgICAgICB1cGRhdGVTZXRBcmdzLnB1c2goW1wic3RhdHVzXCIsIHJlcXVlc3RJZGVudGlmaWVyXSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBldmVudHMgdG8gcHJvY2Vzc1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBldmVudHM6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLnNlbGVjdChFR0FTdG9yZS5FdmVudHMsIHNlbGVjdEFyZ3MpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBmb3IgZXJyb3JzIG9yIGVtcHR5XHJcbiAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cylcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogTm8gZXZlbnRzIHRvIHNlbmRcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIG51bWJlciBvZiBldmVudHMgYW5kIHRha2Ugc29tZSBhY3Rpb24gaWYgdGhlcmUgYXJlIHRvbyBtYW55P1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKGV2ZW50cy5sZW5ndGggPiBHQUV2ZW50cy5NYXhFdmVudENvdW50KVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWFrZSBhIGxpbWl0IHJlcXVlc3RcclxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzLCB0cnVlLCBHQUV2ZW50cy5NYXhFdmVudENvdW50KTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIWV2ZW50cylcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBHZXQgbGFzdCB0aW1lc3RhbXBcclxuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhc3RJdGVtOntba2V5OnN0cmluZ106IGFueX0gPSBldmVudHNbZXZlbnRzLmxlbmd0aCAtIDFdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFzdFRpbWVzdGFtcDpzdHJpbmcgPSBsYXN0SXRlbVtcImNsaWVudF90c1wiXSBhcyBzdHJpbmc7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBTZWxlY3QgYWdhaW5cclxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFldmVudHMpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wiY2xpZW50X3RzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsLCBsYXN0VGltZXN0YW1wXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBMb2dcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRXZlbnQgcXVldWU6IFNlbmRpbmcgXCIgKyBldmVudHMubGVuZ3RoICsgXCIgZXZlbnRzLlwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gU2V0IHN0YXR1cyBvZiBldmVudHMgdG8gJ3NlbmRpbmcnIChhbHNvIGNoZWNrIGZvciBlcnJvcilcclxuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgdXBkYXRlU2V0QXJncywgdXBkYXRlV2hlcmVBcmdzKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBwYXlsb2FkIGRhdGEgZnJvbSBldmVudHNcclxuICAgICAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGk6bnVtYmVyID0gMDsgaSA8IGV2ZW50cy5sZW5ndGg7ICsraSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gZXZlbnRzW2ldO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0ID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChldltcImV2ZW50XCJdKSk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChldmVudERpY3QubGVuZ3RoICE9IDApXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBheWxvYWRBcnJheS5wdXNoKGV2ZW50RGljdCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kRXZlbnRzSW5BcnJheShwYXlsb2FkQXJyYXksIHJlcXVlc3RJZGVudGlmaWVyLCBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzQ2FsbGJhY2spO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIGR1cmluZyBQcm9jZXNzRXZlbnRzKCk6IFwiICsgZS5zdGFjayk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudHNDYWxsYmFjayhyZXNwb25zZUVudW06RUdBSFRUUEFwaVJlc3BvbnNlLCBkYXRhRGljdDp7W2tleTpzdHJpbmddOiBhbnl9LCAgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XHJcbiAgICAgICAgICAgICAgICByZXF1ZXN0SWRXaGVyZUFyZ3MucHVzaChbXCJzdGF0dXNcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIHJlcXVlc3RJZF0pO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHNcclxuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC5cIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgLy8gUHV0IGV2ZW50cyBiYWNrIChPbmx5IGluIGNhc2Ugb2Ygbm8gcmVzcG9uc2UpXHJcbiAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzOkFycmF5PFtzdHJpbmcsIHN0cmluZ10+ID0gW107XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgXCJuZXdcIl0pO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMgdG8gY29sbGVjdG9yIC0gUmV0cnlpbmcgbmV4dCB0aW1lXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHNldEFyZ3MsIHJlcXVlc3RJZFdoZXJlQXJncyk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSBldmVudHMgKFdoZW4gZ2V0dGluZyBzb21lIGFud3NlciBiYWNrIGFsd2F5cyBhc3N1bWUgZXZlbnRzIGFyZSBwcm9jZXNzZWQpXHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKGRhdGFEaWN0KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIganNvbjphbnk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiBpbiBkYXRhRGljdClcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PSAwKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAganNvbiA9IGRhdGFEaWN0W2pdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgJiYganNvbi5jb25zdHJ1Y3RvciA9PT0gQXJyYXkpXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBcIiArIGV2ZW50Q291bnQgKyBcIiBldmVudHMgc2VudC4gXCIgKyBjb3VudCArIFwiIGV2ZW50cyBmYWlsZWQgR0Egc2VydmVyIHZhbGlkYXRpb24uXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5kZWxldGUoRUdBU3RvcmUuRXZlbnRzLCByZXF1ZXN0SWRXaGVyZUFyZ3MpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy51cGRhdGVTZXNzaW9uU3RvcmUoKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2xlYW51cEV2ZW50cygpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgW1tcInN0YXR1c1wiICwgXCJuZXdcIl1dKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBHZXQgYWxsIHNlc3Npb25zIHRoYXQgYXJlIG5vdCBjdXJyZW50XHJcbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcclxuICAgICAgICAgICAgICAgIGFyZ3MucHVzaChbXCJzZXNzaW9uX2lkXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsLCBHQVN0YXRlLmdldFNlc3Npb25JZCgpXSk7XHJcblxyXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25zOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuU2Vzc2lvbnMsIGFyZ3MpO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmICghc2Vzc2lvbnMgfHwgc2Vzc2lvbnMubGVuZ3RoID09IDApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoc2Vzc2lvbnMubGVuZ3RoICsgXCIgc2Vzc2lvbihzKSBsb2NhdGVkIHdpdGggbWlzc2luZyBzZXNzaW9uX2VuZCBldmVudC5cIik7XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gQWRkIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnRzXHJcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpIGluIHNlc3Npb25zKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uRW5kRXZlbnQ6e1trZXk6c3RyaW5nXTogYW55fSA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2Vzc2lvbnNbaV1bXCJldmVudFwiXSBhcyBzdHJpbmcpKTtcclxuICAgICAgICAgICAgICAgICAgICB2YXIgZXZlbnRfdHM6bnVtYmVyID0gc2Vzc2lvbkVuZEV2ZW50W1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcjtcclxuICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gc2Vzc2lvbnNbaV1bXCJ0aW1lc3RhbXBcIl0gYXMgbnVtYmVyO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICB2YXIgbGVuZ3RoOm51bWJlciA9IGV2ZW50X3RzIC0gc3RhcnRfdHM7XHJcbiAgICAgICAgICAgICAgICAgICAgbGVuZ3RoID0gTWF0aC5tYXgoMCwgbGVuZ3RoKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImZpeE1pc3NpbmdTZXNzaW9uRW5kRXZlbnRzIGxlbmd0aCBjYWxjdWxhdGVkOiBcIiArIGxlbmd0aCk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xyXG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImxlbmd0aFwiXSA9IGxlbmd0aDtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXHJcbiAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKHNlc3Npb25FbmRFdmVudCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZEV2ZW50VG9TdG9yZShldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgd2UgYXJlIGluaXRpYWxpemVkXHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3QgYWRkIGV2ZW50OiBTREsgaXMgbm90IGluaXRpYWxpemVkXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICB0cnlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAvLyBDaGVjayBkYiBzaXplIGxpbWl0cyAoMTBtYilcclxuICAgICAgICAgICAgICAgICAgICAvLyBJZiBkYXRhYmFzZSBpcyB0b28gbGFyZ2UgYmxvY2sgYWxsIGV4Y2VwdCB1c2VyLCBzZXNzaW9uIGFuZCBidXNpbmVzc1xyXG4gICAgICAgICAgICAgICAgICAgIGlmIChHQVN0b3JlLmlzU3RvcmVUb29MYXJnZUZvckV2ZW50cygpICYmICFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudERhdGFbXCJjYXRlZ29yeVwiXSBhcyBzdHJpbmcsIC9eKHVzZXJ8c2Vzc2lvbl9lbmR8YnVzaW5lc3MpJC8pKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkRhdGFiYXNlIHRvbyBsYXJnZS4gRXZlbnQgaGFzIGJlZW4gYmxvY2tlZC5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIEdldCBkZWZhdWx0IGFubm90YXRpb25zXHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2Ontba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldEV2ZW50QW5ub3RhdGlvbnMoKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gd2l0aCBvbmx5IGRlZmF1bHQgYW5ub3RhdGlvbnNcclxuICAgICAgICAgICAgICAgICAgICB2YXIganNvbkRlZmF1bHRzOnN0cmluZyA9IEdBVXRpbGl0aWVzLmVuY29kZTY0KEpTT04uc3RyaW5naWZ5KGV2KSk7XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIC8vIE1lcmdlIHdpdGggZXZlbnREYXRhXHJcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBlIGluIGV2ZW50RGF0YSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGV2W2VdID0gZXZlbnREYXRhW2VdO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGpzb24gc3RyaW5nIHJlcHJlc2VudGF0aW9uXHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIGpzb246c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXYpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBvdXRwdXQgaWYgVkVSQk9TRSBMT0cgZW5hYmxlZFxyXG5cclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5paShcIkV2ZW50IGFkZGVkIHRvIHF1ZXVlOiBcIiArIGpzb24pO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcclxuICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcclxuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzdGF0dXNcIl0gPSBcIm5ld1wiO1xyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNhdGVnb3J5XCJdID0gZXZbXCJjYXRlZ29yeVwiXTtcclxuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gZXZbXCJzZXNzaW9uX2lkXCJdO1xyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImNsaWVudF90c1wiXSA9IGV2W1wiY2xpZW50X3RzXCJdO1xyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuRXZlbnRzLCB2YWx1ZXMpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc2Vzc2lvbiBzdG9yZSBpZiBub3QgbGFzdFxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChldmVudERhdGFbXCJjYXRlZ29yeVwiXSA9PSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25FbmQpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5TZXNzaW9ucywgW1tcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGV2W1wic2Vzc2lvbl9pZFwiXSBhcyBzdHJpbmddXSk7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlcyA9IHt9O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gZXZbXCJzZXNzaW9uX2lkXCJdO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0aW1lc3RhbXBcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJldmVudFwiXSA9IGpzb25EZWZhdWx0cztcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuU2Vzc2lvbnMsIHZhbHVlcywgdHJ1ZSwgXCJzZXNzaW9uX2lkXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdG9yZS5pc1N0b3JhZ2VBdmFpbGFibGUoKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRFdmVudFRvU3RvcmU6IGVycm9yXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoZS5zdGFjayk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHVwZGF0ZVNlc3Npb25TdG9yZSgpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xyXG4gICAgICAgICAgICAgICAgdmFsdWVzW1wic2Vzc2lvbl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xyXG4gICAgICAgICAgICAgICAgdmFsdWVzW1widGltZXN0YW1wXCJdID0gR0FTdGF0ZS5nZXRTZXNzaW9uU3RhcnQoKTtcclxuICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCkpKTtcclxuICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLlNlc3Npb25zLCB2YWx1ZXMsIHRydWUsIFwic2Vzc2lvbl9pZFwiKTtcclxuXHJcbiAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudERhdGEpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgLy8gYWRkIHRvIGRpY3QgKGlmIG5vdCBuaWwpXHJcbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEoKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDFcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAyXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wM1wiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlc291cmNlRmxvd1R5cGVUb1N0cmluZyh2YWx1ZTpFR0FSZXNvdXJjZUZsb3dUeXBlKTogc3RyaW5nXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHN3aXRjaCh2YWx1ZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVJlc291cmNlRmxvd1R5cGUuU291cmNlOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTb3VyY2VcIjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVJlc291cmNlRmxvd1R5cGUuU2luazpcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiU2lua1wiO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2dyZXNzaW9uU3RhdHVzVG9TdHJpbmcodmFsdWU6RUdBUHJvZ3Jlc3Npb25TdGF0dXMpOiBzdHJpbmdcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgc3dpdGNoKHZhbHVlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBUHJvZ3Jlc3Npb25TdGF0dXMuU3RhcnQ6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlN0YXJ0XCI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FQcm9ncmVzc2lvblN0YXR1cy5Db21wbGV0ZTpcclxuICAgICAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiQ29tcGxldGVcIjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWw6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIkZhaWxcIjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBlcnJvclNldmVyaXR5VG9TdHJpbmcodmFsdWU6RUdBRXJyb3JTZXZlcml0eSk6IHN0cmluZ1xyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBzd2l0Y2godmFsdWUpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FFcnJvclNldmVyaXR5LkRlYnVnOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJkZWJ1Z1wiO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBRXJyb3JTZXZlcml0eS5JbmZvOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJpbmZvXCI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FFcnJvclNldmVyaXR5Lldhcm5pbmc6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndhcm5pbmdcIjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUVycm9yU2V2ZXJpdHkuRXJyb3I6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcImVycm9yXCI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsOlxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjcml0aWNhbFwiO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIiwibW9kdWxlIGdhXHJcbntcclxuICAgIGV4cG9ydCBtb2R1bGUgdGhyZWFkaW5nXHJcbiAgICB7XHJcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2EubG9nZ2luZy5HQUxvZ2dlcjtcclxuICAgICAgICBpbXBvcnQgR0FVdGlsaXRpZXMgPSBnYS51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XHJcbiAgICAgICAgaW1wb3J0IEdBU3RvcmUgPSBnYS5zdG9yZS5HQVN0b3JlO1xyXG4gICAgICAgIGltcG9ydCBFR0FTdG9yZUFyZ3NPcGVyYXRvciA9IGdhLnN0b3JlLkVHQVN0b3JlQXJnc09wZXJhdG9yO1xyXG4gICAgICAgIGltcG9ydCBFR0FTdG9yZSA9IGdhLnN0b3JlLkVHQVN0b3JlO1xyXG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2Euc3RhdGUuR0FTdGF0ZTtcclxuICAgICAgICBpbXBvcnQgR0FFdmVudHMgPSBnYS5ldmVudHMuR0FFdmVudHM7XHJcbiAgICAgICAgaW1wb3J0IEdBSFRUUEFwaSA9IGdhLmh0dHAuR0FIVFRQQXBpO1xyXG5cclxuICAgICAgICBleHBvcnQgY2xhc3MgR0FUaHJlYWRpbmdcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGluc3RhbmNlOkdBVGhyZWFkaW5nID0gbmV3IEdBVGhyZWFkaW5nKCk7XHJcbiAgICAgICAgICAgIHByaXZhdGUgcmVhZG9ubHkgYmxvY2tzOlByaW9yaXR5UXVldWU8VGltZWRCbG9jaz4gPSBuZXcgUHJpb3JpdHlRdWV1ZTxUaW1lZEJsb2NrPig8SUNvbXBhcmVyPG51bWJlcj4+e1xyXG4gICAgICAgICAgICAgICAgY29tcGFyZTogKHg6bnVtYmVyLCB5Om51bWJlcikgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB4IC0geTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgICAgIHByaXZhdGUgcmVhZG9ubHkgaWQyVGltZWRCbG9ja01hcDp7W2tleTpudW1iZXJdOiBUaW1lZEJsb2NrfSA9IHt9O1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBydW5UaW1lb3V0SWQ6bnVtYmVyO1xyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBUaHJlYWRXYWl0VGltZUluTXM6bnVtYmVyID0gMTAwMDtcclxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzOm51bWJlciA9IDguMDtcclxuICAgICAgICAgICAgcHJpdmF0ZSBrZWVwUnVubmluZzpib29sZWFuO1xyXG4gICAgICAgICAgICBwcml2YXRlIGlzUnVubmluZzpib29sZWFuO1xyXG5cclxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbml0aWFsaXppbmcgR0EgdGhyZWFkLi4uXCIpO1xyXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RhcnRUaHJlYWQoKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwZXJmb3JtVGFza09uR0FUaHJlYWQodGFza0Jsb2NrOigpID0+IHZvaWQsIGRlbGF5SW5TZWNvbmRzOm51bWJlciA9IDApOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciB0aW1lOkRhdGUgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICAgICAgICAgICAgdGltZS5zZXRTZWNvbmRzKHRpbWUuZ2V0U2Vjb25kcygpICsgZGVsYXlJblNlY29uZHMpO1xyXG5cclxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSwgdGFza0Jsb2NrKTtcclxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xyXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzY2hlZHVsZVRpbWVyKGludGVydmFsOm51bWJlciwgY2FsbGJhY2s6KCkgPT4gdm9pZCk6IG51bWJlclxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICB2YXIgdGltZTpEYXRlID0gbmV3IERhdGUoKTtcclxuICAgICAgICAgICAgICAgIHRpbWUuc2V0U2Vjb25kcyh0aW1lLmdldFNlY29uZHMoKSArIGludGVydmFsKTtcclxuXHJcbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSwgY2FsbGJhY2spO1xyXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFt0aW1lZEJsb2NrLmlkXSA9IHRpbWVkQmxvY2s7XHJcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5hZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2spO1xyXG5cclxuICAgICAgICAgICAgICAgIHJldHVybiB0aW1lZEJsb2NrLmlkO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5rZWVwUnVubmluZyA9IHRydWU7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYoIUdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZylcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pc1J1bm5pbmcgPSB0cnVlO1xyXG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNjaGVkdWxlVGltZXIoR0FUaHJlYWRpbmcuUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzLCBHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFbmRpbmcgc2Vzc2lvbi5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcclxuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZFNlc3Npb25FbmRFdmVudCgpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IDA7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0b3BFdmVudFF1ZXVlKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2Uua2VlcFJ1bm5pbmcgPSBmYWxzZTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpZ25vcmVUaW1lcihibG9ja0lkZW50aWZpZXI6bnVtYmVyKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoYmxvY2tJZGVudGlmaWVyIGluIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXApXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFtibG9ja0lkZW50aWZpZXJdLmlnbm9yZSA9IHRydWU7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrOlRpbWVkQmxvY2spOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHRoaXMuYmxvY2tzLmVucXVldWUodGltZWRCbG9jay5kZWFkbGluZS5nZXRUaW1lKCksIHRpbWVkQmxvY2spO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBydW4oKTogdm9pZFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBjbGVhclRpbWVvdXQoR0FUaHJlYWRpbmcucnVuVGltZW91dElkKTtcclxuXHJcbiAgICAgICAgICAgICAgICB0cnlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrO1xyXG5cclxuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoKHRpbWVkQmxvY2sgPSBHQVRocmVhZGluZy5nZXROZXh0QmxvY2soKSkpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIXRpbWVkQmxvY2suaWdub3JlKVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCA9IHNldFRpbWVvdXQoR0FUaHJlYWRpbmcucnVuLCBHQVRocmVhZGluZy5UaHJlYWRXYWl0VGltZUluTXMpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJFcnJvciBvbiBHQSB0aHJlYWRcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShlLnN0YWNrKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJFbmRpbmcgR0EgdGhyZWFkXCIpO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzdGFydFRocmVhZCgpOiB2b2lkXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdGFydGluZyBHQSB0aHJlYWRcIik7XHJcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5ydW5UaW1lb3V0SWQgPSBzZXRUaW1lb3V0KEdBVGhyZWFkaW5nLnJ1biwgMCk7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldE5leHRCbG9jaygpOiBUaW1lZEJsb2NrXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHZhciBub3c6RGF0ZSA9IG5ldyBEYXRlKCk7XHJcblxyXG4gICAgICAgICAgICAgICAgaWYgKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5oYXNJdGVtcygpICYmIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkuZGVhZGxpbmUuZ2V0VGltZSgpIDw9IG5vdy5nZXRUaW1lKCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5kZXF1ZXVlKCk7XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHByb2Nlc3NFdmVudFF1ZXVlKCk6IHZvaWRcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCB0cnVlKTtcclxuICAgICAgICAgICAgICAgIGlmKEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNjaGVkdWxlVGltZXIoR0FUaHJlYWRpbmcuUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzLCBHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSk7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nID0gZmFsc2U7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICB9XHJcbn1cclxuIiwibW9kdWxlIGdhXHJcbntcclxuICAgIGltcG9ydCBHQVRocmVhZGluZyA9IGdhLnRocmVhZGluZy5HQVRocmVhZGluZztcclxuICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhLmxvZ2dpbmcuR0FMb2dnZXI7XHJcbiAgICBpbXBvcnQgR0FTdG9yZSA9IGdhLnN0b3JlLkdBU3RvcmU7XHJcbiAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhLnN0YXRlLkdBU3RhdGU7XHJcbiAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2EuaHR0cC5HQUhUVFBBcGk7XHJcbiAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYS5kZXZpY2UuR0FEZXZpY2U7XHJcbiAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYS52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xyXG4gICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhLmh0dHAuRUdBSFRUUEFwaVJlc3BvbnNlO1xyXG4gICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2EudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xyXG4gICAgaW1wb3J0IEdBRXZlbnRzID0gZ2EuZXZlbnRzLkdBRXZlbnRzO1xyXG5cclxuICAgIGV4cG9ydCBjbGFzcyBHYW1lQW5hbHl0aWNzXHJcbiAgICB7XHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0KCk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBRGV2aWNlLnRvdWNoKCk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMihjdXN0b21EaW1lbnNpb25zKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyhjdXN0b21EaW1lbnNpb25zKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llcyk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSByZXNvdXJjZSBpdGVtIHR5cGVzIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlcyk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVCdWlsZChidWlsZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJCdWlsZCB2ZXJzaW9uIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdWlsZChidWlsZCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZhbGlkYXRpb24gZmFpbCAtIGNvbmZpZ3VyZSBidWlsZDogQ2Fubm90IGJlIG51bGwsIGVtcHR5IG9yIGFib3ZlIDMyIGxlbmd0aC4gU3RyaW5nOiBcIiArIGJ1aWxkKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEJ1aWxkKGJ1aWxkKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZVNka1dyYXBwZXJWZXJzaW9uKHNka0dhbWVFbmdpbmVWZXJzaW9uKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHNkayB2ZXJzaW9uOiBTZGsgdmVyc2lvbiBub3Qgc3VwcG9ydGVkLiBTdHJpbmc6IFwiICsgc2RrR2FtZUVuZ2luZVZlcnNpb24pO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uID0gc2RrR2FtZUVuZ2luZVZlcnNpb247XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVHYW1lRW5naW5lVmVyc2lvbihnYW1lRW5naW5lVmVyc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFbmdpbmVWZXJzaW9uKGdhbWVFbmdpbmVWZXJzaW9uKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIGdhbWUgZW5naW5lIHZlcnNpb246IEdhbWUgZW5naW5lIHZlcnNpb24gbm90IHN1cHBvcnRlZC4gU3RyaW5nOiBcIiArIGdhbWVFbmdpbmVWZXJzaW9uKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbiA9IGdhbWVFbmdpbmVWZXJzaW9uO1xyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlVXNlcklkKHVJZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBIGN1c3RvbSB1c2VyIGlkIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVVc2VySWQodUlkKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHVzZXJfaWQ6IENhbm5vdCBiZSBudWxsLCBlbXB0eSBvciBhYm92ZSA2NCBsZW5ndGguIFdpbGwgdXNlIGRlZmF1bHQgdXNlcl9pZCBtZXRob2QuIFVzZWQgc3RyaW5nOiBcIiArIHVJZCk7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0VXNlcklkKHVJZCk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0aWFsaXplKGdhbWVLZXk6c3RyaW5nID0gXCJcIiwgZ2FtZVNlY3JldDpzdHJpbmcgPSBcIlwiKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcclxuXHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGFscmVhZHkgaW5pdGlhbGl6ZWQuIENhbiBvbmx5IGJlIGNhbGxlZCBvbmNlLlwiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlS2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGZhaWxlZCBpbml0aWFsaXplLiBHYW1lIGtleSBvciBzZWNyZXQga2V5IGlzIGludmFsaWQuIENhbiBvbmx5IGNvbnRhaW4gY2hhcmFjdGVycyBBLXogMC05LCBnYW1lS2V5IGlzIDMyIGxlbmd0aCwgZ2FtZVNlY3JldCBpcyA0MCBsZW5ndGguIEZhaWxlZCBrZXlzIC0gZ2FtZUtleTogXCIgKyBnYW1lS2V5ICsgXCIsIHNlY3JldEtleTogXCIgKyBnYW1lU2VjcmV0KTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRLZXlzKGdhbWVLZXksIGdhbWVTZWNyZXQpO1xyXG5cclxuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW50ZXJuYWxJbml0aWFsaXplKCk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5OnN0cmluZyA9IFwiXCIsIGFtb3VudDpudW1iZXIgPSAwLCBpdGVtVHlwZTpzdHJpbmcgPSBcIlwiLCBpdGVtSWQ6c3RyaW5nID0gXCJcIiwgY2FydFR5cGU6c3RyaW5nID0gXCJcIik6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XHJcblxyXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGJ1c2luZXNzIGV2ZW50XCIpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gZXZlbnRzXHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGl0ZW1UeXBlLCBpdGVtSWQsIGNhcnRUeXBlKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSA9IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkLCBjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xyXG5cclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUmVzb3VyY2VFdmVudChmbG93VHlwZSwgY3VycmVuY3ksIGFtb3VudCwgaXRlbVR5cGUsIGl0ZW1JZCk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBhZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzOkVHQVByb2dyZXNzaW9uU3RhdHVzID0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkLCBwcm9ncmVzc2lvbjAxOnN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDI6c3RyaW5nID0gXCJcIiwgcHJvZ3Jlc3Npb24wMzpzdHJpbmcgPSBcIlwiLCBzY29yZT86bnVtYmVyKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcclxuXHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZighR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBwcm9ncmVzc2lvbiBldmVudFwiKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcclxuICAgICAgICAgICAgICAgIHZhciBzZW5kU2NvcmU6Ym9vbGVhbiA9IHR5cGVvZiBzY29yZSAhPSBcInVuZGVmaW5lZFwiO1xyXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMywgc2VuZFNjb3JlID8gc2NvcmUgOiAwLCBzZW5kU2NvcmUpO1xyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlPzpudW1iZXIpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xyXG5cclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKCFHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgdHJ1ZSwgXCJDb3VsZCBub3QgYWRkIGRlc2lnbiBldmVudFwiKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICB2YXIgc2VuZFZhbHVlOmJvb2xlYW4gPSB0eXBlb2YgdmFsdWUgIT0gXCJ1bmRlZmluZWRcIjtcclxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERlc2lnbkV2ZW50KGV2ZW50SWQsIHNlbmRWYWx1ZSA/IHZhbHVlIDogMCwgc2VuZFZhbHVlKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSA9IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xyXG5cclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRJbmZvTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldEluZm9Mb2coZmxhZyk7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBlbmFibGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbmZvIGxvZ2dpbmcgZGlzYWJsZWRcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRWZXJib3NlTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldFZlcmJvc2VMb2coZmxhZyk7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZlcmJvc2UgbG9nZ2luZyBlbmFibGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWZXJib3NlIGxvZ2dpbmcgZGlzYWJsZWRcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0VmVyYm9zZUxvZyhmbGFnKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRNYW51YWxTZXNzaW9uSGFuZGxpbmcoZmxhZyk7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMShkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMSgpKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZXNcIik7XHJcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMShkaW1lbnNpb24pO1xyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDIgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoZGltZW5zaW9uKTtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMyhkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCkpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlc1wiKTtcclxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbik7XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRGYWNlYm9va0lkKGZhY2Vib29rSWQ6c3RyaW5nID0gXCJcIik6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVGYWNlYm9va0lkKGZhY2Vib29rSWQpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RmFjZWJvb2tJZChmYWNlYm9va0lkKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEdlbmRlcihnZW5kZXI6RUdBR2VuZGVyID0gRUdBR2VuZGVyLlVuZGVmaW5lZCk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAoR0FWYWxpZGF0b3IudmFsaWRhdGVHZW5kZXIoZ2VuZGVyKSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEdlbmRlcihnZW5kZXIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QmlydGhZZWFyKGJpcnRoWWVhcjpudW1iZXIgPSAwKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUJpcnRoeWVhcihiaXJ0aFllYXIpKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QmlydGhZZWFyKGJpcnRoWWVhcik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBzdGFydFNlc3Npb24oKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuZ2V0VXNlTWFudWFsU2Vzc2lvbkhhbmRsaW5nKCkpXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcclxuICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBwdWJsaWMgc3RhdGljIGVuZFNlc3Npb24oKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5vblN0b3AoKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgdHJ5XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBjYXRjaCAoRXhjZXB0aW9uKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgb25SZXN1bWUoKTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5yZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW50ZXJuYWxJbml0aWFsaXplKCk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIEdBU3RhdGUuZW5zdXJlUGVyc2lzdGVkU3RhdGVzKCk7XHJcbiAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRlZmF1bHRVc2VySWRLZXksIEdBU3RhdGUuZ2V0RGVmYXVsdElkKCkpO1xyXG5cclxuICAgICAgICAgICAgR0FTdGF0ZS5zZXRJbml0aWFsaXplZCh0cnVlKTtcclxuXHJcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xyXG5cclxuICAgICAgICAgICAgaWYgKEdBU3RhdGUuaXNFbmFibGVkKCkpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbmV3U2Vzc2lvbigpOiB2b2lkXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiU3RhcnRpbmcgYSBuZXcgc2Vzc2lvbi5cIik7XHJcblxyXG4gICAgICAgICAgICAvLyBtYWtlIHN1cmUgdGhlIGN1cnJlbnQgY3VzdG9tIGRpbWVuc2lvbnMgYXJlIHZhbGlkXHJcbiAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xyXG5cclxuICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnJlcXVlc3RJbml0KEdhbWVBbmFseXRpY3Muc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2spO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2soaW5pdFJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwgaW5pdFJlc3BvbnNlRGljdDp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxyXG4gICAgICAgIHtcclxuICAgICAgICAgICAgLy8gaW5pdCBpcyBva1xyXG4gICAgICAgICAgICBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5PayAmJiBpbml0UmVzcG9uc2VEaWN0KVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAvLyBzZXQgdGhlIHRpbWUgb2Zmc2V0IC0gaG93IG1hbnkgc2Vjb25kcyB0aGUgbG9jYWwgdGltZSBpcyBkaWZmZXJlbnQgZnJvbSBzZXJ2ZXJ0aW1lXHJcbiAgICAgICAgICAgICAgICB2YXIgdGltZU9mZnNldFNlY29uZHM6bnVtYmVyID0gMDtcclxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0pXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgdmFyIHNlcnZlclRzOm51bWJlciA9IGluaXRSZXNwb25zZURpY3RbXCJzZXJ2ZXJfdHNcIl0gYXMgbnVtYmVyO1xyXG4gICAgICAgICAgICAgICAgICAgIHRpbWVPZmZzZXRTZWNvbmRzID0gR0FTdGF0ZS5jYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJ0aW1lX29mZnNldFwiXSA9IHRpbWVPZmZzZXRTZWNvbmRzO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBuZXcgY29uZmlnIGluIHNxbCBsaXRlIGNyb3NzIHNlc3Npb24gc3RvcmFnZVxyXG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuU2RrQ29uZmlnQ2FjaGVkS2V5LCBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShpbml0UmVzcG9uc2VEaWN0KSkpO1xyXG5cclxuICAgICAgICAgICAgICAgIC8vIHNldCBuZXcgY29uZmlnIGFuZCBjYWNoZSBpbiBtZW1vcnlcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gaW5pdFJlc3BvbnNlRGljdDtcclxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gaW5pdFJlc3BvbnNlRGljdDtcclxuXHJcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiSW5pdGlhbGl6ZSBTREsgZmFpbGVkIC0gVW5hdXRob3JpemVkXCIpO1xyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IGZhbHNlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgLy8gbG9nIHRoZSBzdGF0dXMgaWYgbm8gY29ubmVjdGlvblxyXG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5SZXF1ZXN0VGltZW91dClcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBubyByZXNwb25zZS4gQ291bGQgYmUgb2ZmbGluZSBvciB0aW1lb3V0LlwiKTtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIGJhZCByZXNwb25zZS4gQ291bGQgYmUgYmFkIHJlc3BvbnNlIGZyb20gcHJveHkgb3IgR0Egc2VydmVycy5cIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5rbm93blJlc3BvbnNlQ29kZSlcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVxdWVzdCBvciB1bmtub3duIHJlc3BvbnNlLlwiKTtcclxuICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAvLyBpbml0IGNhbGwgZmFpbGVkIChwZXJoYXBzIG9mZmxpbmUpXHJcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9PSBudWxsKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkICE9IG51bGwpXHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzZXQgbGFzdCBjcm9zcyBzZXNzaW9uIHN0b3JlZCBjb25maWcgaW5pdCB2YWx1ZXNcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgZWxzZVxyXG4gICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gdXNpbmcgZGVmYXVsdCBpbml0IHZhbHVlcy5cIik7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IGluaXQgdmFsdWVzXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGVsc2VcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IHRydWU7XHJcbiAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgIC8vIHNldCBvZmZzZXQgaW4gc3RhdGUgKG1lbW9yeSkgZnJvbSBjdXJyZW50IGNvbmZpZyAoY29uZmlnIGNvdWxkIGJlIGZyb20gY2FjaGUgZXRjLilcclxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0ID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdbXCJ0aW1lX29mZnNldFwiXSA/IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnW1widGltZV9vZmZzZXRcIl0gYXMgbnVtYmVyIDogMDtcclxuXHJcbiAgICAgICAgICAgIC8vIGlmIFNESyBpcyBkaXNhYmxlZCBpbiBjb25maWdcclxuICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFbmFibGVkKCkpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc3RhcnQgc2Vzc2lvbjogU0RLIGlzIGRpc2FibGVkLlwiKTtcclxuICAgICAgICAgICAgICAgIC8vIHN0b3AgZXZlbnQgcXVldWVcclxuICAgICAgICAgICAgICAgIC8vICsgbWFrZSBzdXJlIGl0J3MgYWJsZSB0byByZXN0YXJ0IGlmIGFub3RoZXIgc2Vzc2lvbiBkZXRlY3RzIGl0J3MgZW5hYmxlZCBhZ2FpblxyXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcclxuICAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBlbHNlXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuc3VyZUV2ZW50UXVldWVJc1J1bm5pbmcoKTtcclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgLy8gZ2VuZXJhdGUgdGhlIG5ldyBzZXNzaW9uXHJcbiAgICAgICAgICAgIHZhciBuZXdTZXNzaW9uSWQ6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xyXG5cclxuICAgICAgICAgICAgLy8gU2V0IHNlc3Npb24gaWRcclxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQgPSBuZXdTZXNzaW9uSWQ7XHJcblxyXG4gICAgICAgICAgICAvLyBTZXQgc2Vzc2lvbiBzdGFydFxyXG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xyXG5cclxuICAgICAgICAgICAgLy8gQWRkIHNlc3Npb24gc3RhcnQgZXZlbnRcclxuICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHByaXZhdGUgc3RhdGljIHJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk6IHZvaWRcclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJSZXN1bWluZyBzZXNzaW9uLlwiKTtcclxuICAgICAgICAgICAgaWYoIUdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm5ld1Nlc3Npb24oKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaXNTZGtSZWFkeShuZWVkc0luaXRpYWxpemVkOmJvb2xlYW4sIHdhcm46Ym9vbGVhbiA9IHRydWUsIG1lc3NhZ2U6c3RyaW5nID0gXCJcIik6IGJvb2xlYW5cclxuICAgICAgICB7XHJcbiAgICAgICAgICAgIGlmKG1lc3NhZ2UpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlICsgXCI6IFwiO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICAvLyBJcyBTREsgaW5pdGlhbGl6ZWRcclxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBpZiAod2FybilcclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KG1lc3NhZ2UgKyBcIlNESyBpcyBub3QgaW5pdGlhbGl6ZWRcIik7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLy8gSXMgU0RLIGVuYWJsZWRcclxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuaXNFbmFibGVkKCkpXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU0RLIGlzIGRpc2FibGVkXCIpO1xyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBHYW1lQW5hbHl0aWNzLmluaXQoKTtcclxufVxyXG4iXX0=
