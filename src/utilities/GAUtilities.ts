module gameanalytics
{
    export module utilities
    {
        import GALogger = gameanalytics.logging.GALogger;

        export class GAUtilities
        {
            public static getHmac(key:string, data:string): string
            {
                var encryptedMessage = CryptoJS.HmacSHA256(data, key);
                return CryptoJS.enc.Base64.stringify(encryptedMessage);
            }

            public static stringMatch(s:string, pattern:RegExp): boolean
            {
                if(!s || !pattern)
                {
                    return false;
                }

                return pattern.test(s);
            }

            public static joinStringArray(v:Array<string>, delimiter:string): string
            {
                var result:string = "";

                for (let i = 0, il = v.length; i < il; i++)
                {
                    if (i > 0)
                    {
                        result += delimiter;
                    }
                    result += v[i];
                }
                return result;
            }

            public static stringArrayContainsString(array:Array<string>, search:string): boolean
            {
                if (array.length === 0)
                {
                    return false;
                }

                for(let s in array)
                {
                    if(array[s] === search)
                    {
                        return true;
                    }
                }
                return false;
            }

            private static readonly keyStr:string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

            public static encode64(input:string): string
            {
                input = encodeURI(input);
                var output:string = "";
                var chr1:number, chr2:number, chr3:number = 0;
                var enc1:number, enc2:number, enc3:number, enc4:number = 0;
                var i = 0;

                do
                {
                   chr1 = input.charCodeAt(i++);
                   chr2 = input.charCodeAt(i++);
                   chr3 = input.charCodeAt(i++);

                   enc1 = chr1 >> 2;
                   enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                   enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                   enc4 = chr3 & 63;

                   if (isNaN(chr2))
                   {
                      enc3 = enc4 = 64;
                   }
                   else if (isNaN(chr3))
                   {
                      enc4 = 64;
                   }

                   output = output +
                      GAUtilities.keyStr.charAt(enc1) +
                      GAUtilities.keyStr.charAt(enc2) +
                      GAUtilities.keyStr.charAt(enc3) +
                      GAUtilities.keyStr.charAt(enc4);
                   chr1 = chr2 = chr3 = 0;
                   enc1 = enc2 = enc3 = enc4 = 0;
                }
                while (i < input.length);

                return output;
            }

            public static decode64(input:string): string
            {
                var output:string = "";
                var chr1:number, chr2:number, chr3:number = 0;
                var enc1:number, enc2:number, enc3:number, enc4:number = 0;
                var i = 0;

                // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
                var base64test = /[^A-Za-z0-9\+\/\=]/g;
                if (base64test.exec(input)) {
                   GALogger.w("There were invalid base64 characters in the input text. Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='. Expect errors in decoding.");
                }
                input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

                do
                {
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

                }
                while (i < input.length);

                return decodeURI(output);
            }

            public static timeIntervalSince1970(): number
            {
                var date:Date = new Date();
                return Math.round(date.getTime() / 1000);
            }

            public static createGuid(): string
            {
                return ("10000000-1000-4000-8000-100000000000").replace(/[018]/g, c => (+c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> +c / 4).toString(16));
            }
        }
    }
}
