module gameanalytics
{
    export module utilities
    {
        export class GAUtilities
        {
            public static getHmac(key:string, data:string): string
            {
                var encryptedMessage = CryptoJS.HmacSHA256(data, key);
                var result:string = CryptoJS.enc.Base64.stringify(encryptedMessage);
                return result;
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
                if (array.length == 0)
                {
                    return false;
                }

                for(let s in array)
                {
                    if(s === search)
                    {
                        return true;
                    }
                }
                return false;
            }

            public static timeIntervalSince1970(): number
            {
                var date:Date = new Date();
                return Math.round(date.getTime() / 1000);
            }
        }
    }
}
