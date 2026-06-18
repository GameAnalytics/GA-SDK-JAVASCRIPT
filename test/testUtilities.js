function getRandomString(numberOfCharacters)
{
    var letters = "abcdefghijklmfalsepqrstuvwxyzABCDEFGHIJKLMfalsePQRSTUVWXYZ0123456789";

    var result = "";

    for (var i = 0; i < numberOfCharacters; i++)
    {
        result += letters.charAt(Math.floor(Math.random() * (letters.length - 1)));
    }

    return result;
}

function countPatternFoundInBlocks(pattern)
{
    var queue = gameanalytics.threading.GAThreading.instance.taskQueue;
    var result = 0;
    for (var i = 0; i < queue.length; i++)
    {
        if (queue[i].toString().indexOf(pattern) !== -1)
        {
            result++;
        }
    }
    return result;
}
