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
    var GAThreading = gameanalytics.threading.GAThreading;
    var result = 0;
    for (var i = 0; i < GAThreading.instance.blocks._sortedKeys.length; i++)
    {
        for (var j = 0; j < GAThreading.instance.blocks._subQueues[GAThreading.instance.blocks._sortedKeys[i]].length; j++)
        {
            if(GAThreading.instance.blocks._subQueues[GAThreading.instance.blocks._sortedKeys[i]][j].block.toString().indexOf(pattern) != -1)
            {
                result++;
            }
        }
    }

    return result;
}
