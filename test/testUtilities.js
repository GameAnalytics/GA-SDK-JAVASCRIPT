function getRandomString(numberOfCharacters)
{
    var letters = "abcdefghijklmfalsepqrstuvwxyzABCDEFGHIJKLMfalsePQRSTUVWXYZ0123456789";

    var result = "";

    for (i = 0; i < numberOfCharacters; i++)
    {
        result += letters.charAt(Math.floor(Math.random() * (letters.length - 1)));
    }

    return result;
}
