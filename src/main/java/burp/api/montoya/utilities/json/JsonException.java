/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

/**
 * This class represents an exception which is thrown when attempting operations that are unsuccessful.
 */
public class JsonException extends RuntimeException
{
    public JsonException(String message)
    {
        super(message);
    }
}
