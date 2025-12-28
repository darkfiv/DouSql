/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

import burp.api.montoya.utilities.json.JsonUtils;

/**
 * This interface gives you access to other interfaces that have various data conversion and querying features.
 */
public interface Utilities
{
    /**
     * @return an instance of {@link burp.api.montoya.utilities.Base64Utils}
     */
    Base64Utils base64Utils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.ByteUtils}
     */
    ByteUtils byteUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.CompressionUtils}
     */
    CompressionUtils compressionUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.CryptoUtils}
     */
    CryptoUtils cryptoUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.HtmlUtils}
     */
    HtmlUtils htmlUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.NumberUtils}
     */
    NumberUtils numberUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.RandomUtils}
     */
    RandomUtils randomUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.StringUtils}
     */
    StringUtils stringUtils();

    /**
     * @return an instance of {@link burp.api.montoya.utilities.URLUtils}
     */
    URLUtils urlUtils();

    /**
     * @return an instance of {@link JsonUtils}
     */
    JsonUtils jsonUtils();
}
