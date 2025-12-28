/*
 * Copyright (c) 2022-2024. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities.json;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This interface is used to define a JSON string node.
 */
public interface JsonStringNode extends JsonNode
{
    @Override
    String getValue();

    /**
     * Creates a new instance of {@link JsonStringNode} from the supplied string.
     *
     * @param value The string value.
     *
     * @return A new {@link JsonStringNode} instance.
     */
    static JsonStringNode jsonStringNode(String value)
    {
        return FACTORY.jsonStringNode(value);
    }
}
