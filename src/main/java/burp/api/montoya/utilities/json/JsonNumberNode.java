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
 * This interface is used to define a JSON number node.
 */
public interface JsonNumberNode extends JsonNode
{
    @Override
    Number getValue();

    /**
     * Creates a new instance of {@link JsonNumberNode} from the supplied long.
     *
     * @param value The long value.
     *
     * @return A new {@link JsonNumberNode} instance.
     */
    static JsonNumberNode jsonNumberNode(long value)
    {
        return FACTORY.jsonNumberNode(value);
    }

    /**
     * Creates a new instance of {@link JsonNumberNode} from the supplied double.
     *
     * @param value The double value.
     *
     * @return A new {@link JsonNumberNode} instance.
     */
    static JsonNumberNode jsonNumberNode(double value)
    {
        return FACTORY.jsonNumberNode(value);
    }

    /**
     * Creates a new instance of {@link JsonNumberNode} from the supplied number.
     *
     * @param value The number value.
     *
     * @return A new {@link JsonNumberNode} instance.
     */
    static JsonNumberNode jsonNumberNode(Number value)
    {
        return FACTORY.jsonNumberNode(value);
    }
}
