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
 * This interface is used to define a JSON boolean node.
 */
public interface JsonBooleanNode extends JsonNode
{
    @Override
    Boolean getValue();

    /**
     * Creates a new instance of {@link JsonBooleanNode} from the supplied boolean.
     *
     * @param value The boolean value.
     *
     * @return A new {@link JsonBooleanNode} instance.
     */
    static JsonBooleanNode jsonBooleanNode(boolean value)
    {
        return FACTORY.jsonBooleanNode(value);
    }
}
