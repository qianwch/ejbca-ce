/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.acme.eab;

import org.cesecore.accounts.AccountBinding;

/**
 * Base interface for all ACME external account bindings (EAB).
 * 
 * https://tools.ietf.org/html/rfc8555#section-7.3.4 
 * 
 * @version $Id$
 */
public interface AcmeExternalAccountBinding extends AccountBinding {

    /**
     * Parses the EAB message ({@link Acme}. The RFC8555 compliant EAB 
     * implementation uses a JWS protected message. Other implementation 
     * may use their individual message format. 
     * 
     * https://tools.ietf.org/html/rfc8555#section-7.3.4
     * 
     * "externalAccountBinding": {
     *    "protected": base64url({
     *      "alg": "HS256",
     *      "kid": // key identifier from CA //,
     *      "url": "https://example.com/acme/new-account"
     *    }),
     *   "payload": base64url(// same as in "jwk" above //),
     *   "signature": // MAC using MAC key from CA //
     *  }
     * 
     * @param message the message string.
     * @return true if the message could be parsed (technically and well-formed).
     * @throws AcmeEabRequestParsingException if the message could not be parsed.
     */
    boolean parseEabRequestMessage(String message) throws AcmeEabRequestParsingException;
    
    /**
     * Clone has to be implemented instead of a copy constructor due to the 
     * fact that we'll be referring to implementations by this interface only. 
     * 
     * @return a deep copied clone of this account binding implementation.
     */
    AcmeExternalAccountBinding clone();
}
