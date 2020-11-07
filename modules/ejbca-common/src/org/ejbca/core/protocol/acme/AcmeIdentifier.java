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
package org.ejbca.core.protocol.acme;

/**
 * An ACME identifier is what the client requests the CA to certify.
 * 
 * One of:
 * 
 * DNS identifier as specified in RFC8555 ACME Final (March 2019).
 * IP identifier as specified in RFC8738 (ACME) IP Identifier
 *    Validation Extension (February 2020).
 */
public interface AcmeIdentifier {
    
    String getType();

    void setType(String type);

    String getValue();

    void setValue(String value);

    enum AcmeIdentifierTypes {
        DNS,
        IP;

        public String getJsonValue() { return this.name().toLowerCase(); }
    }
}