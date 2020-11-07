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

import java.util.LinkedHashMap;
import static org.ejbca.core.protocol.acme.AcmeIdentifier.AcmeIdentifierTypes;

/**
 * An ACME Challenge is a proof a client needs to provide in order to be 
 * authorized to get a certificate for an identifier.
 * 
 * One of:
 * 
 * DNS_HTTP_01 http-01 challenge for DNS identifier as specified in RFC8555
 * DNS_DNS_01 dns-01 challenge for DNS identifier as specified in RFC8555
 * IP_HTTP_01 http-01 challenge for IP identifier as specified in RFC8738 
 * 
 * PROCESSING constant in AcmeChallengeStatus ENUM is a requirement imposed 
 * by draft-ietf-acme-acme-12 and is preserved for
 * future use. 
 */
public interface AcmeChallenge {

    String getChallengeId();

    void setChallengeId(String challengeId);

    String getAuthorizationId();

    void setAuthorizationId(String authorizationId);

    String getType();

    void setType(String type);

    String getUrl();

    void setUrl(String url);

    AcmeChallengeStatus getStatus();

    void setStatus(AcmeChallengeStatus status);

    String getValidated();

    void setValidated(String validated);

    String getToken();

    void setToken(String token);

    String getKeyAuthorization();

    void setKeyAuthorization(String keyAuthorization);

    float getLatestVersion();

    void upgrade();
    
    LinkedHashMap<Object, Object> getRawData();

    /* Contains RFC8555 challenge DNS_* and RFC8738 IP challenge IP_HTTP_01. */
    enum AcmeChallengeType {

        DNS_HTTP_01(AcmeIdentifierTypes.DNS, "http-01"),
        DNS_DNS_01(AcmeIdentifierTypes.DNS, "dns-01"),
        IP_HTTP_01(AcmeIdentifierTypes.IP, "http-01");

        private final AcmeIdentifierTypes identifierTypes;
        private final String challengeType;

        AcmeChallengeType(final AcmeIdentifierTypes identifierTypes, final String challengeType) {
            this.identifierTypes = identifierTypes;
            this.challengeType = challengeType;
        }

        public AcmeIdentifierTypes getAcmeIdentifierTypes() { return identifierTypes; }
        public String getChallengeType() { return challengeType; }
    }
}