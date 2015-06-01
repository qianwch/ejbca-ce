/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/  
package org.cesecore.certificates.ca;

import org.cesecore.certificates.ca.catoken.CATokenConstants;

/**
 * Constants for CAs.
 *
 * @version $Id$
 */
public final class CAConstants {
    
    /** Constants used to indicate status of a CA. */
    public static final int CA_ACTIVE = 1;
    public static final int CA_WAITING_CERTIFICATE_RESPONSE = 2;
    public static final int CA_EXPIRED = 3;
    public static final int CA_REVOKED = 4;
    public static final int CA_OFFLINE = 5;
    public static final int CA_EXTERNAL = 6;
    public static final int CA_UNINITIALIZED = 7;

    /**
     * The policy ID can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' 
     * or objectID and cpsurl as '2.5.29.32.0 http://foo.bar.com/mycps.txt'. You can add multiple policies such as 
     * '2.5.29.32.0 http://foo.bar.com/mycps.txt 1.1.1.1.1 http://foo.bar.com/111cps.txt'.
     */
    public static final String POLICYID = "policyid";
    
    /** Certificate signing key alias */
    public static final String CAKEYPURPOSE_CERTSIGN_STRING = CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING;
    /** Certificate Revocation List (CRL) signing key alias. Must be the same as the certificate signing key.  */
    public static final String CAKEYPURPOSE_CRLSIGN_STRING = CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING;
    /** Used for decryption of key recovery data. Must be an RSA key. */
    public static final String CAKEYPURPOSE_KEYENCRYPT_STRING = CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING;
    /** Test signing key. Used by health-check. */
    public static final String CAKEYPURPOSE_TESTKEY_STRING = CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING;
    /** Default key. If any of the other aliases are not specified, this will be used in their place. Must be an RSA key if decryption key aliases are not specified.*/
    public static final String CAKEYPURPOSE_DEFAULT_STRING = CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING;
    /** Used for decryption of hard token data (e.g. PUK code). Must be an RSA key. */
    public static final String CAKEYPURPOSE_HARDTOKENENCRYPT_STRING = CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING;

    /**
     * Constants used in the SignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;

    /** Used in profiles and service workers to make the catch all every CA instead of listing individual CAs when operating on them */
    public static final int ALLCAS = 1;
    
    /**
     * Prevents creation of new CAConstants
     */
    private CAConstants() {
    }

}