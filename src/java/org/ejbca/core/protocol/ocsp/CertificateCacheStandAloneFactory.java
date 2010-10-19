/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp;

/**
 * Factory for creating a {@link CertificateCache} object to be used by the verification authority.
 * 
 * @author primelars
 * @version $Id$
 * 
 */
public class CertificateCacheStandAloneFactory {
    private static CertificateCache instance = null;
    /**
     * @return  {@link CertificateCache} for the VA.
     */
    public static synchronized CertificateCache getInstance() {
        if (instance == null) {
            instance = new CertificateCache(new CertStoreStandAlone());
        }
        return instance;
    }

}
