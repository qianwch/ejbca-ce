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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;

import javax.ejb.EJBException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome;
import org.ejbca.core.model.log.Admin;

/**
 * DB store of data to be used by the VA
 *
 * @author primelars
 * @version $Id$
 *
 */
public class CertStoreStandAlone implements ICertStore {
    private static ICertificateStoreOnlyDataSessionLocal m_certStore = null;
    /**
     * Returns the certificate data only session bean
     */
    synchronized ICertificateStoreOnlyDataSessionLocal getStoreSessionOnlyData(){
        if(CertStoreStandAlone.m_certStore == null){   
            try {
                ServiceLocator locator = ServiceLocator.getInstance();
                ICertificateStoreOnlyDataSessionLocalHome castorehome =
                    (ICertificateStoreOnlyDataSessionLocalHome)locator.getLocalHome(ICertificateStoreOnlyDataSessionLocalHome.COMP_NAME);
                CertStoreStandAlone.m_certStore = castorehome.create();
            }catch(Exception e){
                throw new EJBException(e);                          
            }
        }
        return CertStoreStandAlone.m_certStore;
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.protocol.ocsp.ICertStore#findCertificatesByType(org.ejbca.core.model.log.Admin, int, java.lang.String)
     */
    public Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return getStoreSessionOnlyData().findCertificatesByType(adm, type, issuerDN);           
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.ICertStore#findCertificateByIssuerAndSerno(org.ejbca.core.model.log.Admin, java.lang.String, java.math.BigInteger)
     */
    public Certificate findCertificateByIssuerAndSerno(Admin adm,
                                                       String issuerDN,
                                                       BigInteger serno) {
        return getStoreSessionOnlyData().findCertificateByIssuerAndSerno(adm, issuerDN, serno);
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.ICertStore#getStatus(java.lang.String, java.math.BigInteger)
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serialNumber) {
        return getStoreSessionOnlyData().getStatus(issuerDN, serialNumber);
    }
}
