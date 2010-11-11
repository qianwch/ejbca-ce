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
package org.ejbca.core.protocol.crlstore;

import javax.ejb.EJBException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;

/**
 * DB store of data to be used by the CA
 * 
 * @author primelars
 * @version $Id$
 *
 */
public class CRLStore implements ICRLStore {

    private static ICreateCRLSessionLocal crlStore = null;
    synchronized ICreateCRLSessionLocal getCRLSession(){
        if(crlStore == null){    
            try {
            	ICreateCRLSessionLocalHome storehome = (ICreateCRLSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            	crlStore = storehome.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return crlStore;
    }
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getCRLInfo(org.ejbca.core.model.log.Admin, java.lang.String)
	 */
	@Override
	public CRLInfo getCRLInfo(Admin admin, String fingerprint) {
		return getCRLSession().getCRLInfo(admin, fingerprint);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRL(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	@Override
	public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLSession().getLastCRL(admin, issuerdn, deltaCRL);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRLInfo(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	@Override
	public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLSession().getLastCRLInfo(admin, issuerdn, deltaCRL);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRLNumber(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	@Override
	public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLSession().getLastCRLNumber(admin, issuerdn, deltaCRL);
	}

}
