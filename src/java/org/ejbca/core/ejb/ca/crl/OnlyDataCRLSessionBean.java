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

package org.ejbca.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ca.store.CRLDataLocalHome;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CryptoProviderTools;


/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs.
 * CRLs are signed using RSASignSessionBean.
 * 
 * @ejb.bean
 *   description="Session bean handling hard token data, both about hard tokens and hard token issuers."
 *   display-name="OnlyDataCRLSB"
 *   name="OnlyDataCRLSession"
 *   jndi-name="OnlyDataCRLSession"
 *   local-jndi-name="OnlyDataCRLSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Supports"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @jboss.method-attributes pattern="*" transaction-timeout="3600"
 *
 * @ejb.env-entry description="JDBC datasource to be used"
 *   name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.ejb-external-ref description="The CRL entity bean used to store and fetch CRLs"
 *   view-type="local"
 *   ref-name="ejb/CRLDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.store.CRLDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.CRLDataLocal"
 *   link="CRLData"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionRemote"
 *   
 * @version $Id$
 */
public class OnlyDataCRLSessionBean extends BaseSessionBean {

    /** The home interface of CRL entity bean */
    private CRLDataLocalHome crlDataHome = null;
    final private CRLUtil.Adapter adapter;
    public OnlyDataCRLSessionBean() {
        super();
        CryptoProviderTools.installBCProvider();
        this.adapter = new MyAdapter();
    }
    private class MyAdapter implements CRLUtil.Adapter {
		/* (non-Javadoc)
		 * @see org.ejbca.core.ejb.ca.crl.CRLUtil.Adapter#getCRLDataLocalHome()
		 */
		public CRLDataLocalHome getCRLDataLocalHome() {
			return OnlyDataCRLSessionBean.this.crlDataHome;
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.ejb.ca.crl.CRLUtil.Adapter#log(org.ejbca.core.model.log.Admin, int, int, java.util.Date, java.lang.String, java.security.cert.Certificate, int, java.lang.String)
		 */
		public void log(Admin admin, int caid, int module, Date time,
						String username, Certificate certificate, int event,
						String comment) {
			// do nothing
		}
    }
    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        this.crlDataHome = (CRLDataLocalHome) getLocator().getLocalHome(CRLDataLocalHome.COMP_NAME);
    }

    /**
     * Retrieves the latest CRL issued by this CA.
     *
     * @param admin Administrator performing the operation
     * @param issuerdn the CRL issuers DN (CAs subject DN)
     * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
     * @return byte[] with DER encoded X509CRL or null of no CRLs have been issued.
     * @ejb.interface-method
     */
    public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
    	return CRLUtil.getLastCRL(admin, issuerdn, deltaCRL, this.adapter);
    } //getLastCRL

    /**
     * Retrieves the information about the lastest CRL issued by this CA. Retreives less information than getLastCRL, i.e. not the actual CRL data.
     *
     * @param admin Administrator performing the operation
     * @param issuerdn the CRL issuers DN (CAs subject DN)
     * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
     * @return CRLInfo of last CRL by CA or null if no CRL exists.
     * @ejb.interface-method
     */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
    	return CRLUtil.getLastCRLInfo(admin, issuerdn, deltaCRL, this.adapter);
    } //getLastCRLInfo

    /**
     * Retrieves the information about the specified CRL. Retreives less information than getLastCRL, i.e. not the actual CRL data.
     *
     * @param admin Administrator performing the operation
     * @param fingerprint fingerprint of the CRL
     * @return CRLInfo of CRL or null if no CRL exists.
     * @ejb.interface-method
     */
    public CRLInfo getCRLInfo(Admin admin, String fingerprint) {
    	return CRLUtil.getCRLInfo(admin, fingerprint, this.adapter);
    } //getCRLInfo

    /**
     * Retrieves the highest CRLNumber issued by the CA.
     *
     * @param admin    Administrator performing the operation
     * @param issuerdn the subjectDN of a CA certificate
     * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
     * @ejb.interface-method
     */
    public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
    	return CRLUtil.getLastCRLNumber(admin, issuerdn, deltaCRL);
    } //getLastCRLNumber
}

