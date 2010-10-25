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

package org.ejbca.ui.web.protocol;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.protocol.ocsp.CertStoreStandAlone;
import org.ejbca.core.protocol.ocsp.CertificateCache;
import org.ejbca.core.protocol.ocsp.CertificateCacheStandAloneFactory;
import org.ejbca.core.protocol.ocsp.OCSPData;
import org.ejbca.core.protocol.ocsp.standalonesession.StandAloneSessionFactory;
import org.ejbca.ui.web.pub.cluster.VerificationAuthorityHealthCheck;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 * 
 * @web.servlet name = "OCSP"
 *              display-name = "OCSPServletStandAlone"
 *              description="Answers OCSP requests"
 *              load-on-startup = "1"
 *
 * @web.servlet-mapping url-pattern = "/ocsp"
 * @web.servlet-mapping url-pattern = "/ocsp/*"
 *
 * @web.resource-ref
 *  name="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *  type="javax.sql.DataSource"
 *  auth="Container"
 *  
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public class OCSPServletStandAlone extends OCSPServletBase implements IHealtChecker {

    private static final long serialVersionUID = -7093480682721604160L;

    /** Special logger only used to log version number. ejbca.version.log can be directed to a special logger, or have a special log level 
     * in the log4j configuration. 
     */
	private static final Logger m_versionLog = Logger.getLogger("org.ejbca.version.log");

    private IStandAloneSession session;

    /**
     * An instance needs to exist that provides signing functionality to the OCSP responder. This session must implement this interface.
     *
     */
    public interface IStandAloneSession{
        /**
         * Fixes the answer for the call to {@link OCSPServletStandAlone#healthCheck()}
         * @return The answer to be returned by the health-check servlet.
         */
        String healthCheck(boolean doSignTest, boolean doValidityTest);
        /**
         * Adds {@link SigningEntity} to the {@link SigningEntityContainer} object for all OCSP signing keys that could be found.
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param password Password for activation. If null then ust key loading.
         * @throws Exception
         */
        void loadPrivateKeys(Admin adm, String password) throws Exception;
        /**
         * Answers the OCSP request. The answer is assembled in a separate thread by an object of the class {@link SignerThread}.
         * @param caid EJBCA id for the CA.
         * @param request Object with for the request.
         * @return the response.
         * @throws ExtendedCAServiceRequestException
         * @throws ExtendedCAServiceNotActiveException
         * @throws IllegalExtendedCAServiceRequestException
         */
        OCSPCAServiceResponse extendedService(int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException;
    }
    public OCSPServletStandAlone() {
        super(new OCSPData(new CertStoreStandAlone()));
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        // Log with warn priority so it will be visible in strict production configurations  
	    m_versionLog.warn("Init, "+GlobalConfiguration.EJBCA_VERSION+" OCSP startup");

        this.session = StandAloneSessionFactory.getInstance(this.data);
        // session must be created before health check could be done
        VerificationAuthorityHealthCheck.setHealtChecker(this);
    }
    
    /**
     * Method used to log OCSP service shutdown.
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy() {
		super.destroy();
        // Log with warn priority so it will be visible in strict production configurations  
	    m_versionLog.warn("Destroy, "+GlobalConfiguration.EJBCA_VERSION+" OCSP shutdown");
	}

    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.IHealtChecker#healthCheck()
     */
    public String healthCheck(boolean doSignTest, boolean doValidityTest) {
        return this.session.healthCheck(doSignTest, doValidityTest);
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#loadPrivateKeys(org.ejbca.core.model.log.Admin, java.lang.String)
     */
    protected void loadPrivateKeys(Admin adm, String password) throws Exception {
        this.session.loadPrivateKeys(adm, password);
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#extendedService(org.ejbca.core.model.log.Admin, int, org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest)
     */
    protected OCSPCAServiceResponse extendedService(Admin adm, int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException,
                                                                                                    ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        return this.session.extendedService(caid, request);
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletBase#createCertificateCache()
     */
    protected CertificateCache createCertificateCache() {
		return CertificateCacheStandAloneFactory.getInstance();
	}
}
