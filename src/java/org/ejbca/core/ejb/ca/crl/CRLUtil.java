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
import java.security.cert.X509CRL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Date;

import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ca.store.CRLDataLocal;
import org.ejbca.core.ejb.ca.store.CRLDataLocalHome;
import org.ejbca.core.ejb.ca.store.CRLDataPK;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.ui.web.protocol.OCSPServletBase;
import org.ejbca.util.JDBCUtil;
class CRLUtil {
	private static final Logger log = Logger.getLogger(OCSPServletBase.class);
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();
	static interface Adapter {
		/** The home interface of CRL entity bean */
		CRLDataLocalHome getCRLDataLocalHome();
		void log(Admin admin, int caid, int module, Date time, String username,
		         Certificate certificate, int event, String comment);
	}
	/**
	 * Retrieves the latest CRL issued by this CA.
	 *
	 * @param admin Administrator performing the operation
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
	 * @param adapter info about the environment
	 * @return byte[] with DER encoded X509CRL or null of no CRLs have been issued.
	 */
	static byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL, Adapter adapter) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRL(" + issuerdn + ", "+deltaCRL+")");
		}
		try {
			final int maxnumber = getLastCRLNumber(admin, issuerdn, deltaCRL);
			X509CRL crl;
			try {
				CRLDataLocal data = adapter.getCRLDataLocalHome().findByIssuerDNAndCRLNumber(issuerdn, maxnumber);
				crl = data.getCRL();
			} catch (FinderException e) {
				crl = null;
			}
			log.trace("<getLastCRL()");
			if (crl == null) {
				String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, maxnumber);
				adapter.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
				return null;
			}
			String msg = intres.getLocalizedMessage("store.getcrl", issuerdn, new Integer(maxnumber));
			adapter.log(admin, crl.getIssuerDN().toString().hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_GETLASTCRL, msg);
			return crl.getEncoded();
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn);
			adapter.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		}
	} //getLastCRL
	/**
	 * Retrieves the information about the lastest CRL issued by this CA. Retreives less information than getLastCRL, i.e. not the actual CRL data.
	 *
	 * @param admin Administrator performing the operation
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
	 * @param adapter info about the environment
	 * @return CRLInfo of last CRL by CA or null if no CRL exists.
	 */
	static CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL, Adapter adapter) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRLInfo(" + issuerdn + ", "+deltaCRL+")");
		}
		int crlnumber = 0;
		try {
			crlnumber = getLastCRLNumber(admin, issuerdn, deltaCRL);
			CRLDataLocal data = adapter.getCRLDataLocalHome().findByIssuerDNAndCRLNumber(issuerdn, crlnumber);
			return new CRLInfo(data.getIssuerDN(), crlnumber, data.getThisUpdate(), data.getNextUpdate());
		} catch (FinderException e) {
			if (deltaCRL && (crlnumber == 0)) {
				log.debug("No delta CRL exists for CA with dn '"+issuerdn+"'");
			} else if (crlnumber == 0) {
				log.debug("No CRL exists for CA with dn '"+issuerdn+"'");
			} else {
				String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, new Integer(crlnumber));
				log.error(msg, e);
			}
			return null;
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", issuerdn);
			adapter.log(admin, issuerdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		} finally {
			log.trace("<getLastCRLInfo()");
		}
	} //getLastCRLInfo
	/**
	 * Retrieves the information about the specified CRL. Retreives less information than getLastCRL, i.e. not the actual CRL data.
	 *
	 * @param admin Administrator performing the operation
	 * @param fingerprint fingerprint of the CRL
	 * @param adapter info about the environment
	 * @return CRLInfo of CRL or null if no CRL exists.
	 */
	static CRLInfo getCRLInfo(Admin admin, String fingerprint, Adapter adapter) {
		if (log.isTraceEnabled()) {
			log.trace(">getCRLInfo(" + fingerprint+")");
		}
		try {
			final CRLDataLocal data = adapter.getCRLDataLocalHome().findByPrimaryKey(new CRLDataPK(fingerprint));
			return new CRLInfo(data.getIssuerDN(), data.getCrlNumber(), data.getThisUpdate(), data.getNextUpdate());
		} catch (FinderException e) {
			log.debug("No CRL exists with fingerprint '"+fingerprint+"'");
			String msg = intres.getLocalizedMessage("store.errorgetcrl", fingerprint, 0);
			log.error(msg, e);
			return null;
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", fingerprint);
			adapter.log(admin, fingerprint.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		} finally {
			log.trace("<getCRLInfo()");
		}
	} //getCRLInfo
	/**
	 * Retrieves the highest CRLNumber issued by the CA.
	 *
	 * @param admin    Administrator performing the operation
	 * @param issuerdn the subjectDN of a CA certificate
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
	 * @return the number
	 */
	static int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRLNumber(" + issuerdn + ", "+deltaCRL+")");
		}
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet result = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql = "select MAX(cRLNumber) from CRLData where issuerDN=? and deltaCRLIndicator=?";
			String deltaCRLSql = "select MAX(cRLNumber) from CRLData where issuerDN=? and deltaCRLIndicator>?";
			int deltaCRLIndicator = -1;
			if (deltaCRL) {
				sql = deltaCRLSql;
				deltaCRLIndicator = 0;
			}
			ps = con.prepareStatement(sql);
			ps.setString(1, issuerdn);
			ps.setInt(2, deltaCRLIndicator);
			result = ps.executeQuery();
			int maxnumber = 0;
			if (result.next()) {
				maxnumber = result.getInt(1);
			}
			if (log.isTraceEnabled()) {
				log.trace("<getLastCRLNumber(" + maxnumber + ")");
			}
			return maxnumber;
		} catch (Exception e) {
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, result);
		}
	} //getLastCRLNumber
}
