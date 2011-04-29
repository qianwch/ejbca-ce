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
 
package org.ejbca.core.ejb.ca.store;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.FixEndOfBrokenXML;






/**
 * Entity Bean storing historical information about the data user to 
 * create a certificate. Information stored:
 * <pre>
 * Primary Key (fingerprint, String)
 * Issuer DN (issuerDN)
 * Serial number (serialNumber)
 * Username (username);
 * Timestamp (timestamp)
 * UserDataVO (userAdminData)
 * </pre>
 * 
 * the information is currently used to:
 * - list request history for a user
 * - find issuing User DN (UserDataVO) when republishing a certificate (in case the userDN for the user changed)
 * 
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity containing historical record over data user to generate a users certificate"
 * display-name="CertReqHistoryDataEB"
 * name="CertReqHistoryData"
 * jndi-name="CertReqHistoryData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertReqHistoryDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "CertReqHistoryData"
 * 
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocal"
 *
 * @ejb.finder description="findByIssuerDNSerialNumber"
 * signature="Collection findByIssuerDNSerialNumber(java.lang.String issuerDN, java.lang.String serialNumber)"
 * query="SELECT OBJECT(a) from CertReqHistoryDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2"
 *
 * @ejb.finder description="findByUsername"
 * signature="Collection findByUsername(java.lang.String username)"
 * query="SELECT OBJECT(a) from CertReqHistoryDataBean a WHERE  a.username=?1"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CertReqHistoryDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(CertReqHistoryDataBean.class);

    /**
     * @ejb.persistence column-name="rowVersion"
     */
    public abstract int getRowVersion();
    public abstract void setRowVersion(int rowVersion);

    /**
     * @ejb.persistence column-name="rowProtection"
     */
    public abstract String getRowProtection();
    public abstract void setRowProtection(String rowProtection);

    /**
     * DN of issuer of certificate
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return issuer dn
     * @ejb.persistence column-name="issuerDN"
     * 
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * Fingerprint of certificate
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return fingerprint
     * @ejb.persistence column-name="fingerprint"
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getFingerprint();

    /**
     * Fingerprint of certificate
     * Shouldn't be set after creation.
     * 
     * @param fingerprint fingerprint
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * Serialnumber formated as BigInteger.toString()
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return serial number
     * @ejb.persistence column-name="serialNumber"
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     * Shouldn't be set after creation.
     * 
     * @param serialNumber serial number
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return timestamp 
     * @ejb.persistence column-name="timestamp"
     */
    public abstract long getTimestamp();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Shouldn't be set after creation.
     *
     * @param timestamp when certificate request info was stored
     */
    public abstract void setTimestamp(long timestamp);


    /**
     * UserDataVO in xmlencoded String format
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return  xmlencoded encoded UserDataVO
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="userDataVO"
     */
    public abstract String getUserDataVO();

    /**
     * UserDataVO in  xmlencoded String format
     * Shouldn't be set after creation.
     *
     * @param userDataVO xmlencoded encoded UserDataVO
     */
    public abstract void setUserDataVO(String userDataVO);

    /**
     * username in database
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return username
     * @ejb.persistence column-name="username"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * Shouldn't be set after creation.
     *
     * @param username username
     *
     * @see org.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to retreive cert req history 
     * correctly.
     *
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
     * @return certificate request history object
     * @ejb.interface-method
     */
    public CertReqHistory getCertReqHistory() {

		return new CertReqHistory(this.getFingerprint(),this.getSerialNumber(),
		                          this.getIssuerDN(),this.getUsername(),new Date(this.getTimestamp()),
		                          decodeXML(getUserDataVO(), false));
	}
    
	/** just used internally in the this class to indicate that the XML can not be fixed.
	 */
	private class NotPossibleToFixXML extends Exception {
		public NotPossibleToFixXML() {
			// do nothing
		}
	}

	/** decode objects that have been serialized to xml.
	 * This method tries to fix xml that has been broken by some characters missing in the end.
	 * This has been found in some older DB during upgrade from EJBCA 3.4, and seemed to be due to 
	 * internationalized characters. This seemed to truncate the XML somehow, and here we try to handle that
	 * in a nice way.  
	 */
	private UserDataVO decodeXML(final String sXML, final boolean lastTry) {
		final byte baXML[];
		try {
			baXML = sXML.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new EJBException(e);
		}
		final XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(baXML));
		final UserDataVO useradmindata;
		try {
			useradmindata  = (UserDataVO) decoder.readObject();
		} catch( Throwable t ) {
			// try to repair the end of the XML string.
			// this will only succeed if a limited number of chars is lost in the end of the string
			// note that this code will not make anything worse and that it will not be run if the XML can be encoded.
			// 
			try {
				if ( lastTry ) {
					return null;
				}
				final String sFixedXML = FixEndOfBrokenXML.fixXML(sXML, "string", "</void></object></java>");
				if ( sFixedXML==null ) {
					throw new NotPossibleToFixXML();					
				}
				final UserDataVO userDataVO = decodeXML(sFixedXML, true);
				if ( userDataVO==null ) {
					throw new NotPossibleToFixXML();
				}
				storeUserDataVO(userDataVO); // store it right so it does not have to be repaired again.
				log.warn(printUserDataVOXML("XML has been repaired. Trailing tags fixed. DB updated with correct XML.", sXML));
				return userDataVO;
			} catch ( NotPossibleToFixXML e ) {
				log.error(printUserDataVOXML("Not possible to decode UserDataVO. No way to fix the XML.", sXML), t);
				return null;
			}
		} finally {
			decoder.close();
		}
		if (log.isTraceEnabled() ) {
			log.trace(printUserDataVOXML("Successfully decoded UserDataVO XML.",sXML));
		}
		/* Code that fixes broken XML that has actually been parsed. It seems that the decoder is not checking for the java end tag.
		 * Currently this is left out in order to not mess with working but broken XML.
		if ( sXML.indexOf("<java")>0 && sXML.indexOf("</java>")<0 ) {
			storeUserDataVO(useradmindata); // store it right				
		}
		 */
		return useradmindata;
	}
	private String printUserDataVOXML(String sComment, String sXML) {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		pw.println(sComment);
		pw.println("XMLDATA start on next line:");
		pw.print(sXML);
		pw.println("| end of XMLDATA. The char before '|' was the last XML.");
		pw.println();
		pw.println("Issuer DN: "+getIssuerDN());
		pw.println("Serial #"+getSerialNumber());
		pw.println("User name: "+getUsername());
		pw.println("Certificate fingerprint: "+getFingerprint());
		pw.println();
		return sw.toString();
	}
    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a request data at the time the certificate was issued.
     * 
     * @param incert the certificate issued
     * @param UserDataVO, the data used to issue the certificate. 
     *
     * @return primary key
     * @ejb.create-method
     */
    public CertReqHistoryDataPK ejbCreate(Certificate incert, UserDataVO useradmindata)
        throws CreateException {
        // Extract fields to store with the certificate.
        String fingerprint = CertTools.getFingerprintAsString(incert);
        setFingerprint(fingerprint);
        setIssuerDN(CertTools.getIssuerDN(incert));
        if (log.isDebugEnabled()) {
        	log.debug("Creating certreqhistory data, serial=" + CertTools.getSerialNumberAsString(incert) + ", issuer=" + getIssuerDN());
        }
        setSerialNumber(CertTools.getSerialNumber(incert).toString());
        setTimestamp(new Date().getTime());
                	
    	setUsername(useradmindata.getUsername());
    	storeUserDataVO(useradmindata);
        setRowVersion(0);
        return null;
    }
	private void storeUserDataVO(UserDataVO userDataVO) {
		try {
			// Save the user admin data in xml encoding.
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();

			final XMLEncoder encoder = new XMLEncoder(baos);
			encoder.writeObject(userDataVO);
			encoder.close();

			final String s = baos.toString("UTF-8");
			if (log.isDebugEnabled()) {
				log.debug(printUserDataVOXML("useradmindata:",s));
			}
	        setUserDataVO(s);
		} catch (UnsupportedEncodingException e) {
			throw new EJBException(e);
		}
	}
    /**
     * required method, does nothing
     *
     * @param incert certificate
     * @param UserDataVO, the data used to issue the certificate. 
     */
    public void ejbPostCreate(Certificate incert, UserDataVO useradmindata) {
        // Do nothing. Required.
    }
}
