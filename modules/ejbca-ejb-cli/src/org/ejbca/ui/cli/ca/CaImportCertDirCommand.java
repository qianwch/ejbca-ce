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

package org.ejbca.ui.cli.ca;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.FileTools;

/**
 * Imports certificate files to the database for a given CA
 *
 * @author Anders Rundgren
 * @version $Id$
 */
public class CaImportCertDirCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcertdir"; }
	public String getDescription() { return "Imports a directory with PEM encoded certficate file(s) to the database"; }
	
	int count;
	int redundant;
	int rejected;

    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		CryptoProviderTools.installBCProvider();
		if (args.length != 7) {
			usage();
			return;
		}
		try {
			String username_filter = args[1];
			String caname = args[2];
			String active = args[3];
			String certificate_dir = args[4];
			String eeprofile = args[5];
			String certificateprofile = args[6];				
			
			String password = "foo123";

			int status;
			if ("ACTIVE".equalsIgnoreCase(active)) {
				status = SecConst.CERT_ACTIVE;
			}
			else if ("REVOKED".equalsIgnoreCase(active)) {
				status = SecConst.CERT_REVOKED;
			}
			else {
				throw new Exception("Invalid certificate status.");
			}
			if (!username_filter.equalsIgnoreCase ("DN") &&
			    !username_filter.equalsIgnoreCase ("CN") &&
			    !username_filter.equalsIgnoreCase ("FILE")){
				throw new Exception ("Currently only DN, CN and FILE username-source are implemented");
			}
			
			File dir = new File(certificate_dir);
			if ( !dir.isDirectory() ) {
				throw new IOException ("'"+certificate_dir+"' is not a directory.");
			}
			File files[] = dir.listFiles();
			if ( files==null || files.length<1 ) {
				throw new IOException("No files in directory '"+"'. Nothing to do.");
			}
			CAInfo cainfo = getCAInfo(caname);
			X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
			String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			
			int endentityprofileid = SecConst.EMPTY_ENDENTITYPROFILE;
			if (eeprofile != null) {
				getLogger().debug("Searching for End Entity Profile " + eeprofile);
				endentityprofileid = getRaAdminSession().getEndEntityProfileId(getAdmin(), eeprofile);
				if (endentityprofileid == 0) {
					getLogger().error("End Entity Profile " + eeprofile + " doesn't exists.");
					throw new Exception("End Entity Profile '" + eeprofile + "' doesn't exists.");
				}
			}
			
			int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
			if (certificateprofile != null) {
				getLogger().debug("Searching for Certificate Profile " + certificateprofile);
				certificateprofileid = getCertificateStoreSession().getCertificateProfileId(getAdmin(), certificateprofile);
				if (certificateprofileid == SecConst.PROFILE_NO_PROFILE) {
					getLogger().error("Certificate Profile " + certificateprofile + " doesn't exists.");
					throw new Exception("Certificate Profile '" + certificateprofile + "' doesn't exists.");
				}
			}

			for( int i=0; i<files.length; i++ ) {
				String certfile = files[i].getCanonicalPath();
				performImport ((X509Certificate) loadcert(certfile),
					       status,
					       password,
					       endentityprofileid,
					       certificateprofileid,
					       cacert,
					       cainfo,
					       files[i].getName(),
					       issuer,
					       username_filter);
			}
			getLogger().info("\nSummary:\nImported " + count + " certificates");
			if (redundant > 0) {
				getLogger().info(redundant + " certificates were already in the database");
			}
			if (rejected > 0) {
				getLogger().info(rejected + " certificates were rejected because they did not belong to the CA");
			}
		}
		catch (Exception e) {
			getLogger().info("Error: " + e.getMessage());
			usage();
		}
		getLogger().trace("<execute()");
	}
	
	private void performImport(X509Certificate certificate,
			                   int status,
			                   String password,
			                   int endentityprofileid,
			                   int certificateprofileid,
			                   X509Certificate cacert,
			                   CAInfo cainfo,
			                   String file_name,
			                   String issuer,
			                   String username_filter) throws Exception{
		int type = SecConst.USER_ENDUSER;
		String fingerprint = CertTools.getFingerprintAsString(certificate);
		if (getCertificateStoreSession().findCertificateByFingerprint(getAdmin(), fingerprint) != null) {
			redundant++;
			getLogger ().info("Certificate '" + CertTools.getSerialNumberAsString(certificate) + "' is already present, file: " +file_name);
			return;
		}
		// Certificate has expired, but we are obviously keeping it for archival purposes
		if (CertTools.getNotAfter(certificate).compareTo(new java.util.Date()) < 0) {
			status = SecConst.CERT_ARCHIVED;
		}
		String username = username_filter.equalsIgnoreCase("FILE") ? 
				 file_name : CertTools.getSubjectDN(certificate);
		if (username_filter.equalsIgnoreCase("CN")) {
			String cn = CertTools.getPartFromDN(username, "CN");
			// Workaround for "difficult" certificates lacking CNs
			if (cn == null || cn.length () == 0) {
				getLogger ().info("Certificate '" + CertTools.getSerialNumberAsString(certificate) + "' lacks CN, DN used instead, file: " +file_name);
			} else {
				username = cn;
			}
		}
		
		// Check if username already exists.
		UserDataVO userdata = getUserAdminSession().findUser(getAdmin(), username);
		
		if (!cacert.getSubjectX500Principal().getName().equals(certificate.getIssuerX500Principal().getName())){
			getLogger().info("REJECTED, CA issuer mismatch, file: " + file_name);
			rejected++;
			return;
		}
		try {
			certificate.verify(cacert.getPublicKey());
		} catch (GeneralSecurityException gse) {
			getLogger().info("REJECTED, CA signature mismatch,file: " + file_name);
			rejected++;
			return;
		}
		
		String subjectAltName = CertTools.getSubjectAlternativeName(certificate);
	    String email = CertTools.getEMailAddress(certificate);				

		getLogger().debug("Loading/updating user " + username);
		if (userdata == null) {
			getUserAdminSession().addUser(getAdmin(),
					username, password,
					CertTools.getSubjectDN(certificate),
					subjectAltName, email,
					false,
					endentityprofileid,
					certificateprofileid,
					type,
					SecConst.TOKEN_SOFT_BROWSERGEN,
					SecConst.NO_HARDTOKENISSUER,
					cainfo.getCAId());
			getLogger().info("User '" + username + "' has been added.");
		}
		getUserAdminSession().changeUser(getAdmin(),
					username, password,
					CertTools.getSubjectDN(certificate),
					subjectAltName, email,
					false,
					endentityprofileid,
					certificateprofileid,
					type,
					SecConst.TOKEN_SOFT_BROWSERGEN,
					SecConst.NO_HARDTOKENISSUER,
					UserDataConstants.STATUS_GENERATED,
				    cainfo.getCAId());
		if (userdata != null){
			getLogger().info("User '" + username + "' has been updated.");
		}

		getCertificateStoreSession().storeCertificate(getAdmin(),
				certificate, username,
				fingerprint,
				SecConst.CERT_ACTIVE, type, certificateprofileid, null, new Date().getTime());

		if (status == SecConst.CERT_REVOKED){
			getUserAdminSession().revokeCert(getAdmin(),
				           certificate.getSerialNumber(),
				           issuer,
				           username, 
				           RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
		}
		getLogger().info("Certificate '" + CertTools.getSerialNumberAsString(certificate) + "' has been added.");
		count++;

	}

	protected void usage() {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <username-source> <caname> <status> <certificate dir> <endentityprofile> <certificateprofile>");
		getLogger().info(" Username-source: \"DN\" means use certificate's SubjectDN as username, \"CN\" means use certificate subject's common name as username and \"FILE\" means user the file's name as username");
		String existingCas = "";
		Collection cas = null;
		try {
			cas = getCAAdminSession().getAvailableCAs(getAdmin());
			Iterator iter = cas.iterator();
			while (iter.hasNext()) {
				int caid = ((Integer)iter.next()).intValue();
				CAInfo info = getCAAdminSession().getCAInfo(getAdmin(), caid);
				existingCas += (existingCas.length()==0?"":", ") + "\"" + info.getName() + "\"";
			}
		} catch (Exception e) {
			existingCas += "<unable to fetch available CA(s)>";
		}
		getLogger().info(" Available CAs: " + existingCas);
		getLogger().info(" Status: ACTIVE, REVOKED");
		getLogger().info(" Certificate dir: A directory where all files are PEM encoded certificates");
		String endEntityProfiles = "";
		try {
			Collection eps = getRaAdminSession().getAuthorizedEndEntityProfileIds(getAdmin());
			Iterator iter = eps.iterator();
			while (iter.hasNext()) {
				int epid = ((Integer)iter.next()).intValue();
				endEntityProfiles += (endEntityProfiles.length()==0?"":", ") + "\"" + getRaAdminSession().getEndEntityProfileName(getAdmin(), epid) + "\"";
			}
		}
		catch (Exception e) {
			endEntityProfiles += "<unable to fetch available end entity profiles>";
		}
		getLogger().info(" Available end entity profiles: " + endEntityProfiles);
		String certificateProfiles = "";
		try {
			Collection cps = getCertificateStoreSession().getAuthorizedCertificateProfileIds(getAdmin(), SecConst.CERTTYPE_ENDENTITY, cas);
			boolean first = true;
			Iterator iter = cps.iterator();
			while (iter.hasNext()) {
				int cpid = ((Integer)iter.next()).intValue();
				if (first) {
					first = false;
				} else {
					certificateProfiles += ", ";
				}
				certificateProfiles += (certificateProfiles.length()==0?"":", ") + "\"" + getCertificateStoreSession().getCertificateProfileName(getAdmin(), cpid) + "\"";
			}
		} catch (Exception e) {
			certificateProfiles += "<unable to fetch available certificate profile>";
		}
		getLogger().info(" Available certificate profiles: " + certificateProfiles);
	}
	
	/** Load a PEM encoded certificate from the specified file. */
	private Certificate loadcert(final String filename) throws Exception {
		try {
			final byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(filename), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
			return CertTools.getCertfromByteArray(bytes);
		} catch (IOException ioe) {
			throw new Exception("Error reading " + filename + ": " + ioe.toString());
		} catch (CertificateException ce) {
			throw new Exception(filename + " is not a valid X.509 certificate: " + ce.toString());
		} catch (Exception e) {
			throw new Exception("Error parsing certificate from " + filename + ": " + e.toString());
		}
	}
}
