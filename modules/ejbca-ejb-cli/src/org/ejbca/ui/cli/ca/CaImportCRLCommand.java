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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.FileTools;
import org.ejbca.util.cert.CrlExtensions;
import org.ejbca.util.keystore.KeyTools;

/**
 * Imports a CRL file to the database.
 *
 * @author Anders Rundgren
 * @version $Id$
 */
public class CaImportCRLCommand extends BaseCaAdminCommand {

	static final String STRICT_OP = "STRICT";
	static final String LENIENT_OP = "LENIENT";
	static final String ADAPTIVE_OP = "ADAPTIVE";
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcrl"; }
	public String getDescription() { return "Imports a crl file (and update certificates) to the database"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		if (args.length != 4 || (!args[3].equalsIgnoreCase (STRICT_OP) &&
				                 !args[3].equalsIgnoreCase(LENIENT_OP) &&
				                 !args[3].equalsIgnoreCase(ADAPTIVE_OP))){
			usage();
			return;
		}
		try {
			CryptoProviderTools.installBCProvider();
			String caname = args[1];
			String crl_file = args[2];
			boolean strict = args[3].equalsIgnoreCase (STRICT_OP);
			boolean adaptive = args[3].equalsIgnoreCase (ADAPTIVE_OP);
			CAInfo cainfo = getCAInfo(caname);
			X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
	        String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			
	        X509CRL x509crl = (X509CRL) CertTools.getCertificateFactory().generateCRL(new FileInputStream (crl_file));
	        if (!x509crl.getIssuerX500Principal().getName().equals(cacert.getSubjectX500Principal().getName())){
	        	throw new IOException ("CRL wasn't issued by this CA");
	        }
	        x509crl.verify(cacert.getPublicKey());
	        int crl_no = CrlExtensions.getCrlNumber(x509crl).intValue();
	        getLogger ().info("Processing CRL #" + crl_no);
	        		
	        Set<X509CRLEntry> revokedCerts = (Set<X509CRLEntry>) x509crl.getRevokedCertificates();
	        Iterator<X509CRLEntry> i = revokedCerts.iterator();
	        int miss_count = 0;
	        int revoked = 0;
	        int already_revoked = 0;
	        while ( i.hasNext() ) {
	        	X509CRLEntry entry = i.next();
	        	Date date = entry.getRevocationDate();
	        	BigInteger serialNr = entry.getSerialNumber();
	        	String serialHex = serialNr.toString(16).toUpperCase();
	        	String username = getCertificateStoreSession().findUsernameByCertSerno(getAdmin(), serialNr, issuer);
	        	if (username == null){
	        		getLogger ().info ("Certificate '"+ serialHex +"' missing in the database");
	        		if (strict) {
	        			throw new IOException ("Aborted!");
	        		}
	        		miss_count++;
	        		if (!adaptive){
	        			continue;
	        		}
	        		Date time = new Date ();              // time from which certificate is valid
	        		KeyPair key_pair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);		
	        		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	        		X500Principal              dnName = new X500Principal("CN=Dummy Missing in Imported CRL, serialNumber=" + serialHex);
	        		certGen.setSerialNumber(serialNr);
	        		certGen.setIssuerDN(cacert.getSubjectX500Principal());
	        		certGen.setNotBefore(time);
	        		certGen.setNotAfter(time);
	        		certGen.setSubjectDN(dnName);                       // note: same as issuer
	        		certGen.setPublicKey(key_pair.getPublic());
	        		certGen.setSignatureAlgorithm("SHA1withRSA");
	        		X509Certificate certificate = certGen.generate(key_pair.getPrivate(), "BC");
	        		String fingerprint = CertTools.getFingerprintAsString(certificate);
	        		username ="***MISSING DURING CRL IMPORT***";
	        		String password="foo123";
	        		UserDataVO userdata = getUserAdminSession().findUser(getAdmin(), username);
	        		getLogger().debug("Loading/updating user " + username);
	        		if (userdata == null) {
	        			getUserAdminSession().addUser(getAdmin(),
	        					username, password,
	        					CertTools.getSubjectDN(certificate),
	        					null, null,
	        					false,
	        					SecConst.EMPTY_ENDENTITYPROFILE,
	        					SecConst.CERTPROFILE_FIXED_ENDUSER,
	        					SecConst.USER_ENDUSER,
	        					SecConst.TOKEN_SOFT_BROWSERGEN,
	        					SecConst.NO_HARDTOKENISSUER,
	        					cainfo.getCAId());
	        			getLogger().info("User '" + username + "' has been added.");
	        		}
	        		getUserAdminSession().changeUser(getAdmin(),
	        					username, password,
	        					CertTools.getSubjectDN(certificate),
	        					null, null,
	        					false,
	        					SecConst.EMPTY_ENDENTITYPROFILE,
	        					SecConst.CERTPROFILE_FIXED_ENDUSER,
	        					SecConst.USER_ENDUSER,
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
	        				SecConst.CERT_ACTIVE, SecConst.USER_ENDUSER, SecConst.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
        			getLogger().info("Dummy certificate  '" + serialHex + "' has been stored.");
	        	}
	        	if (!strict && getCertificateStoreSession().isRevoked(issuer, serialNr)) {
		        	getLogger ().info("Certificate '" + serialHex +"' is already revoked");
		        	already_revoked++;
		        	continue;
	        	}
	        	getLogger ().info("Revoking '" + serialHex +"'");
	        	revoked++;
				getUserAdminSession().revokeCert(getAdmin(),
							serialNr,
							entry.getRevocationDate(),
				           issuer,
				           username, 
				           RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
	        }
        	String crl_summary = "CRL #" + crl_no + " stored in the database";
	        if (getCreateCRLSession().getLastCRLNumber(getAdmin(), issuer, false) < crl_no) {
	        	getCreateCRLSession().storeCRL(getAdmin(),
	        		                       x509crl.getEncoded(),
	        		                       CertTools.getFingerprintAsString(cacert), 
	        		                       crl_no,
	        		                       issuer,
	        		                       x509crl.getThisUpdate(),
	        		                       x509crl.getNextUpdate(),
	        		                       -1);
	        } else {
	        	crl_summary = "CRL #" + crl_no + " or higher is already in the database";
	        	if (strict) {
	        		throw new IOException (crl_summary);
	        	}
	        }
			getLogger ().info("\nSummary:\nRevoked " + revoked + " certificates");
			if (already_revoked > 0) {
				getLogger ().info(already_revoked + " certificates were already revoked");
			}
			if (miss_count > 0) {
				getLogger ().info("There were " + miss_count + (adaptive ? " dummy certificates added to" : " certificates missing in") +  " the database");
			}
        	getLogger ().info(crl_summary);
		}
		catch (Exception e) {
			getLogger().info("Error: " + e.getMessage());
			usage();
		}
		getLogger().trace("<execute()");

	}

	protected void usage() {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <caname> <crl file> <" + STRICT_OP + "|" + LENIENT_OP + "|" + ADAPTIVE_OP + ">");
		getLogger().info(STRICT_OP + " means that all certificates must be in the database\nand that the CRL must not already be in the database");
		getLogger().info(ADAPTIVE_OP + " means that missing certficates will be replaced by\ndummy certificates to cater for proper CRLs for missing certificates");
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
		getLogger().info(" Existing CAs: " + existingCas);
	}
	
}
