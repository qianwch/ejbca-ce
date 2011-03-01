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
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
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

/**
 * Imports a CRL file to the database.
 *
 * @author Anders Rundgren
 * @version $Id$
 */
public class CaImportCRLCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcrl"; }
	public String getDescription() { return "Imports a crl file (and update certificates) to the database"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		if (args.length != 4 || (!args[3].equalsIgnoreCase ("STRICT") && !args[3].equalsIgnoreCase("LENIENT"))){
			usage();
			return;
		}
		try {
			CryptoProviderTools.installBCProvider();
			String caname = args[1];
			String crl_file = args[2];
			boolean strict = args[3].equalsIgnoreCase ("STRICT");
			CAInfo cainfo = getCAInfo(caname);
			X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
	        String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			
	        X509CRL x509crl = (X509CRL) CertTools.getCertificateFactory().generateCRL(new FileInputStream (crl_file));
	        if (!x509crl.getIssuerX500Principal().getName().equals(cacert.getSubjectX500Principal().getName())){
	        	throw new IOException ("CRL wasn't issued by this CA");
	        }
	        x509crl.verify(cacert.getPublicKey());
	        int crl_no = 1;
	        byte[] extvalue = x509crl.getExtensionValue("2.5.29.20");
	        if (extvalue != null) {
		        DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
		        DERInteger crl_no_asn1 = (DERInteger) (new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
		        crl_no = crl_no_asn1.getPositiveValue().intValue();
            }
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
	        		continue;
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
				getLogger ().info("There were " + miss_count + " certificates missing in the database");
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
		getLogger().info("Usage: " + getCommand() + " <caname> <crl file> <STRICT|LENIENT>");
		getLogger().info("STRICT means that all certificates must be in the database\nand that the CRL must not already be in the database");
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
