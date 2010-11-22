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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * @author tomas
 * @version $Id$
 */
public class CrmfRARequestCustomSerialNoTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestCustomSerialNoTest.class);

    final private static String PBEPASSWORD = "password";

    final private static String issuerDN;

    final private static int caid;
    final private static Admin admin;
    final private static X509Certificate cacert;

    static {
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
        CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;
        try {
            adminca1 = TestTools.getCAAdminSession().getCAInfo(admin, "AdminCA1");
        } catch (RemoteException e) {
            throw new Error(e);
        }
        if (adminca1 == null) {
            final Collection<Integer> caids;
            try {
                caids = TestTools.getCAAdminSession().getAvailableCAs(admin);
            } catch (RemoteException e) {
                throw new Error(e);
            }
            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
            }
            caid = tmp;
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo;
        try {
            cainfo = TestTools.getCAAdminSession().getCAInfo(admin, caid);
        } catch (RemoteException e) {
            throw new Error(e);
        }
        Collection<X509Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<X509Certificate> certiter = certs.iterator();
            X509Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                try {
                    cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
                } catch (Exception e) {
                    throw new Error(e);
                }
            } else {
                cacert = null;
            }
        } else {
            log.error("NO CACERT for caid " + caid);
            cacert = null;
        }
        issuerDN = cacert != null ? cacert.getIssuerDN().getName() : "CN=AdminCA1,O=EJBCA Sample,C=SE";
    }

    public CrmfRARequestCustomSerialNoTest(String arg0) throws RemoteException, CertificateEncodingException, CertificateException {
        super(arg0);
        // Configure CMP for this test, we allow custom certificate serial numbers
    	CertificateProfile profile = new EndUserCertificateProfile();
    	//profile.setAllowCertSerialNumberOverride(true);
    	try {
			TestTools.getCertificateStoreSession().addCertificateProfile(admin, "CMPTESTPROFILE", profile);
		} catch (CertificateProfileExistsException e) {
			log.error("Could not create certificate profile.", e);
		}
        int cpId = TestTools.getCertificateStoreSession().getCertificateProfileId(admin, "CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false);	// Don't use field from "email" data
        try {
			TestTools.getRaAdminSession().addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
		} catch (EndEntityProfileExistsException e) {
			log.error("Could not create end entity profile.", e);
		}
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, "password");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO, "false");
    }

    /**
     * @param userDN
     *            for new certificate.
     * @param keys
     *            key of the new certificate.
     * @param sFailMessage
     *            if !=null then EJBCA is expected to fail. The failure response
     *            message string is checked against this parameter.
     * @return If it is a certificate request that results in a successful certificate issuance, this certificate is returned
     * @throws Exception
     */
    private X509Certificate crmfHttpUserTest(String userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno) throws Exception {

        X509Certificate ret = null;
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, customCertSerno);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, sFailMessage == null, null);
            if (sFailMessage == null) {
                ret = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                	assertTrue(ret.getSerialNumber().toString(16)+" is not same as expected "+customCertSerno.toString(16), ret.getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, FailInfo.BAD_REQUEST.hashCode());
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
            assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
            checkCmpPKIConfirmMessage(userDN, cacert, resp);
        }
        return ret;
    }

    public void test01CustomCertificateSerialNumber() throws Exception {
    	final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    	final String userName1 = "cmptest1";
    	final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
    	try {
    		// check that several certificates could be created for one user and one key.
    		long serno = RandomUtils.nextLong();
    		BigInteger bint = BigInteger.valueOf(serno);
            int cpId = TestTools.getCertificateStoreSession().getCertificateProfileId(admin, "CMPTESTPROFILE");
            // First it should fail because the CMP RA does not even look for, or parse, requested custom certificate serial numbers
            // Actually it does not fail here, but returns good answer
    		X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null);
    		assertFalse("SerialNumbers should not be equal when custom serialnumbers are not allowed.", bint.equals(cert.getSerialNumber()));
            // Second it should fail when the certificate profile does not allow serial number override
            // crmfHttpUserTest checks the returned serno if bint parameter is not null 
            TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO, "true");
    		crmfHttpUserTest(userDN1, key1, "Used certificate profile ('"+cpId+"') is not allowing certificate serial number override.", bint);
    		// Third it should succeed and we should get our custom requested serialnumber
            TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO, "true");
    		CertificateProfile cp = TestTools.getCertificateStoreSession().getCertificateProfile(admin, "CMPTESTPROFILE");
    		cp.setAllowCertSerialNumberOverride(true);
    		// Now when the profile allows serial number override it should work
    		TestTools.getCertificateStoreSession().changeCertificateProfile(admin, "CMPTESTPROFILE", cp);
    		crmfHttpUserTest(userDN1, key1, null, bint);
    	} finally {
    		try {
    			TestTools.getUserAdminSession().deleteUser(admin, userName1);
    		} catch (NotFoundException e) {}
    	}
    }

    public void testZZZCleanUp() throws Exception {
        TestTools.getConfigurationSession().restoreConfiguration();
        // Remove test profiles
        TestTools.getCertificateStoreSession().removeCertificateProfile(admin, "CMPTESTPROFILE");
        TestTools.getRaAdminSession().removeEndEntityProfile(admin, "CMPTESTPROFILE");
    }
}
