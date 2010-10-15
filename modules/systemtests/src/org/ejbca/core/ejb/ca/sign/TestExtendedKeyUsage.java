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

package org.ejbca.core.ejb.ca.sign;

import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.DuplicateKeyException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * Tests creating certificate with extended key usage.
 * 
 * Works similar to TestSignSession.
 *
 * @version $Id$
 */
public class TestExtendedKeyUsage extends TestCase {
    private static final Logger log = Logger.getLogger(TestExtendedKeyUsage.class);
    
    private static KeyPair rsakeys=null;
    private static int rsacaid = 0;    
    private final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

    /**
     * @param name name
     */
    public TestExtendedKeyUsage(String name) throws Exception {
        super(name);

        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        if (rsakeys == null) {
            rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
        // Add this again since it will be removed by the other tests in the batch..
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
        CAInfo inforsa = TestTools.getCAAdminSession().getCAInfo(admin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    /**
     * @throws Exception if an error occurs...
     */
    public void test01CodeSigning() throws Exception {
        TestTools.getCertificateStoreSession().removeCertificateProfile(admin,"EXTKEYUSAGECERTPROFILE");
        final EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        ArrayList list = new ArrayList();
        list.add("1.3.6.1.4.1.311.2.1.21"); // MS individual code signing
        list.add("1.3.6.1.4.1.311.2.1.22"); // MS commercial code signing
        certprof.setExtendedKeyUsage(list);
        TestTools.getCertificateStoreSession().addCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        final int fooCertProfile = TestTools.getCertificateStoreSession().getCertificateProfileId(admin,"EXTKEYUSAGECERTPROFILE");

        TestTools.getRaAdminSession().removeEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE");
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0,Integer.toString(fooCertProfile));
        TestTools.getRaAdminSession().addEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE", profile);
        final int fooEEProfile = TestTools.getRaAdminSession().getEndEntityProfileId(admin, "EXTKEYUSAGEEEPROFILE");

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic(), -1);
        assertNotNull("Failed to create certificate", cert);
        //log.debug("Cert=" + cert.toString());
        List ku = cert.getExtendedKeyUsage();
        assertEquals(2, ku.size());
        assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.21"));
        assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.22"));
    }

    /**
     * @throws Exception if an error occurs...
     */
    public void test02SSH() throws Exception {
        TestTools.getCertificateStoreSession().removeCertificateProfile(admin,"EXTKEYUSAGECERTPROFILE");
        final EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        ArrayList list = new ArrayList();
        certprof.setExtendedKeyUsage(list);
        TestTools.getCertificateStoreSession().addCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        final int fooCertProfile = TestTools.getCertificateStoreSession().getCertificateProfileId(admin,"EXTKEYUSAGECERTPROFILE");

        TestTools.getRaAdminSession().removeEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE");
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0,Integer.toString(fooCertProfile));
        TestTools.getRaAdminSession().addEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE", profile);
        final int fooEEProfile = TestTools.getRaAdminSession().getEndEntityProfileId(admin, "EXTKEYUSAGEEEPROFILE");

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic(), -1);
        assertNotNull("Failed to create certificate", cert);
        //log.debug("Cert=" + cert.toString());
        List ku = cert.getExtendedKeyUsage();
        assertNull(ku);

        // Now add the SSH extended key usages
        list.add("1.3.6.1.5.5.7.3.21"); // SSH client
        list.add("1.3.6.1.5.5.7.3.22"); // SSH server
        certprof.setExtendedKeyUsage(list);
        TestTools.getCertificateStoreSession().changeCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        createOrEditUser(fooCertProfile, fooEEProfile);
        cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic(), -1);
        assertNotNull("Failed to create certificate", cert);
        //log.debug("Cert=" + cert.toString());
        ku = cert.getExtendedKeyUsage();
        assertEquals(2, ku.size());
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.21")); 
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.22"));     
    }

    public void test99CleanUp() throws Exception {
        // Delete test end entity profile
        TestTools.getRaAdminSession().removeEndEntityProfile(admin, "EXTKEYUSAGECERTPROFILE");
        TestTools.getCertificateStoreSession().removeCertificateProfile(admin,"EXTKEYUSAGEEEPROFILE");
        // delete users that we know...
        try {        	
        	TestTools.getUserAdminSession().deleteUser(admin, "extkeyusagefoo");
        	log.debug("deleted user: foo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (Exception e) { /* ignore */ }
		TestTools.removeTestCA();
    }

	private void createOrEditUser(final int fooCertProfile,
			final int fooEEProfile) throws AuthorizationDeniedException,
			UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
			CADoesntExistsException, EjbcaException, RemoteException {
		// Make user that we know...
        boolean userExists = false;
        UserDataVO user = new UserDataVO("extkeyusagefoo","C=SE,O=AnaTom,CN=extkeyusagefoo",rsacaid,null,"foo@anatom.se",SecConst.USER_ENDUSER,fooEEProfile,fooCertProfile, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setStatus(UserDataConstants.STATUS_NEW);
        user.setPassword("foo123");
        try {
            TestTools.getUserAdminSession().addUser(admin, user, false);
            log.debug("created user: extkeyusagefoo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (RemoteException re) {
        	userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User extkeyusagefoo already exists, resetting status.");
            TestTools.getUserAdminSession().changeUser(admin, user, false);
            log.debug("Reset status to NEW");
        }
	}
    
}
