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

package org.ejbca.core.model.services;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import org.cesecore.core.ejb.ca.store.CertificateProfileSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.services.ServiceDataSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the certificate expiration notifications.
 * 
 * @version $Id$
 */
public class CertificateExpireTest extends CaTestCase {

    private static final Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    private static final String CA_NAME = "CertExpNotifCA";
    private static final String USERNAME = "CertificateExpireTest";
    private static final String PASSWORD = "foo123";
    private int caid = getTestCAId(CA_NAME);

    private static final String CERTIFICATE_EXPIRATION_SERVICE = "CertificateExpirationService";

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private ServiceSessionRemote serviceSession = InterfaceCache.getServiceSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private ServiceDataSessionRemote serviceDataSession = InterfaceCache.getServiceDataSessionRemote();

    private X509Certificate cert;
    private CertificateInfo info;
    private String fingerprint;
    
    public CertificateExpireTest() {
        super();
    }

    public CertificateExpireTest(String name) {
        super(name);
    }

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA(CA_NAME);  
        // Create a new user
        userAdminSession.addUser(admin, USERNAME, PASSWORD, "C=SE,O=AnaTom,CN=" + USERNAME, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, caid);
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        cert = (X509Certificate) signSession.createCertificate(admin, USERNAME, PASSWORD, keys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        fingerprint = CertTools.getFingerprintAsString(cert);
        X509Certificate ce = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(admin, fingerprint);
        if(ce == null) {
            throw new Exception("Cannot find certificate with fp=" + fingerprint);
        }
        info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
        if (!fingerprint.equals(info.getFingerprint())) {
            throw new Exception("fingerprint does not match.");
        }
        if (!cert.getSerialNumber().equals(info.getSerialNumber())) {
            throw new Exception("serialnumber does not match.");
        }
        if (!CertTools.getIssuerDN(cert).equals(info.getIssuerDN())) {
            throw new Exception("issuerdn does not match.");
        }
        if (!CertTools.getSubjectDN(cert).equals(info.getSubjectDN())) {
            throw new Exception("subjectdn does not match.");
        }
        // The cert was just stored above with status INACTIVE
        if (!(SecConst.CERT_ACTIVE == info.getStatus())) {
            throw new Exception("status does not match.");
        }

    }

    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    @Test
    public void testExpireCertificate() throws Exception {
        long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
        // Create a new UserPasswordExpireService
        ServiceConfiguration config = new ServiceConfiguration();
        config.setActive(true);
        config.setDescription("This is a description");
        // No mailsending for this Junit test service
        config.setActionClassPath(NoAction.class.getName());
        config.setActionProperties(null);
        config.setIntervalClassPath(PeriodicalInterval.class.getName());
        Properties intervalprop = new Properties();
        // Run the service every 3:rd second
        intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
        intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        config.setIntervalProperties(intervalprop);
        config.setWorkerClassPath(CertificateExpirationNotifierWorker.class.getName());
        Properties workerprop = new Properties();
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid));
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);
        if (serviceSession.getService(admin, CERTIFICATE_EXPIRATION_SERVICE) == null) {
            serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
        }
        serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
        // The service will run... the cert should still be active after 2
        // seconds..
        Thread.sleep(2000);
        info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
        assertEquals("status dotes not match.", SecConst.CERT_ACTIVE, info.getStatus());
        // The service will run...We need some tolerance since timers cannot
        // be guaranteed to executed at the exact interval.
        Thread.sleep(3000);
        int tries = 0;
        while (info.getStatus() != SecConst.CERT_NOTIFIEDABOUTEXPIRATION && tries < 5) {
            Thread.sleep(500);
            info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
            tries++;
        }
        info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
        assertEquals("Status does not match.", SecConst.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
    }

    /**
     * Add a new user and an expire service. Test running on all CAs.
     * 
     */
    @Test
    public void testExpireCertificateWithAllCAs() throws Exception {
        long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
        // Create a new UserPasswordExpireService
        ServiceConfiguration config = new ServiceConfiguration();
        config.setActive(true);
        config.setDescription("This is a description");
        // No mailsending for this Junit test service
        config.setActionClassPath(NoAction.class.getName());
        config.setActionProperties(null);
        config.setIntervalClassPath(PeriodicalInterval.class.getName());
        Properties intervalprop = new Properties();
        // Run the service every 3:rd second
        intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
        intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        config.setIntervalProperties(intervalprop);
        config.setWorkerClassPath(CertificateExpirationNotifierWorker.class.getName());
        Properties workerprop = new Properties();
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
        //Here is the line that matters for this test
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, Integer.valueOf(SecConst.ALLCAS).toString());
        
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);
        if (serviceSession.getService(admin, CERTIFICATE_EXPIRATION_SERVICE) == null) {
            serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
        }
        serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
        // The service will run... the cert should still be active after 2
        // seconds..
        Thread.sleep(2000);
        info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
        assertEquals("status dotes not match.", SecConst.CERT_ACTIVE, info.getStatus());
        // The service will run...We need some tolerance since timers cannot
        // be guaranteed to executed at the exact interval.
        Thread.sleep(3000);
        int tries = 0;
        while (info.getStatus() != SecConst.CERT_NOTIFIEDABOUTEXPIRATION && tries < 5) {
            Thread.sleep(500);
            info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
            tries++;
        }
        info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
        assertEquals("Status does not match.", SecConst.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
    }
    
    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    @Test
    public void testExpireCertificateWithCertificateProfiles() throws Exception {
        final String certificateprofilename = "foo";
        certificateProfileSession.addCertificateProfile(admin, certificateprofilename, new CertificateProfile());
        try {
            //Modify the CA to use the Certificate Profile
            CAInfo caInfo = caAdminSession.getCAInfo(admin, caid);
            caInfo.setCertificateProfileId(certificateProfileSession.getCertificateProfileId(admin, certificateprofilename));
            caAdminSession.editCA(admin, caInfo);
            
            long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
            // Create a new UserPasswordExpireService
            ServiceConfiguration config = new ServiceConfiguration();
            config.setActive(true);
            config.setDescription("This is a description");
            // No mailsending for this Junit test service
            config.setActionClassPath(NoAction.class.getName());
            config.setActionProperties(null);
            config.setIntervalClassPath(PeriodicalInterval.class.getName());
            Properties intervalprop = new Properties();
            // Run the service every 3:rd second
            intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
            intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
            config.setIntervalProperties(intervalprop);
            config.setWorkerClassPath(CertificateExpirationNotifierWorker.class.getName());
            Properties workerprop = new Properties();
            workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
            workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
            // All CAs
            workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid));

            workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
            workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
            config.setWorkerProperties(workerprop);
            if (serviceSession.getService(admin, CERTIFICATE_EXPIRATION_SERVICE) == null) {
                serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
            }
            serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
            // The service will run... the cert should still be active after 2
            // seconds..
            Thread.sleep(2000);
            info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
            assertEquals("status dotes not match.", SecConst.CERT_ACTIVE, info.getStatus());
            // The service will run...We need some tolerance since timers cannot
            // be guaranteed to executed at the exact interval.
            Thread.sleep(3000);
            int tries = 0;
            while (info.getStatus() != SecConst.CERT_NOTIFIEDABOUTEXPIRATION && tries < 5) {
                Thread.sleep(500);
                info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
                tries++;
            }
            info = certificateStoreSession.getCertificateInfo(admin, fingerprint);
            assertEquals("Status does not match.", SecConst.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
        } finally {
            //Clean the certificate profile
            certificateProfileSession.removeCertificateProfile(admin, certificateprofilename);
        }
    }
    
    @After
    public void tearDown() {
        try {
            userAdminSession.deleteUser(admin, USERNAME);
        } catch (Exception e) {
            e.printStackTrace();
        }
        serviceSession.removeService(admin, CERTIFICATE_EXPIRATION_SERVICE);
        serviceDataSession.findById(4711);
        removeTestCA(CA_NAME);
    }
}
