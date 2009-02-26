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

package se.anatom.ejbca.ra;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.util.CertTools;


/**
 * Add a lot of users and a lot of certificates for each user 
 *
 * @version $Id: TestAddLotsofUsers.java 6668 2008-11-28 16:28:44Z jeklund $
 */
public class TestAddLotsofCertsPerUser extends TestCase {
    private static final Logger log = Logger.getLogger(TestAddLotsofCertsPerUser.class);

    private IUserAdminSessionRemote userAdminSession;
    private ISignSessionRemote signSession;
    private IRaAdminSessionRemote raAdminSession;
    private ICertificateStoreSessionRemote certificateStoreSession;
    private ICreateCRLSessionRemote createCrlSession;

    private static String baseUsername;
    private static int userNo = 0;
    private static final int caid = "CN=TEST".hashCode();
    private static KeyPair keys;

    /**
     * Creates a new TestAddLotsofUsers object.
     *
     * @param name name
     * @throws InvalidAlgorithmParameterException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     */
    public TestAddLotsofCertsPerUser(String name) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        super(name);
        CertTools.installBCProvider();
        keys = org.ejbca.util.KeyTools.genKeys("2048", "RSA");
		try {
			if (userAdminSession == null) {
				userAdminSession = ((IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class)).create();
			}
			if (signSession == null) {
				signSession = ((ISignSessionHome) ServiceLocator.getInstance().getRemoteHome(ISignSessionHome.JNDI_NAME, ISignSessionHome.class)).create();
			}
			if (raAdminSession == null) {
				raAdminSession = ((IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class)).create();
			}
			if (certificateStoreSession == null) {
				certificateStoreSession = ((ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class)).create();
			}
			if (createCrlSession == null) {
				createCrlSession = ((ICreateCRLSessionHome) ServiceLocator.getInstance().getRemoteHome(ICreateCRLSessionHome.JNDI_NAME, ICreateCRLSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
		}
    }

    protected void setUp() throws Exception {
        baseUsername = "lotsacertsperuser-" + System.currentTimeMillis() + "-";
    }

    protected void tearDown() throws Exception {
    }

    private String genUserName() throws Exception {
        userNo++;
        return baseUsername + userNo;
    }

    private String genRandomPwd() throws Exception {
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        return password;
    }

    /**
     * tests creating 10 users, each with 50 active, 50 revoked, 50 expired and 50 expired and "archived"
     *
     * @throws Exception on error
     */
    public void test01Create2000Users() throws Exception {
        log.trace(">test01Create2000Users()");
        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);
        final int NUMBER_OF_USERS = 10;
        final int CERTS_OF_EACH_KIND = 50;
        for (int i = 0; i < NUMBER_OF_USERS; i++) {
            String username = genUserName();
            String password = genRandomPwd();
            final String certificateProfileName = "testLotsOfCertsPerUser";
            final String endEntityProfileName = "testLotsOfCertsPerUser";
            CertificateProfile certificateProfile = new EndUserCertificateProfile();
            certificateProfile.setValidity(1);
            certificateProfile.setAllowValidityOverride(true);
            try {
            	certificateStoreSession.addCertificateProfile(administrator, certificateProfileName, certificateProfile);
            } catch (CertificateProfileExistsException e) {
            }

            int type = SecConst.USER_ENDUSER;
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            if (userAdminSession.findUser(administrator, username) != null) {
                System.out.println("Error : User already exists in the database.");
            }
        	UserDataVO userdata = new UserDataVO(username, CertTools.stringToBCDNString(dn), caid, subjectaltname, 
                    email, UserDataConstants.STATUS_NEW, type, profileid, certificatetypeid,
                    null,null, token, hardtokenissuerid, null);
        	userdata.setPassword(password);
        	userAdminSession.addUser(administrator, userdata, true);
            // Create some valid certs
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
            }
            // Create some revoked certs
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, ((X509Certificate) certificate).getSerialNumber(), ((X509Certificate) certificate).getIssuerDN().getName(),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            }

            int cid = certificateStoreSession.getCertificateProfileId(administrator, certificateProfileName);
            int eid = raAdminSession.getEndEntityProfileId(administrator, endEntityProfileName);
            if (eid == 0) {
                EndEntityProfile endEntityProfile = new EndEntityProfile(true);
                endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES , 0, "" + cid);
                endEntityProfile.setUse(EndEntityProfile.ENDTIME, 0, true);
                //endEntityProfile.setValue(EndEntityProfile.ENDTIME, 0, "0:0:10");
                raAdminSession.addEndEntityProfile(administrator, endEntityProfileName, endEntityProfile);
                eid = raAdminSession.getEndEntityProfileId(administrator, endEntityProfileName);
            }
            userdata.setEndEntityProfileId(eid);
            ExtendedInformation extendedInformation = userdata.getExtendedinformation();
            extendedInformation.setCustomData(EndEntityProfile.ENDTIME, "0:0:10");
            userdata.setExtendedinformation(extendedInformation);
            userdata.setCertificateProfileId(cid);
            userAdminSession.changeUser(administrator, userdata, true);
            // Create some certs that will be expired in one day
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, ((X509Certificate) certificate).getSerialNumber(), ((X509Certificate) certificate).getIssuerDN().getName(),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            }
            // Create some certs that will be expired in one day and set them to archived already
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, ((X509Certificate) certificate).getSerialNumber(), ((X509Certificate) certificate).getIssuerDN().getName(),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
                createCrlSession.setArchivedStatus(CertTools.getFingerprintAsString((X509Certificate) certificate));
            }
            raAdminSession.removeEndEntityProfile(administrator, endEntityProfileName);
            certificateStoreSession.removeCertificateProfile(administrator, certificateProfileName);
            if (i % 10 == 0) {
                log.debug("Created " + i + " users...");
            }
        }
        log.debug("Created 2000 users!");
        log.trace("<test01Create2000Users()");
    }
}
