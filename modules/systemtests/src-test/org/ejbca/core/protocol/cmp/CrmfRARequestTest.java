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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationProxySessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * @author tomas
 * @version $Id$
 */
public class CrmfRARequestTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestTest.class);

    final private static String PBEPASSWORD = "password";

    private String issuerDN;

    private int caid;
    final private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRARequestTest"));
    private X509Certificate cacert;

    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private ConfigurationSessionRemote configurationSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class);
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    private CertificateProfileSession certProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityAccessSession eeAccessSession = InterfaceCache.getEndEntityAccessSession();
    private GlobalConfigurationProxySessionRemote globalConfigurationProxySession = JndiHelper.getRemoteSession(GlobalConfigurationProxySessionRemote.class);
    private GlobalConfigurationSession globalConfSession = InterfaceCache.getGlobalConfigurationSession();
    private InternalCertificateStoreSessionRemote internalCertStoreSession = JndiHelper.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        super.setUp();

        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowExtensionOverride(true);
        // profile.setAllowCertSerialNumberOverride(true);
        try {
            certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        int cpId = certProfileSession.getCertificateProfileId("CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
        try {
            eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-;-");

        CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;

        adminca1 = caSession.getCAInfo(admin, "AdminCA1");

        if (adminca1 == null) {
            final Collection<Integer> caids;

            caids = caSession.getAvailableCAs(admin);

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
            Assert.assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo;

        cainfo = caSession.getCAInfo(admin, caid);

        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
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

    /**
     * @param userDN for new certificate.
     * @param keys key of the new certificate.
     * @param sFailMessage if !=null then EJBCA is expected to fail. The failure response message string is checked against this parameter.
     * @return X509Certificate the cert produced if test was successfull, null for a test that resulted in failure (can be expected if sFailMessage != null)
     * @throws Exception
     */
    private X509Certificate crmfHttpUserTest(String userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno, String sigAlg) throws Exception {

        // Create a new good user

        X509Certificate cert = null;
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, customCertSerno);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, sFailMessage == null, null, 
                                sigAlg);
            if (sFailMessage == null) {
                cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                    Assert.assertTrue(cert.getSerialNumber().toString(16) + " is not same as expected " + customCertSerno.toString(16), cert
                            .getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, FailInfo.BAD_REQUEST.hashCode());
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
            Assert.assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(userDN, cacert, resp);
        }
        return cert;
    }

    @Test
    public void test01CrmfHttpOkUser() throws Exception {
        final CAInfo caInfo = caSession.getCAInfo(admin, "AdminCA1");
        // make sure same keys for different users is prevented
        caInfo.setDoEnforceUniquePublicKeys(true);
        // make sure same DN for different users is prevented
        caInfo.setDoEnforceUniqueDistinguishedName(true);
        caAdminSessionRemote.editCA(admin, caInfo);

        final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key3 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key4 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String userName1 = "cmptest1";
        final String userName2 = "cmptest2";
        final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
        final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;
        String hostname = null;
        try {
            // check that several certificates could be created for one user and one key.
            crmfHttpUserTest(userDN1, key1, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            crmfHttpUserTest(userDN2, key2, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            // check that the request fails when asking for certificate for another user with same key.
            crmfHttpUserTest(
                    userDN2,
                    key1,
                    "User 'cmptest2' is not allowed to use same key as the user(s) 'cmptest1' is/are using.", null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            crmfHttpUserTest(
                    userDN1,
                    key2,
                    "User 'cmptest1' is not allowed to use same key as the user(s) 'cmptest2' is/are using.", null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            // check that you can not issue a certificate with same DN as another user.
            crmfHttpUserTest(
                    "CN=AdminCA1,O=EJBCA Sample,C=SE",
                    key3,
                    "User 'AdminCA1' is not allowed to use same subject DN as the user(s) 'SYSTEMCA' is/are using (even if CN postfix is used). See setting for 'Enforce unique DN' in Edit Certificate Authorities.", 
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

            hostname = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME);

            crmfHttpUserTest(
                    "CN=" + hostname + ",O=EJBCA Sample,C=SE",
                    key4,
                    "User 'localhost' is not allowed to use same subject DN as the user(s) 'tomcat' is/are using (even if CN postfix is used). See setting for 'Enforce unique DN' in Edit Certificate Authorities.", 
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        } finally {
            try {
                userAdminSession.deleteUser(admin, userName1);
            } catch (NotFoundException e) {
            }
            try {
                userAdminSession.deleteUser(admin, userName2);
            } catch (NotFoundException e) {
            }
            try {
                userAdminSession.deleteUser(admin, "AdminCA1");
            } catch (NotFoundException e) {
            }
            try {
                userAdminSession.deleteUser(admin, hostname);
            } catch (NotFoundException e) {
            }
        }
    }

    @Test
    public void test02NullKeyID() throws Exception {

        // Create a new good user

        String userDN = "CN=keyIDTestUser,C=SE";
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        
        final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
        final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, null, 567);
        Assert.assertNotNull(req);
        reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
        BigInteger serialnumber = cert.getSerialNumber();
        
        // Revoke the created certificate
        final PKIMessage con = genRevReq(issuerDN, userDN, serialnumber, cacert, nonce, transid, false);
        Assert.assertNotNull(con);
        PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, null, 567);
        final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
        final DEROutputStream outrev = new DEROutputStream(baorev);
        outrev.writeObject(revmsg);
        final byte[] barev = baorev.toByteArray();
        // Send request and receive response
        final byte[] resprev = sendCmpHttp(barev, 200);
        checkCmpResponseGeneral(resprev, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revstatus = checkRevokeStatus(issuerDN, serialnumber);
        Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);
        
    }

    @Test
    public void test03UseKeyID() throws Exception {

        GlobalConfiguration gc = globalConfSession.getCachedGlobalConfiguration();
        gc.setEnableEndEntityProfileLimitations(true);
        globalConfigurationProxySession.saveGlobalConfigurationRemote(roleMgmgToken, gc);
        
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "KeyId");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "KeyId");

        try {
            certProfileSession.removeCertificateProfile(admin, "CMPKEYIDTESTPROFILE");
            eeProfileSession.removeEndEntityProfile(admin, "CMPKEYIDTESTPROFILE");
        } catch(Exception e) {}

        
        
        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            certProfileSession.addCertificateProfile(admin, "CMPKEYIDTESTPROFILE", profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        
        int cpId = certProfileSession.getCertificateProfileId("CMPKEYIDTESTPROFILE");
        
        EndEntityProfile eep = new EndEntityProfile();
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
        eep.setValue(EndEntityProfile.DEFAULTCA, 0, "" + caid); //CertificateProfile.ANYCA
        eep.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);
        eep.addField(DnComponents.ORGANIZATION);
        eep.setRequired(DnComponents.ORGANIZATION, 0, true);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
        
        try {
            eeProfileSession.addEndEntityProfile(admin, "CMPKEYIDTESTPROFILE", eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        
        // Create a new user that does not fulfill the end entity profile

        String userDN = "CN=keyIDTestUser,C=SE";
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        
        try {
            userAdminSession.deleteUser(admin, "keyIDTestUser");
        } catch (NotFoundException e) {
            // NOPMD
        }
        try {
            userAdminSession.deleteUser(admin, "keyidtest2");
        } catch (NotFoundException e) {
            // NOPMD
        }

        try {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpFailMessage(resp, "Subject DN field 'ORGANIZATION' must exist.", CmpPKIBodyConstants.INITIALIZATIONRESPONSE, reqId, FailInfo.BAD_REQUEST.hashCode());


            // Create a new user that fulfills the end entity profile

            userDN = "CN=keyidtest2,O=org";
            final KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce2 = CmpMessageHelper.createSenderNonce();
            final byte[] transid2 = CmpMessageHelper.createSenderNonce();
            final int reqId2;

            final PKIMessage one2 = genCertReq(issuerDN, userDN, keys2, cacert, nonce2, transid2, true, null, null, null, null);
            final PKIMessage req2 = protectPKIMessage(one2, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

            reqId2 = req2.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req2);
            final ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
            final DEROutputStream out2 = new DEROutputStream(bao2);
            out2.writeObject(req2);
            final byte[] ba2 = bao2.toByteArray();
            // Send request and receive response
            final byte[] resp2 = sendCmpHttp(ba2, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp2, issuerDN, userDN, cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp2, reqId2);
            BigInteger serialnumber = cert.getSerialNumber();

            EndEntityInformation ee = eeAccessSession.findUser(admin, "keyidtest2");
            Assert.assertEquals("Wrong certificate profile", cpId, ee.getCertificateProfileId());

            // Revoke the created certificate and use keyid
            final PKIMessage con = genRevReq(issuerDN, userDN, serialnumber, cacert, nonce2, transid2, false);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200);
            checkCmpResponseGeneral(resprev, issuerDN, userDN, cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(issuerDN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);
        } finally {
            try {
                userAdminSession.deleteUser(admin, "keyIDTestUser");
            } catch (NotFoundException e) {
                // NOPMD
            }
            try {
                userAdminSession.deleteUser(admin, "keyidtest2");
            } catch (NotFoundException e) {
                // NOPMD
            }
        }        
    }

    /**
     * Send a CMP request with SubjectAltName containing OIDs that are not defined by Ejbca.
     * Expected to pass and a certificate containing the unsupported OIDs is returned.
     * 
     * @throws Exception
     */
    @Test
    public void test04UsingOtherNameInSubjectAltName() throws Exception {

        ASN1EncodableVector vec = new ASN1EncodableVector();
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(new DERObjectIdentifier(CertTools.UPN_OBJECTID));
        v.add(new DERTaggedObject(true, 0, new DERUTF8String( "foo@bar" )));
        DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
        
        v = new ASN1EncodableVector();
        v.add(new DERObjectIdentifier("2.5.5.5"));
        v.add(new DERTaggedObject(true, 0, new DERIA5String( "2.16.528.1.1007.99.8-1-993000027-N-99300011-00.000-00000000" )));
        // GeneralName gn = new GeneralName(new DERSequence(v), 0);
        gn = new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
        
        GeneralNames san = new GeneralNames(new DERSequence(vec));
        
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        Vector<X509Extension> values = new Vector<X509Extension>();
        Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
        dOut.writeObject(san);
        byte[] value = bOut.toByteArray();
        X509Extension sanext = new X509Extension(false, new DEROctetString(value));
        values.add(sanext);
        oids.add(X509Extensions.SubjectAlternativeName);
        X509Extensions exts = new X509Extensions(oids, values);
        
        String userDN = "CN=TestAltNameUser";
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        String fingerprint = null;
        
        try {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, exts, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            fingerprint = CertTools.getFingerprintAsString(cert);
            
        } finally {
            try {
                userAdminSession.revokeAndDeleteUser(admin, "TestAltNameUser", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            } catch (NotFoundException e) {}
            
            try{
                internalCertStoreSession.removeCertificate(fingerprint);
            } catch(Exception e) {}
        }    
        
    }
    
    @Test
    public void test06CrmfEcdsaCA() throws Exception {
        final String oldIssuerDN = issuerDN;
        final X509Certificate oldCaCert = cacert;
        try {
            createEllipticCurveDsaCa(admin);
            CAInfo caInfo = caSession.getCAInfo(admin, "TESTECDSA");
            updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "TESTECDSA");

            issuerDN = caInfo.getSubjectDN(); // Make sure this CA is used for the test
            cacert = (X509Certificate)caInfo.getCertificateChain().iterator().next();
            final KeyPair key1 = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
            final String userName1 = "cmptestecdsa1";
            final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
            try {
                // check that we can get a certificate from this ECDSA CA.
                X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null, X9ObjectIdentifiers.ecdsa_with_SHA1.getId());
                assertNotNull(cert);
                // Check that this was really signed using SHA256WithECDSA and that the users key algo is in there
                assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getSignatureAlgorithm(cert));
                // Keyspec we get back from AlgorithmTools.getKeySpecification seems to differ between OracleJDK and OpenJDK so we only check key type
                assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(cert.getPublicKey()));
            } finally {
                try {
                    userAdminSession.deleteUser(admin, userName1);
                } catch (NotFoundException e) {
                }
            }
        } finally {
            // Reset this test class as it was before this test
            issuerDN = oldIssuerDN;
            cacert = oldCaCert;
            updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "TestCA");
            removeTestCA("TESTECDSA");
        }
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        Assert.assertTrue("Unable to restore server configuration.", configurationSession.restoreConfiguration());
        // Remove test profiles
        certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");
        certProfileSession.removeCertificateProfile(admin, "CMPKEYIDTESTPROFILE");
        eeProfileSession.removeEndEntityProfile(admin, "CMPTESTPROFILE");
        eeProfileSession.removeEndEntityProfile(admin, "CMPKEYIDTESTPROFILE");
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
