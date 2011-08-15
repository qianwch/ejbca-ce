package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;
import org.hibernate.ObjectNotFoundException;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.InfoTypeAndValue;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.PBMParameter;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

public class NestedMessageContentTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(NestedMessageContentTest.class);
	
    private Admin admin;
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private CertificateProfileSession certProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    
    private int caid;
    private Certificate cacert;
    private String issuerDN;
	
	public NestedMessageContentTest(String arg0) {
		super(arg0);
		
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
        // Configure CMP for this test, we allow custom certificate serial numbers
    	CertificateProfile profile = new EndUserCertificateProfile();
    	try {
    		certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
		} catch (CertificateProfileExistsException e) {
			log.error("Could not create certificate profile.", e);
		}
        int cpId = certProfileSession.getCertificateProfileId(admin, "CMPTESTPROFILE");
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
        	eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
		} catch (EndEntityProfileExistsException e) {
			log.error("Could not create end entity profile.", e);
		}
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, "foo123");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");

        CryptoProviderTools.installBCProvider();
        
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;

        adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");

        if (adminca1 == null) {
            final Collection<Integer> caids;

            caids = caSession.getAvailableCAs(admin);
            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
                if(tmp != 0)	break;
            }
            caid = tmp;
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo;

        cainfo = caAdminSession.getCAInfo(admin, caid);

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
        
        issuerDN = cacert != null ? ((X509Certificate) cacert).getIssuerDN().getName() : "CN=AdminCA1,O=EJBCA Sample,C=SE";
		
	}

	public void test01ConstructNested() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createCrmfReq();
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
        	
    	org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
    	org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raSigner", "foo123", raKeys, nb, na);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(myPKIMessage);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        //final byte[] resp = sendCmpHttp(myPKIMessage.getDERObject().toASN1Object().getEncoded(), 200);
        // do not check signing if we expect a failure (sFailMessage==null)
        checkCmpResponseGeneral(resp, issuerDN, reqSubjectDN, cacert, crmfMsg.getHeader().getSenderNonce().getOctets(), crmfMsg.getHeader().getTransactionID().getOctets(), false, null);
   	}
	
	public void test02Verify() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		String reqSubjectDN = "CN=bogusSubjectNested";
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        
    	PKIMessage crmfMsg = createCrmfReq();
    	assertNotNull("Failed to create crmfMsg.", crmfMsg);
        	
    	org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
    	org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name(reqSubjectDN)), new GeneralName(new X509Name(((X509Certificate)cacert).getSubjectDN()
                   .getName())));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
        myPKIHeader.setSenderNonce(new DEROctetString(nonce));
        // TransactionId
        myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.addGeneralInfo(new InfoTypeAndValue(ASN1Sequence.getInstance(crmfMsg)));

        PKIBody myPKIBody = new PKIBody(crmfMsg, 20); // NestedMessageContent
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
		KeyPair raKeys = KeyTools.genKeys("1024", "RSA");
		createRACertificate("raSignerV", "foo123", raKeys, nb, na);
		signPKIMessage(myPKIMessage, raKeys);
            
            
        assertNotNull("Failed to create myPKIHeader", myPKIHeader);
        assertNotNull("myPKIBody is null", myPKIBody);
        assertNotNull("myPKIMessage is null", myPKIMessage);
        	
        NestedMessageContent nestedMsg = new NestedMessageContent(myPKIMessage);
        boolean verify = nestedMsg.verify();
        assertTrue("NestedMessageVerification faild.", verify);
		
	}
	
    public void testZZZCleanUp() throws Exception {
    	log.trace(">testZZZCleanUp");
    	boolean cleanUpOk = true;
    	
    	certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");
		try {
			userAdminSession.deleteUser(admin, "cmptest");
		} catch (NotFoundException e) {
			// A test probably failed before creating the entity
        	log.error("Failed to delete user \"cmptest\".");
        	cleanUpOk = false;
		}
        assertTrue("Unable to clean up properly.", cleanUpOk);
    	log.trace("<testZZZCleanUp");
    }
	
	private PKIMessage createCrmfReq() throws ObjectNotFoundException, InvalidKeyException, SignatureException, AuthorizationDeniedException, EjbcaException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, Exception {
		
		createUser("cmptest", "C=SE,O=PrimeKey,CN=cmptest", "foo123");
		
		String reqSubjectDN = "CN=bogusSubject";
		byte[] senderNonce = CmpMessageHelper.createSenderNonce();
		byte[] transactionID = CmpMessageHelper.createSenderNonce();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		assertNotNull(nb);
		assertNotNull(na);
		
		KeyPair keys = null;
		keys = KeyTools.genKeys("1024", "RSA");
        PKIMessage req = genCertReq(issuerDN, reqSubjectDN, keys, cacert, senderNonce, transactionID, false, null, nb.getDate(), na.getDate(), null);
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
		req.getHeader().setProtectionAlg(pAlg);		 
		signPKIMessageWithEECert(req, nb, na);
		assertNotNull(req);
		
		return req;
	}
	
	private void createRACertificate(String username, String password, KeyPair keys, org.bouncycastle.asn1.x509.Time notBefore, 
			org.bouncycastle.asn1.x509.Time notAfter) throws AuthorizationDeniedException, EjbcaException, CertificateException, FileNotFoundException,
			IOException, UserDoesntFullfillEndEntityProfile, ObjectNotFoundException, Exception {
        UserDataVO userdata = createUser(username, "CN="+username, password);
        Certificate racert = signSession.createCertificate(admin, username, password, keys.getPublic(), X509KeyUsage.digitalSignature|X509KeyUsage.keyCertSign, notAfter.getDate(), notBefore.getDate());
        
        Vector<Certificate> certCollection = new Vector<Certificate>();
        certCollection.add(racert);
        byte[] pemRaCert = CertTools.getPEMFromCerts(certCollection);
        
        String raCertPath = "/tmp/racerts";
        raCertPath = CmpConfiguration.getRaCertificatePath();
        String filename = raCertPath + "/" + username + ".pem";
        File file = new File(filename);
        assertNotNull(file);
        FileOutputStream fout = new FileOutputStream(file);
        fout.write(pemRaCert);
        fout.flush();
        fout.close();        
        
        userAdminSession.deleteUser(admin, username);

	}
	
	private void signPKIMessageWithEECert(PKIMessage msg, org.bouncycastle.asn1.x509.Time nb, org.bouncycastle.asn1.x509.Time na) throws NoSuchAlgorithmException, 
				AuthorizationDeniedException, EjbcaException, InvalidKeyException, SignatureException, NoSuchProviderException, UserDoesntFullfillEndEntityProfile,
				ObjectNotFoundException, InvalidAlgorithmParameterException, WaitingForApprovalException, Exception {
		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		UserDataVO userdata = createUser("testUSer", "CN=testUSer", "foo123");
		log.debug("create user testUser");
        Certificate eeextracert = signSession.createCertificate(admin, userdata.getUsername(), "foo123", keys.getPublic(), X509KeyUsage.digitalSignature|X509KeyUsage.keyCertSign, na.getDate(), nb.getDate());
		ByteArrayInputStream    bIn = new ByteArrayInputStream(eeextracert.getEncoded());
		ASN1InputStream         dIn = new ASN1InputStream(bIn);
		ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
        X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
		msg.addExtraCert(extraCert);
		signPKIMessage(msg, keys);

	}
	
	private void signPKIMessage(PKIMessage msg, KeyPair keys) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
		sig.initSign(keys.getPrivate());
		sig.update(msg.getProtectedBytes());
		byte[] eeSignature = sig.sign();			
		msg.setProtection(new DERBitString(eeSignature));	
	}

    private UserDataVO createUser(String username, String subjectDN, String password) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
            EjbcaException, Exception {
    	
        UserDataVO user = new UserDataVO(username, subjectDN, caid, null, username+"@primekey.se", SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            userAdminSession.addUser(admin, user, false);
            // usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            userAdminSession.changeUser(admin, user, false);
            userAdminSession.setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        
        return user;
        
    }
    

}
