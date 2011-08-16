package org.ejbca.core.protocol.cmp.authentication;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.passgen.NoLookOrSoundALikeENLDPasswordGenerator;

public class EndEntityCertificateAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger log = Logger.getLogger(EndEntityCertificateAuthenticationModule.class);
	
	private String authenticationParameterCAName;
	private Admin admin;
	private CAAdminSession caSession;
	private UserAdminSession userSession;
	private CertificateStoreSession certSession;

	public EndEntityCertificateAuthenticationModule(String parameter) {
		this.authenticationParameterCAName = parameter;
	}
	
	public void setSession(Admin adm, CAAdminSession caSession, UserAdminSession userSession, CertificateStoreSession certSession) {
		this.admin = adm;
		this.caSession = caSession;
		this.userSession = userSession;
		this.certSession = certSession;
	}
	
	@Override
	public String extractPassword(CrmfRequestMessage req) {
		String password = null;
		try {
			UserDataVO userdata = userSession.findUserBySubjectDN(admin, req.getSubjectDN());
			
			X509CertificateStructure extraCert = req.getPKIMessage().getExtraCert(0);
			Certificate extraCertCert = CertTools.getCertfromByteArray(extraCert.getEncoded());
			Certificate[] extraCertChain = {extraCertCert};

			CAInfo ca = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
			
			Collection<Certificate> certs = certSession.findCertificatesBySubjectAndIssuer(admin, CertTools.getSubjectDN(extraCertCert), ca.getSubjectDN()); //Username(this.admin, userdata.getUsername());
			Iterator<Certificate> itr = certs.iterator();
			Certificate cert;
			Certificate[] certChain = new Certificate[1];
			while(itr.hasNext()) {
				cert = itr.next();
				certChain[0] = cert;
				if(CertTools.compareCertificateChains(extraCertChain, certChain) /*StringUtils.equals(ca.getSubjectDN(), CertTools.getIssuerDN(extraCertCert))*/) {
					final Signature sig = Signature.getInstance(req.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
					sig.initVerify(cert.getPublicKey());
					sig.update(req.getPKIMessage().getProtectedBytes());
					if(sig.verify(req.getPKIMessage().getProtection().getBytes())) {
						password = genRandomPwd();
						userdata.setPassword(password);
						userSession.changeUser(admin, userdata, true);
					}
				}
			}
		} catch (NoSuchAlgorithmException e) {
			log.debug(e.getLocalizedMessage());
		} catch (NoSuchProviderException e) {
			log.debug("Unknown provider BouncyCastle. " + e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			log.debug(e.getLocalizedMessage());
		} catch (SignatureException e) {
			log.debug(e.getLocalizedMessage());
		} catch (AuthorizationDeniedException e) {
			log.debug(e.getLocalizedMessage());
		} catch (CADoesntExistsException e) {
			log.debug(e.getLocalizedMessage());
		} catch (UserDoesntFullfillEndEntityProfile e) {
			log.debug(e.getLocalizedMessage());
		} catch (WaitingForApprovalException e) {
			log.debug(e.getLocalizedMessage());
		} catch (EjbcaException e) {
			log.debug(e.getLocalizedMessage());
		} catch (CertificateException e) {
			log.debug(e.getLocalizedMessage());
		} catch (IOException e) {
			log.debug(e.getLocalizedMessage());
		}
	
		return password;
	}
	
	public String getName() {
		return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
	}

    private String genRandomPwd() {
    	NoLookOrSoundALikeENLDPasswordGenerator pwdGen = new NoLookOrSoundALikeENLDPasswordGenerator();
    	return pwdGen.getNewPassword(16, 16);
    }

}
