package org.ejbca.core.protocol.cmp.Authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
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
		try {
			UserDataVO userdata = userSession.findUserBySubjectDN(admin, req.getSubjectDN());
			CAInfo ca = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
			Collection<Certificate> certs = certSession.findCertificatesByUsername(this.admin, userdata.getUsername());
			Iterator<Certificate> itr = certs.iterator();
			Certificate cert;
			while(itr.hasNext()) {
				cert = itr.next();
				if(StringUtils.equals(ca.getSubjectDN(), CertTools.getIssuerDN(cert))) {
					Signature sig = Signature.getInstance(CertTools.getSignatureAlgorithm(cert), "BC");
					sig.initVerify(cert);
					//sig.update(protBytes);
					if(sig.verify(req.getPKIMessage().getProtectedBytes())) {
						String password = genRandomPwd();
						userdata.setPassword(password);
						userSession.changeUser(admin, userdata, true);
						return password;
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
		}
	
		return null;
	}

    private String genRandomPwd() {
    	NoLookOrSoundALikeENLDPasswordGenerator pwdGen = new NoLookOrSoundALikeENLDPasswordGenerator();
    	return pwdGen.getNewPassword(16, 16);
    }

}
