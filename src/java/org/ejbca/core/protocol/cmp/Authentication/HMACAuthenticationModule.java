package org.ejbca.core.protocol.cmp.Authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.cmp.CmpPbeVerifyer;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;

import com.novosec.pkix.asn1.cmp.PKIMessage;

public class HMACAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger log = Logger.getLogger(HMACAuthenticationModule.class);
	
	private PKIMessage pkiMessage;
	private Admin admin;
	private UserAdminSession userAdminSession;
	
	public HMACAuthenticationModule(String parameter) {}
	
	public void setPkiMessage(PKIMessage msg) {
		this.pkiMessage = msg;
	}
	
	public void setSession(Admin adm, UserAdminSession userSession) {
		this.admin = adm;
		this.userAdminSession = userSession;
	}
	
	@Override
	public String extractPassword(CrmfRequestMessage req) {
		
		try {
			String subjectDN = req.getSubjectDN();
			String issuerDN = req.getIssuerDN();
			log.debug("Searching for an end entity with SubjectDN=\"" + subjectDN + "\" and issuerDN=\"" + issuerDN + "\"");
			UserDataVO userdata = this.userAdminSession.findUserBySubjectAndIssuerDN(this.admin, subjectDN, issuerDN);
			if(userdata != null) {
				String eepassword = userdata.getPassword();
				CmpPbeVerifyer cmpverify = new CmpPbeVerifyer(this.pkiMessage);
				if((eepassword != null) && cmpverify.verify(eepassword)) {
					return eepassword;
				}
			}
		} catch (AuthorizationDeniedException e) {
			log.debug("Admin is not authorized. " + e.getLocalizedMessage());
		} catch (InvalidKeyException e) {
			log.debug("Incorrect password. " + e.getLocalizedMessage());
		} catch (NoSuchAlgorithmException e) {
			log.debug("Invalid algorithm. " + e.getLocalizedMessage());
		} catch (NoSuchProviderException e) {
			log.debug("The provider was not recognized. " + e.getLocalizedMessage());
		}
		
		return null;
	}

}
