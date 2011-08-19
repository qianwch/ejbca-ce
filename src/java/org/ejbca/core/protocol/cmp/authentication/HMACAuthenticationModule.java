package org.ejbca.core.protocol.cmp.authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.core.protocol.cmp.CmpPbeVerifyer;

import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.CertTemplate;

/**
 * This class is used basically only to authenticate CrmfRequests
 * 
 * @author aveen
 *
 */
public class HMACAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger LOG = Logger.getLogger(HMACAuthenticationModule.class);
    private static final InternalResources INTRES = InternalResources.getInstance();

	
	private Admin admin;
	private UserAdminSession userAdminSession;
	
	private String raAuthSecret;
	private CAInfo cainfo;
	private String password;
	private String errorMessage;
		
	public HMACAuthenticationModule(String parameter) {
		this.raAuthSecret = parameter;
		this.cainfo = null;
		this.password = null;
		this.errorMessage = null;
		
		this.admin = null;
		this.userAdminSession = null;
	}

	public void setCaInfo(CAInfo cainfo) {
		this.cainfo = cainfo;
	}
	
	public void setSession(Admin adm, UserAdminSession userSession) {
		this.admin = adm;
		this.userAdminSession = userSession;
	}
	
	@Override
	public String getName() {
		return CmpConfiguration.AUTHMODULE_HMAC;
	}
	
	@Override
	public String getAuthenticationString() {
		return this.password;
	}
	
	@Override
	public String getErrorMessage(){
		return this.errorMessage;
	}
	
	@Override
	public boolean verify(PKIMessage msg) {
		
		if(msg == null) {
			LOG.error("No PKIMessage was found");
			return false;
		}

		CmpPbeVerifyer verifyer = null;
		try {	
			verifyer = new CmpPbeVerifyer(msg);
		} catch(IllegalArgumentException e) {
			if(LOG.isDebugEnabled()) {
				LOG.debug("Could not create CmpPbeVerifyer");
				LOG.debug(e.getLocalizedMessage());
			}
			return false;
		}
		
		if(verifyer == null) {
			if(LOG.isDebugEnabled()) {
				LOG.debug("Could not create CmpPbeVerifyer Object");
			}
			return false;
		}
			
		// If we use a globally configured shared secret for all CAs we check it right away
		if (this.raAuthSecret != null) {
			try {
				if(!verifyer.verify(this.raAuthSecret)) {
					errorMessage = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Global auth secret");
					LOG.info(errorMessage); // info because this is something we should expect and we handle it
					if (verifyer.getErrMsg() != null) {
						errorMessage = verifyer.getErrMsg();
						LOG.info(errorMessage);
					}
				} else {
					this.password = this.raAuthSecret;
				}
			} catch (InvalidKeyException e) {
				errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
				LOG.error(errorMessage, e);
			} catch (NoSuchAlgorithmException e) {
				errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
				LOG.error(errorMessage, e);
			} catch (NoSuchProviderException e) {
				errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
				LOG.error(errorMessage, e);
			}
		}

		// Now we know which CA the request is for, if we didn't use a global shared secret we can check it now!
		if (this.password == null) {
			//CAInfo caInfo = this.caAdminSession.getCAInfo(this.admin, caId);
			String cmpRaAuthSecret = null;  
			if (cainfo instanceof X509CAInfo) {
				cmpRaAuthSecret = ((X509CAInfo) cainfo).getCmpRaAuthSecret();
			}		
			if (StringUtils.isNotEmpty(cmpRaAuthSecret)) {
				try {
					if(!verifyer.verify(cmpRaAuthSecret)) {
						errorMessage = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Auth secret for CAId="+cainfo.getCAId());
						if (StringUtils.isEmpty(cmpRaAuthSecret)) {
							errorMessage += " Secret is empty";
						} else {
							errorMessage += " Secret fails verify";
						}
						LOG.info(errorMessage); // info because this is something we should expect and we handle it
						if (verifyer.getErrMsg() != null) {
							errorMessage = verifyer.getErrMsg();
						}
					} else {
						this.password = cmpRaAuthSecret;
					}
				} catch (InvalidKeyException e) {
					errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errorMessage, e);
				} catch (NoSuchAlgorithmException e) {
					errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errorMessage, e);
				} catch (NoSuchProviderException e) {
					errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errorMessage, e);
				}
			}
		}
			
		//If neither a global shared secret nor CA specific secret, we try to get the pre-registered endentity from the DB, and if there is a 
		//clear text password we check HMAC using this password.
		//Note that this should only work in client mode
		if((!CmpConfiguration.getRAOperationMode()) && this.password == null) {
			CertTemplate certTemp = getCertTemplate(msg);
			String subjectDN = certTemp.getSubject().toString();
			String issuerDN = certTemp.getIssuer().toString();
			if(LOG.isDebugEnabled()) {
				LOG.debug("Searching for an end entity with SubjectDN=\"" + subjectDN + "\" and issuerDN=\"" + issuerDN + "\"");
			}
			UserDataVO userdata = null;
			try {
				userdata = this.userAdminSession.findUserBySubjectAndIssuerDN(this.admin, subjectDN, issuerDN);
			} catch (AuthorizationDeniedException e) {
				LOG.info("No EndEntity with subjectDN \"" + subjectDN + "\" and issuer \"" + issuerDN + "\" could be found, wich is expected if the request had been send in Client mode.");
			}
			if(userdata != null) {
				String eepassword = userdata.getPassword();
				if(StringUtils.isNotEmpty(eepassword)) { 
					CmpPbeVerifyer cmpverify = new CmpPbeVerifyer(msg);
					try {
						if(cmpverify.verify(eepassword)) {
							this.password = eepassword;
						}
					} catch (InvalidKeyException e) {
						errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
						LOG.error(errorMessage, e);
					} catch (NoSuchAlgorithmException e) {
						errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
						LOG.error(errorMessage, e);
					} catch (NoSuchProviderException e) {
						errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
						LOG.error(errorMessage, e);
					}
				}
			} else {
				errorMessage = "End Entity with subjectDN \"" + subjectDN + "\" and issuerDN \"" + issuerDN + "\" was not found";
				LOG.error(errorMessage);
			}
		}
		return this.password != null;
	}

	
    
    private CertTemplate getCertTemplate(PKIMessage msg) {
    	int tagnr = msg.getBody().getTagNo();
    	if(tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST) {
    		return msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertTemplate();
    	}
    	if(tagnr==CmpPKIBodyConstants.CERTIFICATAIONREQUEST) {
    		return msg.getBody().getCr().getCertReqMsg(0).getCertReq().getCertTemplate();
    	}
    	if(tagnr==CmpPKIBodyConstants.REVOCATIONREQUEST) {
    		return msg.getBody().getRr().getRevDetails(0).getCertDetails();
    	}
    	return null;
    }

}
