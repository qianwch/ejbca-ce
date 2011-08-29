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

package org.ejbca.core.protocol.cmp.authentication;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.passgen.NoLookOrSoundALikeENLDPasswordGenerator;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Check the authentication of the PKIMessage by verifying the signature of the administrator who sent the message
 * 
 * @version $Id$
 *
 */
public class EndEntityCertificateAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger log = Logger.getLogger(EndEntityCertificateAuthenticationModule.class);
    private static final InternalResources intres = InternalResources.getInstance();
	
	private String authenticationParameterCAName;
	private String password;
	private String errorMessage;
	
	private Admin admin;
	private CAAdminSession caSession;
	private CertificateStoreSession certSession;
	private AuthorizationSession authSession;
	private EndEntityProfileSession eeProfileSession;

	public EndEntityCertificateAuthenticationModule(String parameter) {
		this.authenticationParameterCAName = parameter;
		password = null;
		errorMessage = null;
		
		admin = null;
		caSession = null;
		certSession = null;
		authSession = null;
		eeProfileSession = null;
	}
	
	public void setSession(Admin adm, CAAdminSession caSession, CertificateStoreSession certSession, 
					AuthorizationSession authSession, EndEntityProfileSession eeprofSession) {
		this.admin = adm;
		this.caSession = caSession;
		this.certSession = certSession;
		this.authSession = authSession;
		this.eeProfileSession = eeprofSession;
	}
	
	
	public String getName() {
		return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
	}
	
	public String getAuthenticationString() {
		return this.password;
	}
	
	public String getErrorMessage() {
		return this.errorMessage;
	}
	
	@Override
	public boolean verify(PKIMessage msg) {
		
		//Check that there is a certificate in the extraCert field in msg
 		X509CertificateStructure extraCertStruct = msg.getExtraCert(0);
		if(extraCertStruct == null) {
			errorMessage = "There is no certificate in the extraCert field in the PKIMessage";
			log.info(errorMessage);
			return false;
		}
			
		//Check that the certificate in the extraCert field exists in the DB
		Certificate extracert = null;
		try {
			extracert = CertTools.getCertfromByteArray(extraCertStruct.getEncoded());
		} catch (CertificateException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			this.errorMessage = e.getLocalizedMessage();
		} catch (IOException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			this.errorMessage = e.getLocalizedMessage();
		}
		Certificate dbcert = certSession.findCertificateByFingerprint(admin, CertTools.getFingerprintAsString(extracert));
		if(dbcert == null) {
			errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
			if(log.isDebugEnabled()) {
				log.debug(errorMessage);
			}
			return false;
		}
			
		//Check that the extraCert is given by the right CA
		CAInfo ca = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
		if(!StringUtils.equals(CertTools.getIssuerDN(extracert), ca.getSubjectDN())) {
			errorMessage = "The End Entity certificate attached to the PKIMessage is not given by the CA \"" + this.authenticationParameterCAName + "\"";
			if(log.isDebugEnabled()) {
				log.debug(errorMessage);
			}
			return false;
		}
		
		//Check that the request sender is an authorized administrator
		try {
			if(!isAuthorized(extracert, msg, ca.getCAId())){
				errorMessage = "\"" + CertTools.getSubjectDN(extracert) + "\" is not an authorized administrator.";
				if(log.isDebugEnabled()) {
					log.debug(errorMessage);
				}
				return false;			
			}
		} catch (NotFoundException e1) {
			if(log.isDebugEnabled()) {
				log.debug(e1.getLocalizedMessage());
			}
			errorMessage = e1.getLocalizedMessage();
		}
		
		//Begin the verification process.
		//Verify the signature of msg using the public key of the certificate we found in the database
		try {
			final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
			sig.initVerify(dbcert.getPublicKey());
			sig.update(msg.getProtectedBytes());
			if(sig.verify(msg.getProtection().getBytes())) {
				password = genRandomPwd();
				return true;
			}
		} catch (InvalidKeyException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (NoSuchAlgorithmException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (NoSuchProviderException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		} catch (SignatureException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
			errorMessage = e.getLocalizedMessage();
		}
		return false;
	}

    private String genRandomPwd() {
    	NoLookOrSoundALikeENLDPasswordGenerator pwdGen = new NoLookOrSoundALikeENLDPasswordGenerator();
    	return pwdGen.getNewPassword(16, 16);
    }
    
    private boolean isAuthorized(Certificate cert, PKIMessage msg, int caid) throws NotFoundException {
    	CertificateInfo certInfo = certSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
    	String username = certInfo.getUsername();
    	Admin reqAdmin = new Admin(cert, username, CertTools.getEMailAddress(cert));    	
    	
        if (!authorizedToCA(reqAdmin, caid)) {
            errorMessage = intres.getLocalizedMessage("ra.errorauthca", Integer.valueOf(caid));
            if(log.isDebugEnabled()) {
            	log.error("Admin " + username + " is not authorized for CA " + caid);
            }
            return false;
        }
        
        int eeprofid = getUsedEndEntityProfileId(msg.getHeader().getSenderKID().toString());
        int tagnr = msg.getBody().getTagNo();
        if((tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST)) {
        
            if (!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.CREATE_RIGHTS)) {
            	errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
            	if(log.isDebugEnabled()) {
            		log.error(errorMessage);
            	}
                return false;
            }
            
        	if(!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.EDIT_RIGHTS)) {
        		errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
        		if(log.isDebugEnabled()) {
        			log.error(errorMessage);
        		}
                return false;
        	}
        	
        	if(!authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
        		errorMessage = "Administrator " + username + " is not authorized to create certificates.";
        		if(log.isDebugEnabled()) {
        			log.error(errorMessage);
        		}
                return false;
        	}
		} else if(tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
			
        	if(!authorizedToEndEntityProfile(reqAdmin, eeprofid, AccessRulesConstants.REVOKE_RIGHTS)) {
        		errorMessage = "Administrator " + username + " is not authorized to revoke.";
        		if(log.isDebugEnabled()) {
        			log.error(errorMessage);
        		}
                return false;
        	}
			
        	if(!authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
        		errorMessage = "Administrator " + username + " is not authorized to revoke End Entities";
        		if(log.isDebugEnabled()) {
        			log.error(errorMessage);
        		}
                return false;
        	}
        	
        }
        
        return true;

    }
    
    private boolean authorizedToCA(Admin admin, int caid) {
        boolean returnval = false;
        returnval = authSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
        if (!returnval) {
        	errorMessage = "Admin " + admin.getUsername() + " not authorized to resource " + AccessRulesConstants.CAPREFIX + caid; 
            log.info(errorMessage);
        }
        return returnval;
    }
    
    private boolean authorizedToEndEntityProfile(Admin admin, int profileid, String rights) {
        boolean returnval = false;
        if (profileid == SecConst.EMPTY_ENDENTITYPROFILE
                && (rights.equals(AccessRulesConstants.CREATE_RIGHTS) || rights.equals(AccessRulesConstants.EDIT_RIGHTS))) {
            if (authSession.isAuthorizedNoLog(admin, "/super_administrator")) {
                returnval = true;
            } else {
            	errorMessage = "Admin " + admin.getUsername() + " was not authorized to resource /super_administrator"; 
                log.info(errorMessage);
            }
        } else {
            returnval = authSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights)
                    && authSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
        return returnval;
    }

	private int getUsedEndEntityProfileId(final String keyId) throws NotFoundException {
		int ret = 0;
		String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
		if (StringUtils.equals(endEntityProfile, "KeyId")) {
			if (log.isDebugEnabled()) {
				log.debug("Using End Entity Profile with same name as KeyId in request: "+keyId);
			}
			endEntityProfile = keyId;
		} 
		ret = eeProfileSession.getEndEntityProfileId(admin, endEntityProfile);
		if (ret == 0) {
			errorMessage = "No end entity profile found with name: "+endEntityProfile;
			log.info(errorMessage);
			throw new NotFoundException(errorMessage);
		}
		return ret;
	}
}
