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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Message handler for certificate request confirmation message.
 * 
 * According to RFC 4210 4.2.2.2:
 *  "Where verification of the cert confirmation message fails, the RA/CA
 *   MUST revoke the newly issued certificate if it has been published or
 *   otherwise made available."
 * 
 * However, EJBCA does not keep track of the transaction and always responds
 * with a ResponseStatus.SUCCESS Certificate Confirmation ACK.
 * 
 * @author tomas
 * @version $Id$
 */
public class ConfirmationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(ConfirmationMessageHandler.class);
	private static final InternalResources INTRES = InternalResources.getInstance();
	
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	/** CA Session used to sign the response */
	private CaSession caSession;
	/** User Admin Session used to authenticate the request */
	private UserAdminSession userAdminSession;
	/** Certificate Store Session used to authenticate the request */
	private CertificateStoreSession certificateStoreSession;
	/** Authorization Session used to authenticate the request */
	private AuthorizationSession authorizationSession;
	
	public ConfirmationMessageHandler(final Admin admin, final CAAdminSession caAdminSession, final CaSession caSession, final EndEntityProfileSession endEntityProfileSession, 
					final CertificateProfileSession certificateProfileSession, final UserAdminSession userAdminSession, final CertificateStoreSession certStoreSession, 
					final AuthorizationSession authSession) {
		super(admin, caAdminSession, endEntityProfileSession, certificateProfileSession);
		responseProtection = CmpConfiguration.getResponseProtection();
		this.caSession = caSession;
		this.userAdminSession = userAdminSession;
		this.certificateStoreSession = certStoreSession;
		this.authorizationSession = authSession;
	}
	public IResponseMessage handleMessage(final BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		int version = msg.getHeader().getPvno().getValue().intValue();
		IResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		if (version > 1) {
			// Try to find a HMAC/SHA1 protection key
			String owfAlg = null;
			String macAlg = null;
			int iterationCount = 1024;
			String cmpRaAuthSecret = null;	
			final String keyId = getSenderKeyId(msg.getHeader());
			if (keyId != null) {
				
				CAInfo caInfo;
				try {
					int eeProfileId = getUsedEndEntityProfileId(keyId);
					int caId = getUsedCaId(keyId, eeProfileId);
					caInfo = caAdminSession.getCAInfo(admin, caId);
				} catch (NotFoundException e) {
					LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
				} catch (EJBException e) {
					final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
					LOG.error(errMsg, e);			
					return null;	// Fatal error
				}
				
				//Verify the authenticity of the message
				VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(caInfo, admin, caAdminSession, userAdminSession, certificateStoreSession, authorizationSession, endEntityProfileSession);
				ICMPAuthenticationModule authenticationModule = null;
				if(messageVerifyer.verify(msg.getMessage())) {
					authenticationModule = messageVerifyer.getUsedAuthenticationModule();
				}
				if(authenticationModule == null) {
					String errMsg = "";
					if(errMsg != null) {
						errMsg = messageVerifyer.getErrorMessage();
					} else {
						errMsg = "Unrecognized authentication modules";
					}
					LOG.error(errMsg);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
				} else {
					if(authenticationModule instanceof HMACAuthenticationModule) {
						HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
						owfAlg = hmacmodule.getCmpPbeVerifyer().getOwfOid();
						macAlg = hmacmodule.getCmpPbeVerifyer().getMacOid();
					}
				}
				cmpRaAuthSecret = authenticationModule.getAuthenticationString();
				
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("Creating a PKI confirm message response");
			}
			final CmpConfirmResponseMessage cresp = new CmpConfirmResponseMessage();
			cresp.setRecipientNonce(msg.getSenderNonce());
			cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
			cresp.setSender(msg.getRecipient());
			cresp.setRecipient(msg.getSender());
			cresp.setTransactionId(msg.getTransactionId());
			// Set all protection parameters
			if (LOG.isDebugEnabled()) {
				LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
			}
			if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
				cresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
			 } else if (StringUtils.equals(responseProtection, "signature")) {
				try {
					// Get the CA that should sign the response
					final String cadn = CertTools.stringToBCDNString(msg.getRecipient().getName().toString());
				    CA ca = null;
				    if (cadn == null) {
				    	if (LOG.isDebugEnabled()) {
				    		LOG.debug("Using Default CA to sign Certificate Confirm message: "+CmpConfiguration.getDefaultCA());
				        }
				    	ca = caSession.getCA(admin, CmpConfiguration.getDefaultCA());
				    } else {
				    	if (LOG.isDebugEnabled()) {
				    		LOG.debug("Using recipient CA to sign Certificate Confirm message: '"+cadn+"', "+cadn.hashCode());
				    	}
				        ca = caSession.getCA(admin, cadn.hashCode());
				    }
				    if (ca != null) {
				    	final CATokenContainer catoken = ca.getCAToken();
				        cresp.setSignKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
				    } else {
				        if (LOG.isDebugEnabled()) {
				        	LOG.info("Could not find CA to sign Certificate Confirm, either from recipient ("+cadn+") or default ("+CmpConfiguration.getDefaultCA()+"). Not signing Certificate Confirm.");
				        }
				    }
				 } catch (CADoesntExistsException e) {
					 LOG.error("Exception during CMP response signing: ", e);
				 } catch (IllegalKeyStoreException e) {
					 LOG.error("Exception during CMP response signing: ", e);
				 } catch (CATokenOfflineException e) {
				     LOG.error("Exception during CMP response signing: ", e);
				 }
			}
			resp = cresp;
			try {
				resp.create();
			} catch (InvalidKeyException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchAlgorithmException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchProviderException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (SignRequestException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NotFoundException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (IOException e) {
				LOG.error("Exception during CMP processing: ", e);			
			}							
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Cmp1999 - Not creating a PKI confirm message response");
			}
		}
		return resp;
	}
}
