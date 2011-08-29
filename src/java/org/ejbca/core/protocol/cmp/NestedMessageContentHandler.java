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

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.CertificateRequestSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Message handler for the NestedMessageContent format.
 * 
 * @version $Id$
 *
 */
public class NestedMessageContentHandler extends BaseCmpMessageHandler implements ICmpMessageHandler{

	private static final Logger LOG = Logger.getLogger(NestedMessageContentHandler.class);
    /** Internal localization of logs and errors */
    
	private final CertificateStoreSession certificateStoreSession;
	private final UserAdminSession userAdminSession;
	private final CertificateRequestSession certificateRequestSession;
	private final SignSession signSession;
	private final AuthorizationSession authorizationSession;

	public NestedMessageContentHandler(Admin admin, CAAdminSession caAdminSession, EndEntityProfileSession eeProfileSession, CertificateProfileSession certProfileSession, 
			CertificateStoreSession certSession, UserAdminSession userAdminSession, CertificateRequestSession certReqSession, SignSession signSession, 
			AuthorizationSession authSession) {
		super(admin, caAdminSession, eeProfileSession, certProfileSession);
		this.certificateStoreSession = certSession;
		this.userAdminSession = userAdminSession;
		this.certificateRequestSession = certReqSession;
		this.signSession = signSession;
		this.authorizationSession = authSession;
	}
	
	@Override
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		
		IResponseMessage resp = null;
		if (msg instanceof NestedMessageContent) {
	
			NestedMessageContent nestedMsg = (NestedMessageContent) msg;
			if(nestedMsg.verify()) {
				PKIMessage nested = ((NestedMessageContent) msg).getPKIMessage().getBody().getNested();
				int tagnr = nested.getBody().getTagNo();
			
				if((tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST) || (tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST)) {
			
					//CrmfRequestMessage crmfMsg = (CrmfRequestMessage) msg.getHeader().getGeneralInfo(0).getInfoValue();
					CrmfRequestMessage crmfMsg = new CrmfRequestMessage(nested, ((NestedMessageContent) msg).getIssuerDN(), true, null);
					CrmfMessageHandler crmfHandler = new CrmfMessageHandler(admin, caAdminSession, certificateProfileSession, certificateRequestSession, 
							endEntityProfileSession, signSession, userAdminSession, certificateStoreSession, authorizationSession);
					resp = crmfHandler.handleMessage(crmfMsg);
				} else if(tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
					BaseCmpMessage baseMsg = new GeneralCmpMessage(nested);
					RevocationMessageHandler revHandler = new RevocationMessageHandler(admin, certificateStoreSession, userAdminSession, caAdminSession, endEntityProfileSession, certificateProfileSession, authorizationSession);
					resp = revHandler.handleMessage(baseMsg);
				} else {
					LOG.error("Unsupported type of nested PKIMessage");
				}
			} else {
				final String errMsg = "Could not verify the RA";
				LOG.error(errMsg);				
				fillMessageDetails(msg);
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, errMsg);
			}
		} else {
			final String errMsg = "ICmpMessage is not a NestedMessageContent.";
			LOG.error(errMsg);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		}
		if (resp == null) {
			//final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
			final String errMsg = "Could not create a response message.";
			LOG.error(errMsg);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		}
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("<handleMessage");
		}
		return resp;
	}
	
	private void fillMessageDetails(BaseCmpMessage msg) {
		msg.setSender(msg.getMessage().getHeader().getSender());
		msg.setRecipient(msg.getMessage().getHeader().getRecipient());
		msg.setSenderNonce(msg.getMessage().getHeader().getSenderNonce().toString());
		msg.setRecipientNonce(msg.getMessage().getHeader().getRecipNonce().toString());
		
	}

}
