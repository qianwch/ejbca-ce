package org.ejbca.core.protocol.cmp;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.CertificateRequestSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;

public class NestedMessageContentHandler extends BaseCmpMessageHandler implements ICmpMessageHandler{

	private static final Logger LOG = Logger.getLogger(NestedMessageContentHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    
	private final CertificateStoreSession certificateStoreSession;
	private final UserAdminSession userAdminSession;
	private final CertificateRequestSession certificateRequestSession;
	private final SignSession signSession;

	public NestedMessageContentHandler(Admin admin, CAAdminSession caAdminSession, EndEntityProfileSession eeProfileSession, CertificateProfileSession certProfileSession, 
			CertificateStoreSession certSession, UserAdminSession userAdminSession, CertificateRequestSession certReqSession, SignSession signSession ) {
		super(admin, caAdminSession, eeProfileSession, certProfileSession);
		this.certificateStoreSession = certSession;
		this.userAdminSession = userAdminSession;
		this.certificateRequestSession = certReqSession;
		this.signSession = signSession;
	}
	
	@Override
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		
		IResponseMessage resp = null;
		if (msg instanceof NestedMessageContent) {
			//CrmfRequestMessage crmfMsg = (CrmfRequestMessage) msg.getHeader().getGeneralInfo(0).getInfoValue();
			CrmfRequestMessage crmfMsg = new CrmfRequestMessage(((NestedMessageContent) msg).getPKIMessage().getBody().getNested(), ((NestedMessageContent) msg).getIssuerDN(), true, null);
			CrmfMessageHandler crmfHandler = new CrmfMessageHandler(admin, caAdminSession, certificateProfileSession, certificateRequestSession, 
						endEntityProfileSession, signSession, userAdminSession, certificateStoreSession);
			resp = crmfHandler.handleMessage(crmfMsg);
		} else {
			final String errMsg = INTRES.getLocalizedMessage("cmp.errornocmrfreq");
			LOG.error(errMsg);
		}
		if (resp == null) {
			final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
			LOG.error(errMsg);
		}
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("<handleMessage");
		}
		return resp;
	}

}
