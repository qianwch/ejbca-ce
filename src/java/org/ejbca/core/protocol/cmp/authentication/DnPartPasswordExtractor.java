package org.ejbca.core.protocol.cmp.authentication;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.crmf.CertReqMsg;

public class DnPartPasswordExtractor {

	private static final Logger log = Logger.getLogger(DnPartPasswordExtractor.class);

	public static String extractPassword(CertReqMsg req, String dnPart) {
		String ret = null;
		String dnString = req.getCertReq().getCertTemplate().getSubject().toString();
		if(log.isDebugEnabled()) {
			log.debug("Extracting password from SubjectDN \"" + dnString + "\" and DN part \"" + dnPart + "\"");
		}
		if(dnString != null) {
			ret = CertTools.getPartFromDN(dnString, dnPart);
		}
		
		return ret;
	}
}
