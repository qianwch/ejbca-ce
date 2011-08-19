package org.ejbca.core.protocol.cmp.authentication;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERUTF8String;

import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMsg;

public class RegTokenPasswordExtractor {
	
	private static final Logger log = Logger.getLogger(RegTokenPasswordExtractor.class);
		
	public static String extractPassword(CertReqMsg req) {
		
		String ret = null;
		
		// If there is "Registration Token Control" in the CertReqMsg regInfo containing a password, we can use that
		AttributeTypeAndValue av = null;
		int i = 0;
		do {
			av = req.getRegInfo(i);
			if (av != null) {
				if (log.isTraceEnabled()) {
					log.trace("Found AttributeTypeAndValue (in CertReqMsg): "+av.getObjectId().getId());
				}
				if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
					final DEREncodable enc = av.getParameters();
					final DERUTF8String str = DERUTF8String.getInstance(enc);
					ret = str.getString();
					if (log.isDebugEnabled()) {
						log.debug("Found a request password in CRMF request regCtrl_regToken");
					}
				}
			}
			i++;
		} while ( (av != null) && (ret == null) );
		
		if (ret == null) {
			// If there is "Registration Token Control" in the CertRequest controls containing a password, we can use that
			// Note, this is the correct way to use the regToken according to RFC4211, section "6.1.  Registration Token Control"
			av = null;
			i = 0;
			do {
				av = req.getCertReq().getControls(i);
				if (av != null) {
					if (log.isTraceEnabled()) {
						log.trace("Found AttributeTypeAndValue (in CertReq): "+av.getObjectId().getId());
					}
					if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
						final DEREncodable enc = av.getParameters();
						final DERUTF8String str = DERUTF8String.getInstance(enc);
						ret = str.getString();
						if (log.isDebugEnabled()) {
							log.debug("Found a request password in CRMF request regCtrl_regToken");
						}
					}
				}
				i++;
			} while ( (av != null) && (ret == null) );
		}
		
		return ret;
	}

}
