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

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.crmf.CertReqMsg;

/**
 * Extracts password from the request DN of a CMRF request message
 *
 * @version $Id$
 *
 */
public class DnPartPasswordExtractor {

	private static final Logger log = Logger.getLogger(DnPartPasswordExtractor.class);

	/**
	 * Extracts the value of 'dnPart' from the subjectDN of the certificate request template.
	 * 
	 * @param req
	 * @param dnPart
	 * @return
	 */
	public static String extractPassword(final CertReqMsg req, final String dnPart) {
		String ret = null;
		final String dnString = req.getCertReq().getCertTemplate().getSubject().toString();
		if(log.isDebugEnabled()) {
			log.debug("Extracting password from SubjectDN \"" + dnString + "\" and DN part \"" + dnPart + "\"");
		}
		if (dnString != null) {
			ret = CertTools.getPartFromDN(dnString, dnPart);
		}
		
		return ret;
	}
}
