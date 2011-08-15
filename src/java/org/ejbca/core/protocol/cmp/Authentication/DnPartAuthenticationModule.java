package org.ejbca.core.protocol.cmp.Authentication;

import org.apache.log4j.Logger;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;
import org.ejbca.util.CertTools;

public class DnPartAuthenticationModule implements ICMPAuthenticationModule {

	private static final Logger log = Logger.getLogger(DnPartAuthenticationModule.class);

	private String authenticationParameter;
	
	public DnPartAuthenticationModule(String parameter) {
		this.authenticationParameter = parameter;
	}
	
	public String extractPassword(CrmfRequestMessage req) {
		String dnString = req.getSubjectDN();
		log.debug("Extractin password from SubjectDN: " + dnString);
		return CertTools.getPartFromDN(dnString, authenticationParameter);
	}
	
	public String getName() {
		return CmpConfiguration.AUTHMODULE_DN_PART_PWD;
	}
}
