package org.ejbca.core.protocol.cmp.authentication;

import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;

public class RegTokenAuthenticationModule implements ICMPAuthenticationModule {
	
	public RegTokenAuthenticationModule(String parameter) {}
	
	public String extractPassword(CrmfRequestMessage req) {
		return req.getPassword();
	}
	
	public String getName() {
		return CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
	}
}
