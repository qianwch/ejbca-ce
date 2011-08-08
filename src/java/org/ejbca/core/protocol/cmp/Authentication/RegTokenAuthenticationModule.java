package org.ejbca.core.protocol.cmp.Authentication;

import org.ejbca.core.protocol.cmp.CrmfRequestMessage;

public class RegTokenAuthenticationModule implements ICMPAuthenticationModule {
	
	public RegTokenAuthenticationModule(String parameter) {}
	
	public String extractPassword(CrmfRequestMessage req) {
		return req.getPassword();
	}
}
