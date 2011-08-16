package org.ejbca.core.protocol.cmp.authentication;

import org.ejbca.core.protocol.cmp.CrmfRequestMessage;

public interface ICMPAuthenticationModule {
	
	public abstract String extractPassword(CrmfRequestMessage req);
	public abstract String getName();

}