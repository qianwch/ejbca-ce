package org.ejbca.core.protocol.cmp.Authentication;

import org.ejbca.core.protocol.cmp.CrmfRequestMessage;

public interface ICMPAuthenticationModule {
	
	public abstract String extractPassword(CrmfRequestMessage req);
	public abstract String getName();

}