package org.ejbca.core.protocol.cmp.authentication;

import com.novosec.pkix.asn1.cmp.PKIMessage;

public interface ICMPAuthenticationModule {
	
	public abstract boolean verify(PKIMessage msg);
	public abstract String getName();
	public abstract String getAuthenticationString();
	public abstract String getErrorMessage();

}