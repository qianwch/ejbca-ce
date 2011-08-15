package org.ejbca.core.protocol.cmp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

import com.novosec.pkix.asn1.cmp.PKIBody;

public class EESignedCMPMessage extends BaseCmpMessage implements IRequestMessage{


	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(EESignedCMPMessage.class);
	
	private CrmfRequestMessage crmfMessage;
	private byte[] eesignature;
	
	private Admin admin;
	private CertificateStoreSession certSession;
	
	public EESignedCMPMessage(){}
	
	public EESignedCMPMessage(CrmfRequestMessage crmf, byte[] sig) {
		this.crmfMessage = crmf;
		this.eesignature = sig;
	}
	
	@Override
	public IResponseMessage createResponseMessage(Class responseClass,
			IRequestMessage req, Certificate cert, PrivateKey signPriv,
			String provider) {
		return crmfMessage.createResponseMessage(responseClass, req, cert, signPriv, provider);
	}

	@Override
	public String getCRLIssuerDN() {
		return crmfMessage.getCRLIssuerDN();
	}

	@Override
	public BigInteger getCRLSerialNo() {
		return crmfMessage.getCRLSerialNo();
	}

	@Override
	public int getErrorNo() {
		return crmfMessage.getErrorNo();
	}

	@Override
	public String getErrorText() {
		return crmfMessage.getErrorText();
	}

	@Override
	public String getIssuerDN() {
		return crmfMessage.getIssuerDN();
	}

	@Override
	public String getPassword() {
		return crmfMessage.getPassword();
	}

	@Override
	public String getPreferredDigestAlg() {
		return crmfMessage.getPreferredDigestAlg();
	}

	@Override
	public String getRequestAltNames() {
		return crmfMessage.getRequestAltNames();
	}

	@Override
	public String getRequestDN() {
		return crmfMessage.getRequestDN();
	}

	@Override
	public X509Extensions getRequestExtensions() {
		return crmfMessage.getRequestExtensions();
	}

	@Override
	public int getRequestId() {
		return crmfMessage.getRequestId();
	}

	@Override
	public byte[] getRequestKeyInfo() {
		return crmfMessage.getRequestKeyInfo();
	}

	@Override
	public PublicKey getRequestPublicKey() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return crmfMessage.getRequestPublicKey();
	}

	@Override
	public int getRequestType() {
		return crmfMessage.getRequestType();
	}

	@Override
	public Date getRequestValidityNotAfter() {
		return crmfMessage.getRequestValidityNotAfter();
	}

	@Override
	public Date getRequestValidityNotBefore() {
		return crmfMessage.getRequestValidityNotBefore();
	}

	@Override
	public X509Name getRequestX509Name() {
		return crmfMessage.getRequestX509Name();
	}

	@Override
	public BigInteger getSerialNo() {
		return crmfMessage.getSerialNo();
	}

	@Override
	public String getUsername() {
		return crmfMessage.getUsername();
	}

	@Override
	public boolean includeCACert() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean requireKeyInfo() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean verify() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		X509CertificateStructure extraCert = crmfMessage.getPKIMessage().getExtraCert(0);
		boolean ret = false;
		try {
			Certificate extraCertCert;
			extraCertCert = CertTools.getCertfromByteArray(extraCert.getEncoded());
		
			final Signature sig = Signature.getInstance(crmfMessage.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
			sig.initVerify(extraCertCert.getPublicKey());
			sig.update(crmfMessage.getMessage().getProtectedBytes());
			ret = sig.verify(eesignature);	
		} catch (CertificateException e) {
			log.error(e.getLocalizedMessage());
		} catch (IOException e) {
			log.error(e.getLocalizedMessage());
		} catch (SignatureException e) {
			log.error(e.getLocalizedMessage());
		}
		return ret;
	}
	
}
