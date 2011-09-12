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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
import java.io.File;
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
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Nested Message Content according to RFC4210. The PKI message is signed by an RA authority.
 * The PKIMessage body is another PKIMessage containing the request to be processed. 
 * 
 * @version $Id$
 *
 */
public class NestedMessageContent extends BaseCmpMessage implements IRequestMessage {

	private static final long serialVersionUID = 1L;
	
    private static final Logger log = Logger.getLogger(NestedMessageContent.class);
	
	private PKIMessage raSignedMessage;
	private PKIMessage originalMessage;
	
	/** Because PKIMessage is not serializable we need to have the serializable bytes save as well, so 
	 * we can restore the PKIMessage after serialization/deserialization. */ 
	private byte[] pkimsgbytes = null;

	public NestedMessageContent() {}
	
	public NestedMessageContent(PKIMessage pkiMsg) {
		this.raSignedMessage = pkiMsg;
		setPKIMessageBytes(pkiMsg);
		this.originalMessage = pkiMsg.getBody().getNested();
	}

	public PKIMessage getPKIMessage() {
		if (getMessage() == null) {
			try {
				setMessage(PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(pkimsgbytes)).readObject()));				
			} catch (IOException e) {
				log.error("Error decoding bytes for PKIMessage: ", e);
			}
		}
		return getMessage();
	}
	public void setPKIMessageBytes(final PKIMessage msg) {
		try {
			this.pkimsgbytes = msg.getDERObject().getEncoded();
		} catch (IOException e) {
			log.error("Error getting encoded bytes from PKIMessage: ", e);
		}
		setMessage(msg);
	}
	public PKIMessage getNestedPKIMessage() {
		return this.originalMessage;
	}
	
	@Override
	/**
	 * Verifies the signature of the pkimessage using the trusted RA certificate stored in cmpConfiguration.getRaCertificatePath()
	 * 
	 * @return True if the verification succeeds. False otherwise.
	 */
	public boolean verify() {
		boolean ret = false;
		try {
			Vector<X509Certificate> racerts = getRaCerts();
			Iterator<X509Certificate> itr = racerts.iterator();
			X509Certificate cert;
			Signature sig;
			while(itr.hasNext() && !ret) {
				cert = itr.next();
				sig = Signature.getInstance(cert.getSigAlgName(), "BC");
				sig.initVerify(cert.getPublicKey());
				sig.update(raSignedMessage.getProtectedBytes());
				ret = sig.verify(raSignedMessage.getProtection().getBytes());
			}
		} catch (CertificateException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		} catch (IOException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		} catch (NoSuchAlgorithmException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		} catch (NoSuchProviderException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		} catch (InvalidKeyException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		} catch (SignatureException e) {
			if(log.isDebugEnabled()) {
				log.debug(e.getLocalizedMessage());
			}
		}

		if(log.isDebugEnabled()) {
			log.debug("Verifying the NestedMessageContent returned " + ret);
		}

		return ret;
	}

	/**
	 * Reads the files in cmpConfiguration.getRaCertificatePath() and returns them as a list of certificates.
	 *  
	 * The certificate files should be PEM encoded.
	 * 
	 * @return A list of the certificates in cmpConfiguration.getRaCertificatePath(). 
	 * @throws CertificateException
	 * @throws IOException
	 */
	private Vector<X509Certificate> getRaCerts() throws CertificateException, IOException {
			
		Vector<X509Certificate> racerts = new Vector<X509Certificate>();
		String raCertsPath = CmpConfiguration.getRaCertificatePath();
		File raCertDirectory = new File(raCertsPath);
		String[] files = raCertDirectory.list();
		String filepath;
		if(files != null) {
			for(String certFile : files) {
				filepath = raCertsPath + "/" + certFile;
				racerts.add((X509Certificate) CertTools.getCertsFromPEM(filepath).iterator().next());
			}
		}		
		return racerts;
	}
	
	
	
	@Override
	public IResponseMessage createResponseMessage(Class responseClass,
			IRequestMessage req, Certificate cert, PrivateKey signPriv,
			String provider) {
		return null;
	}

	@Override
	public String getCRLIssuerDN() {
		return null;
	}

	@Override
	public BigInteger getCRLSerialNo() {
		return null;
	}

	@Override
	public int getErrorNo() {
		return 0;
	}

	@Override
	public String getErrorText() {
		return null;
	}

	@Override
	public String getIssuerDN() {
		return null;
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getPreferredDigestAlg() {
		return null;
	}

	@Override
	public String getRequestAltNames() {
		return null;
	}

	@Override
	public String getRequestDN() {
		return null;
	}

	@Override
	public X509Extensions getRequestExtensions() {
		return null;
	}

	@Override
	public int getRequestId() {
		return 0;
	}

	@Override
	public byte[] getRequestKeyInfo() {
		return null;
	}

	@Override
	public PublicKey getRequestPublicKey() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException {
		return null;
	}

	@Override
	public int getRequestType() {
		return 0;
	}

	@Override
	public Date getRequestValidityNotAfter() {
		return null;
	}

	@Override
	public Date getRequestValidityNotBefore() {
		return null;
	}

	@Override
	public X509Name getRequestX509Name() {
		return null;
	}

	@Override
	public BigInteger getSerialNo() {
		return null;
	}

	@Override
	public String getUsername() {
		return null;
	}

	@Override
	public boolean includeCACert() {
		return false;
	}

	@Override
	public boolean requireKeyInfo() {
		return false;
	}

	@Override
	public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {}
}
