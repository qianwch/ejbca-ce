/**
 * 
 */
package org.cesecore.keys.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author lars
 *
 */
public class PublicCryptoToken implements CryptoToken {

	private static final long serialVersionUID = 1L;
	private int id;

	@Override
	public void init(Properties properties, byte[] data, int _id)
			throws Exception {
		this.id = _id;
		final PublicKey pk= CertificateFactory.getInstance( "X509" ).generateCertificate(new ByteArrayInputStream(data)).getPublicKey();
		KeyFactory.
		// TODO Auto-generated method stub

	}

	@Override
	public int getId() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void activate(char[] authenticationcode)
			throws CryptoTokenOfflineException,
			CryptoTokenAuthenticationFailedException {
		// TODO Auto-generated method stub

	}

	@Override
	public void deactivate() {
		// TODO Auto-generated method stub

	}

	@Override
	public PrivateKey getPrivateKey(String alias)
			throws CryptoTokenOfflineException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PublicKey getPublicKey(String alias)
			throws CryptoTokenOfflineException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Key getKey(String alias) throws CryptoTokenOfflineException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void deleteEntry(char[] authenticationcode, String alias)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, CryptoTokenOfflineException {
		// TODO Auto-generated method stub

	}

	@Override
	public void generateKeyPair(String keySpec, String alias)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			SignatureException, KeyStoreException, CertificateException,
			IOException, CryptoTokenOfflineException {
		// TODO Auto-generated method stub

	}

	@Override
	public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			SignatureException, KeyStoreException, CertificateException,
			IOException, CryptoTokenOfflineException {
		// TODO Auto-generated method stub

	}

	@Override
	public void generateKey(String algorithm, int keysize, String alias)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			KeyStoreException, CryptoTokenOfflineException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			SignatureException, CertificateException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException {
		// TODO Auto-generated method stub

	}

	@Override
	public String getSignProviderName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getEncProviderName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void reset() {
		// TODO Auto-generated method stub

	}

	@Override
	public int getTokenStatus() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Properties getProperties() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setProperties(Properties properties) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] getTokenData() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void testKeyPair(PrivateKey privateKey, PublicKey publicKey)
			throws InvalidKeyException, NoSuchProviderException {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] extractKey(String privKeyTransform,
			String encryptionKeyAlias, String privateKeyAlias)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			NoSuchProviderException, InvalidKeyException,
			IllegalBlockSizeException, CryptoTokenOfflineException,
			PrivateKeyNotExtractableException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] extractKey(String privKeyTransform,
			AlgorithmParameterSpec spec, String encryptionKeyAlias,
			String privateKeyAlias) throws NoSuchAlgorithmException,
			NoSuchPaddingException, NoSuchProviderException,
			InvalidKeyException, IllegalBlockSizeException,
			CryptoTokenOfflineException, PrivateKeyNotExtractableException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean doPermitExtractablePrivateKey() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Enumeration<String> getAliases() throws KeyStoreException,
			CryptoTokenOfflineException {
		// TODO Auto-generated method stub
		return null;
	}

}
