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

package org.ejbca.core.protocol.ocsp;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * See {@link ICertificateCache} to see what this is.
 *
 * @version $Id$
 *
 */
class CertificateCache implements ICertificateCache {

	/** Log4j instance for Base */
	private static final Logger log = Logger.getLogger(CertificateCache.class);

	/** Registry of certificates. HashMap is not synchronized, so when updating the HashMap, no read operations should be allowed
	 * The key in this HashMap is the fingerprint of the certificate. */
	final private Map<Integer, X509Certificate> certCache = new HashMap<Integer, X509Certificate>();
	/** Mapping from subjectDN to key in the certs HashMap. */
	final private Map<Integer, Integer> certsFromSubjectDN = new HashMap<Integer, Integer>();
	/** Mapping from OCSP CertificateID to key in the certs HashMap. */
	final private Map<Integer, Integer> certsFromOcspCertId = new HashMap<Integer, Integer>();
	/** Mapping from issuerDN to key in the certs HashMap. */
	final private Map<Integer, Set<Integer>> certsFromIssuerDN = new HashMap<Integer, Set<Integer>>();
	/** Mapping from subject key identifier to key in the certs HashMap. */
	final private Map<Integer, Integer> certsFromSubjectKeyIdentifier = new HashMap<Integer, Integer>();

	/** The interval in milliseconds on which new OCSP signing certs are loaded. */
	final private int m_valid_time = OcspConfiguration.getSigningCertsValidTime();

	/** A collection that can be used to JUnit test this class. Set responder type to OCSPUtil.RESPONDER_TYPE_TEST
	 * and give a Collection of CA certificate in the initialization properties.
	 */
	final private Collection<Certificate> testcerts;

	final private ICertStore certStore;

	/** Cache time counter, set and used by loadCertificates */
	private long m_certValidTo = 0;

	/** Admin for calling session beans in EJBCA */
	final private Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

	/** We need an object to synchronize around when rebuilding and reading the cache. When rebuilding the cache no thread
	 * can be allowed to read the cache, since the cache will be in an inconsistent state. In the normal case we want to use
	 * as fast objects as possible (HashMap) for reading fast.
	 */
	final private Lock rebuildlock = new ReentrantLock();

	/**
	 * @param _certStore The DB store to be used.
	 */
	CertificateCache(ICertStore _certStore) {
		// Default values
		this.testcerts = null;
		this.certStore = _certStore;
		loadCertificates();
	}

	/**
	 * @param _testcerts can be set to null or be a collection of test certificates
	 */
	CertificateCache(Collection<Certificate> _testcerts) {
		// Default values
		this.certStore = null;
		this.testcerts = _testcerts;
		loadCertificates();
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#findLatestBySubjectDN(java.lang.String)
	 */
	public X509Certificate findLatestByReadableSubjectDN(String subjectDN) {
		if (null == subjectDN) {
			throw new IllegalArgumentException();
		}

		loadCertificates(); // refresh cache?

		final X509Certificate ret;
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			final Integer key = this.certsFromSubjectDN.get(keyFromDNString(subjectDN));
			ret = key!=null ? this.certCache.get(key) : null;
		} finally {
			this.rebuildlock.unlock();
		}
		if (log.isDebugEnabled()) {
			if (ret != null) {
				log.debug("Found certificate from subjectDN in cache. SubjectDN='"+CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret));
			} else {
				log.debug("No certificate found in cache for subjectDN='"+subjectDN+"'.");
			}
		}
		return ret;
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#findLatestByHashedSubjectDN(java.lang.String)
	 */
	@Override
	public X509Certificate findLatestByHashedSubjectDN(String subjectDN) {
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			final Integer key = this.certsFromSubjectDN.get(keyFromHashString(subjectDN));
			return key!=null ? this.certCache.get(key) : null;
		} finally {
			this.rebuildlock.unlock();
		}
	}

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#findByHash(org.bouncycastle.ocsp.CertificateID)
	 */
	public X509Certificate findByOcspHash(CertificateID certId) {
		if (null == certId) {
			throw new IllegalArgumentException();
		}
		loadCertificates(); // refresh cache?

		// See if we have it in one of the certificate caches
		final Integer key =  keyFromCertificateID(certId);
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		try {
			this.rebuildlock.lock();
			final Integer fp = this.certsFromOcspCertId.get(key);
			if (fp == null) {
				if (log.isDebugEnabled()) {
					log.debug("Certificate not found from CertificateID in SHA1CertId map.");
				}
				return null;
			}
			final X509Certificate ret = this.certCache.get(fp);
			if (log.isDebugEnabled()) {
				log.debug("Found certificate from CertificateID in cache. SubjectDN='"+ CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret) + ", IssuerKeyHash=" + new String(Hex.encode(certId.getIssuerKeyHash())));
			}
			return ret;
		} finally {
			this.rebuildlock.unlock();
		}
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#forceReload()
	 */
	public void forceReload() {
		this.m_certValidTo = 0;
		loadCertificates();
	}

	/* private helper methods */

	private Integer keyFromBA(byte ba[]) {
		return new Integer(new BigInteger(ba).hashCode());
	}
	private Integer keyFromCertificateID(CertificateID certID) {
		return new Integer(new BigInteger(certID.getIssuerNameHash()).hashCode()^new BigInteger(certID.getIssuerKeyHash()).hashCode());
	}
	private Integer keyFromSubjectDNHash(X509Certificate cert) {
		final byte hash[] = CertTools.generateSHA1Fingerprint(cert.getSubjectX500Principal().getEncoded());
		log.info("The certificate with subject DN '"+CertTools.getSubjectDN(cert)+"' will be encoded to '"+new String(Base64.encode(hash))+"' when fetched from the VA.");
		return keyFromBA( hash );
	}
	private Integer keyFromIssuerDNHash(X509Certificate cert) {
		return keyFromBA( CertTools.generateSHA1Fingerprint(cert.getIssuerX500Principal().getEncoded()) );
	}
	private Integer keyFromHashString( String s ) {
		return keyFromBA( Base64.decode(s) );
	}
	private Integer keyFromDNString(String orgDN) {
		final String ejbcaDN = CertTools.stringToBCDNString(orgDN);
		return  keyFromBA( CertTools.generateSHA1Fingerprint(new X509Principal(ejbcaDN).getEncoded()) );
	}
	private Integer keyFromSubjectKeyId(X509Certificate cert) {
		return keyFromBA( KeyTools.createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier() );
	}
	/** Loads CA certificates but holds a cache so it's reloaded only every five minutes (configurable).
	 *
	 * We keep this method as synchronized, it should not take more than a few microseconds to complete if the cache does not have
	 * to be reloaded. If the cache must be reloaded, we must wait for it anyway to not have ConcurrentModificationException.
	 * We also only want one single thread to do the rebuilding.
	 */
	private void loadCertificates() {
		this.rebuildlock.lock();
		try {
			// Check if we have a cached collection that is not too old
			if (this.certCache != null && this.m_certValidTo > new Date().getTime()) {
				// The other HashMaps are always created as well, if this one is created
				return;
			}
			final Collection<Certificate> certs = findCertificatesByType(this.admin, SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ROOTCA, null);
			if (log.isDebugEnabled()) {
				log.debug("Loaded "+(certs == null ? "0":Integer.toString(certs.size()))+" ca certificates");
			}
			if ( certs==null ) {
				log.fatal("findCertificatesByType returns null. This should never happen!");
				return;
			}
			// Set up certsFromSubjectDN, certsFromSHA1CertId and certCache
			this.certCache.clear();
			this.certsFromSubjectDN.clear();
			this.certsFromOcspCertId.clear();
			this.certsFromIssuerDN.clear();
			this.certsFromSubjectKeyIdentifier.clear();
			final Iterator<Certificate> i = certs.iterator();
			while (i.hasNext()) {
				final Certificate tmp = i.next();
				if ( !(tmp instanceof X509Certificate) ) {
					log.debug("Not adding CA certificate of type: "+tmp.getType());
					continue;
				}
				final X509Certificate cert = (X509Certificate)tmp;
				final Integer certCachKey = new Integer(cert.hashCode());
				this.certCache.put(certCachKey, cert);
				final Integer subjectDNKey = keyFromSubjectDNHash(cert);
				// Check if we already have a certificate from this issuer in the HashMap.
				// We only want to store the latest cert from each issuer in this map
				final Integer pastCertCachKey = this.certsFromSubjectDN.get(subjectDNKey);
				final boolean isLatest;
				if ( pastCertCachKey!=null ) {
					final X509Certificate pastCert = this.certCache.get(pastCertCachKey);
					if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(pastCert))) {
						isLatest = true;
					} else {
						isLatest = false;
					}
				} else {
					isLatest = true;
				}
				if ( isLatest ) {
					this.certsFromSubjectDN.put(subjectDNKey, certCachKey);
					final Integer issuerDNKey = keyFromIssuerDNHash(cert);
					Set<Integer> sIssuer = this.certsFromIssuerDN.get(issuerDNKey);
					if ( sIssuer==null ) {
						sIssuer = new HashSet<Integer>();
						this.certsFromIssuerDN.put(issuerDNKey, sIssuer);
					}
					sIssuer.add(certCachKey);
				}
				this.certsFromSubjectKeyIdentifier.put(keyFromSubjectKeyId(cert), certCachKey);
				// We only need issuerNameHash and issuerKeyHash from certId
				try {
					final CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, cert, new BigInteger("1"));
					this.certsFromOcspCertId.put(keyFromCertificateID(certId), certCachKey);
				} catch (OCSPException e) {
					log.info(e);
				}
			} // while (i.hasNext()) {

			// Log what we have stored in the cache
			if (log.isDebugEnabled()) {
				final StringWriter sw = new StringWriter();
				final PrintWriter pw = new PrintWriter(sw,true);
				final Set<Integer> keys = this.certCache.keySet();
				final Iterator<Integer> iter = keys.iterator();
				pw.println("Found the following CA certificates :");
				while (iter.hasNext()) {
					final Integer key = iter.next();
					final Certificate cert = this.certCache.get(key);
					pw.print(CertTools.getSubjectDN(cert));
					pw.print(',');
					pw.println(CertTools.getSerialNumberAsString(cert));
				}
				log.debug(sw);
			}
			// If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
			this.m_certValidTo = this.m_valid_time>0 ? new Date().getTime()+this.m_valid_time : Long.MAX_VALUE;
		} finally {
			this.rebuildlock.unlock();
		}
	} // loadCertificates

	/**
	 *
	 * @param adm
	 * @param type
	 * @param issuerDN
	 * @return Collection of Certificate never null
	 */
	private Collection<Certificate> findCertificatesByType(Admin adm, int type, String issuerDN) {
		if ( this.certStore==null ) {
			// Use classes CertificateCacheStandalone or CertificateCacheInternal for non-test caches
			return this.testcerts;
		}
		return this.certStore.findCertificatesByType(adm, type, issuerDN);
	}
}
