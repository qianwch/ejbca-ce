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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;


/**
 * See {@link ICertificateCache} to see what this is.
 * 
 * @version $Id$
 * 
 */
class CertificateCache implements ICertificateCache {
	
    /** Log4j instance for Base */
    private static final Logger log = Logger.getLogger(CertificateCache.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Registry of certificates. HashMap is not synchronized, so when updating the HashMap, no read operations should be allowed 
     * The key in this HashMap is the fingerprint of the certificate. */
    final private Map<String, X509Certificate> certCache = new HashMap<String, X509Certificate>();
    /** Mapping from subjectDN to key in the certs HashMap. */
    final private Map<String, String> certsFromSubjectDN = new HashMap<String, String>();
    /** Mapping from CertificateID to key in the certs HashMap. */
    final private  Map<String, String> certsFromSHA1CertId = new HashMap<String, String>();
    
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
	public X509Certificate findLatestBySubjectDN(String subjectDN) {
		if (null == subjectDN) {
			throw new IllegalArgumentException();
		}

		loadCertificates(); // refresh cache?

		final X509Certificate ret;
		// Do the actual lookup
		final String dn = CertTools.stringToBCDNString(subjectDN);
		if (log.isDebugEnabled()) {
			log.debug("Looking for cert in cache: "+dn);    		
		}
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			final String key = this.certsFromSubjectDN.get(dn);
			if (key != null) {
				ret = this.certCache.get(key);
			} else {
                ret = null;
            }
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
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#findByHash(org.bouncycastle.ocsp.CertificateID)
	 */
    public X509Certificate findByHash(CertificateID certId) {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        loadCertificates(); // refresh cache?

        final X509Certificate ret;

        // See if we have it in one of the certificate caches
        final String key = new String(Hex.encode(certId.getIssuerNameHash()))+new String(Hex.encode(certId.getIssuerKeyHash()));
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
        try {
        	this.rebuildlock.lock();
            String fp = this.certsFromSHA1CertId.get(key);
            if (fp != null) {
            	ret = this.certCache.get(fp);
            	if (log.isDebugEnabled()) {
            		log.debug("Found certificate from CertificateID in cache. SubjectDN='"+ CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret) + ", IssuerKeyHash=" + new String(Hex.encode(certId.getIssuerKeyHash())));
            	}        		
            } else {
            	ret = findByHashNotInCache(certId);
            }
		} finally {
			this.rebuildlock.unlock();
		}
		return ret;
    }
    private X509Certificate findByHashNotInCache(CertificateID certId) {
    	X509Certificate ret = null;
    	// If we did not find it in the cache, lets look for it the hard way.
    	// This also requires a much larger synchronization lock
    	if (log.isDebugEnabled()) {
    		log.debug("Certificate not found from CertificateID in SHA1CertId map, looking for it the hard way.");
    	}        		
    	final Set<Map.Entry<String,X509Certificate>> certs = this.certCache.entrySet();
    	if (null == certs || certs.isEmpty()) {
    		// No certs in collection, no point in continuing
    		final String iMsg = intres.getLocalizedMessage("ocsp.certcollectionempty");
    		log.info(iMsg);
    	} else {
    		final Iterator<Map.Entry<String,X509Certificate>> iter = certs.iterator();
    		while (iter.hasNext()) {
    			final Map.Entry<String,X509Certificate> entry = iter.next();
    			final X509Certificate cert = entry.getValue();
    			// OCSP only supports X509 certificates
    			final X509Certificate cacert = cert;
    			try {
    				CertificateID issuerId = new CertificateID(certId.getHashAlgOID(), cacert, CertTools.getSerialNumber(cacert));
    				if (log.isDebugEnabled()) {
    					log.debug("Comparing the following certificate hashes:\n"
    					          + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
    					          + " CA certificate\n"
    					          + "      CA SubjectDN: '" + CertTools.getSubjectDN(cacert) + "'\n"
    					          + "      SerialNumber: '" + CertTools.getSerialNumberAsString(cacert) + "'\n"
    					          + " CA certificate hashes\n"
    					          + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
    					          + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n"
    					          + " OCSP certificate hashes\n"
    					          + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
    					          + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");
    				}
    				if ((issuerId.toASN1Object().getIssuerNameHash().equals(certId.toASN1Object().getIssuerNameHash()))
    						&& (issuerId.toASN1Object().getIssuerKeyHash().equals(certId.toASN1Object().getIssuerKeyHash()))) {
    					if (log.isDebugEnabled()) {
    						log.debug("Found matching CA-cert with:\n"
    						          + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
    						          + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n");                    
    					}
    					ret = cacert;
    					break; // don't continue the while loop if we found it
    				}
    			} catch (OCSPException e) {
    				String infoMsg = intres.getLocalizedMessage("ocsp.errorcomparehash", cacert.getIssuerDN());
    				log.info(infoMsg, e);
    			}        		
    		}
    		if (log.isDebugEnabled()) {
    			log.debug("Did not find matching CA-cert for:\n"
    			          + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
    			          + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");            
    		}        		
    	}
    	return ret;
    }
    
    /* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#forceReload()
	 */
    public void forceReload() {
    	this.m_certValidTo = 0;
    	loadCertificates();
    }
    
    /* private helper methods */
    
	/** Loads CA certificates but holds a cache so it's reloaded only every five minutes (configurable).
	 * 
     * We keep this method as synchronized, it should not take more than a few microseconds to complete if the cache does not have
     * to be reloaded. If the cache must be reloaded, we must wait for it anyway to not have ConcurrentModificationException.
     * We also only want one single thread to do the rebuilding.
     */
    private synchronized void loadCertificates() {
    	// Check if we have a cached collection that is not too old
    	if (this.certCache != null && this.m_certValidTo > new Date().getTime()) {
    		// The other HashMaps are always created as well, if this one is created
    		return;
    	}
    	
    	this.rebuildlock.lock();
    	try {
        	final Collection<Certificate> certs = findCertificatesByType(this.admin, SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ROOTCA, null);
        	if (log.isDebugEnabled()) {
        		log.debug("Loaded "+(certs == null ? "0":Integer.toString(certs.size()))+" ca certificates");        	
        	}
        	// Set up certsFromSubjectDN, certsFromSHA1CertId and certCache
        	this.certCache.clear();
        	this.certsFromSubjectDN.clear();
        	this.certsFromSHA1CertId.clear();
        	final Iterator<Certificate> i = certs.iterator();
        	while (i.hasNext()) {
        		final Certificate tmp = i.next();
        		if (tmp instanceof X509Certificate) {
            		final X509Certificate cert = (X509Certificate)tmp;
            		final String fp = CertTools.getFingerprintAsString(cert);
            		this.certCache.put(fp, cert);
            		final String subjectDN = CertTools.getSubjectDN(cert);
            		// Check if we already have a certificate from this issuer in the HashMap. 
            		// We only want to store the latest cert from each issuer in this map
            		final String lfp = this.certsFromSubjectDN.get(subjectDN);
            		if (lfp != null) {
                    	final X509Certificate pcert = this.certCache.get(lfp);
                    	if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(pcert))) {
                    		this.certsFromSubjectDN.put(subjectDN, fp);                    		
                    	}
            		} else {
                		this.certsFromSubjectDN.put(subjectDN, fp);                    		
            		}
            		// We only need issuerNameHash and issuerKeyHash from certId
            		try {
                		final CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, cert, new BigInteger("1"));
                		final String key = new String(Hex.encode(certId.getIssuerNameHash()))+new String(Hex.encode(certId.getIssuerKeyHash()));
                		this.certsFromSHA1CertId.put(key, fp);
            		} catch (OCSPException e) {
            			log.info(e);
            		}
        		} else {
        			log.debug("Not adding CA certificate of type: "+tmp.getType());
        		}
        	} // while (i.hasNext()) {
        	
        	// Log what we have stored in the cache 
        	if (log.isDebugEnabled()) {
        		final StringBuffer certInfo = new StringBuffer();
        		final Set<String> keys = this.certCache.keySet();
        		final Iterator<String> iter = keys.iterator();
        		while (iter.hasNext()) {
        			final String key = iter.next();
        			final Certificate cert = this.certCache.get(key);
        			certInfo.append(CertTools.getSubjectDN(cert));
        			certInfo.append(',');
        			certInfo.append(CertTools.getSerialNumberAsString(cert));
        			certInfo.append('\n');
        		}
        		log.debug("Found the following CA certificates : \n"+ certInfo.toString());
        	}
    	} finally {
    		this.rebuildlock.unlock();
    	}
    	// If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
    	this.m_certValidTo = this.m_valid_time>0 ? new Date().getTime()+this.m_valid_time : Long.MAX_VALUE;
    } // loadCertificates
    
    /* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ocsp.ICertificateCache#update(java.security.cert.Certificate)
	 */
    public void update(Certificate cert) {
		if (cert != null && cert instanceof X509Certificate) {
			this.rebuildlock.lock(); 
			try {
	    		String fp = CertTools.getFingerprintAsString(cert);
	    		this.certCache.put(fp, (X509Certificate)cert);
	    	} finally {
	    		this.rebuildlock.unlock();
	    	}
		}
    }
    
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
