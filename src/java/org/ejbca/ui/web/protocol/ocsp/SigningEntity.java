package org.ejbca.ui.web.protocol.ocsp;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.protocol.ocsp.OCSPUtil;

/**
 * An object of this class is used to sign OCSP responses for certificates belonging to one CA.
 */
class SigningEntity {
    /**
     * The certificate chain with the CA of the signer on top.
     */
    final private List<X509Certificate> chain;
    /**
     * The signing key.
     */
    final PrivateKeyContainer keyContainer;
    /**
     * The provider to be used when signing.
     */
    final ProviderHandler providerHandler;
    /**
     * The object is ready to sign after this constructor has been called.
     * @param c Certificate chain with CA for which OCSP requests should be signed on top.
     * @param f The signing key.
     * @param ph The provider.
     */
    SigningEntity(List<X509Certificate> c, PrivateKeyContainer f, ProviderHandler ph) {
        this.chain = c;
        this.keyContainer = f;
        this.providerHandler = ph;
    }
    /**
     * Get certificate chain. With signing certificate on top.
     * @return The chain.
     */
    X509Certificate[] getCertificateChain() {
        return getCertificateChain(this.keyContainer.getCertificate());
    }
    /**
     * Add certificate on top of certificate chain.
     * @param entityCert The certificate to be on top.
     * @return The certificate chain.
     */
    private X509Certificate[] getCertificateChain(final X509Certificate entityCert) {
        final List<X509Certificate> entityChain = new ArrayList<X509Certificate>(this.chain);
        if ( entityCert==null ) {
            StandAloneSession.m_log.error("CA "+this.chain.get(0).getSubjectDN()+" has no signer.");
            return null;
        }
        entityChain.add(0, entityCert);
        return entityChain.toArray(new X509Certificate[0]);
    }
    /**
     * Initiates key key renewal.
     * @param caid The EJBCA CA id for the CA.
     */
    void init(int caid) {
        this.providerHandler.addKeyContainer(this.keyContainer);
        this.keyContainer.init(this.chain, caid);
    }
    /**
     * Stops key renewal.
     */
    void shutDown() {
        this.keyContainer.destroy();
    }
    /**
     * Signs a OCSP response.
     * @param request The response to be signed.
     * @return The signed response.
     * @throws ExtendedCAServiceRequestException
     * @throws IllegalExtendedCAServiceRequestException
     */
    OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
        final String hsmErrorString = "HSM not functional";
        final String providerName = this.providerHandler.getProviderName();
        final long HSM_DOWN_ANSWER_TIME = 15000; 
        if ( providerName==null ) {
            synchronized(this) {
                try {
                    this.wait(HSM_DOWN_ANSWER_TIME); // Wait here to prevent the client repeat the request right away. Some CPU power might be needed to recover the HSM.
                } catch (InterruptedException e) {
                    throw new Error(e); //should never ever happen. The main thread should never be interrupted.
                }
            }
            throw new ExtendedCAServiceRequestException(hsmErrorString+". Waited "+HSM_DOWN_ANSWER_TIME/1000+" seconds to throw the exception");
        }
        final PrivateKey privKey;
        final X509Certificate entityCert;
        try {
            privKey = this.keyContainer.getKey();
            entityCert = this.keyContainer.getCertificate(); // must be after getKey
        } catch (ExtendedCAServiceRequestException e) {
            this.providerHandler.reload();
            throw e;
        } catch (Exception e) {
            this.providerHandler.reload();
            throw new ExtendedCAServiceRequestException(e);
        }
        if ( privKey==null ) {
            throw new ExtendedCAServiceRequestException(hsmErrorString);
        }
        try {
            return OCSPUtil.createOCSPCAServiceResponse(request, privKey, providerName, getCertificateChain(entityCert));
        } catch( ExtendedCAServiceRequestException e) {
            this.providerHandler.reload();
            throw e;
        } catch( IllegalExtendedCAServiceRequestException e ) {
            throw e;
        } catch( Throwable e ) {
            this.providerHandler.reload();
            final ExtendedCAServiceRequestException e1 = new ExtendedCAServiceRequestException(hsmErrorString);
            e1.initCause(e);
            throw e1;
        } finally {
            this.keyContainer.releaseKey();
        }
    }
    /**
     * Checks if the signer could be used.
     * @return True if OK.
     */
    boolean isOK() {
        try {
            return this.keyContainer.isOK();
        } catch (Exception e) {
            StandAloneSession.m_log.info("Exception thrown when accessing the private key: ", e);
            return false;
        }
    }
}