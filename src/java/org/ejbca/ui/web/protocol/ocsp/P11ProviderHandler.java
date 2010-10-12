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

package org.ejbca.ui.web.protocol.ocsp;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * P11 implementation. Reload the provider when {@link #reload()} is called.
 * 
 * @author primelars
 * @version  $Id$
 */
class P11ProviderHandler implements ProviderHandler {
    /**
     * 
     */
    private final StandAloneSession standAloneSession;
    /**
     * Provider name.
     */
    final private String name;
    /**
     * Set of all {@link PrivateKeyContainer} using this provider.
     */
    final Set<PrivateKeyContainer> sKeyContainer = new HashSet<PrivateKeyContainer>();
    /**
     * Creation of the provider.
     * @param standAloneSession TODO
     * @throws Exception
     */
    P11ProviderHandler(StandAloneSession standAloneSession) throws Exception {
        this.standAloneSession = standAloneSession;
        this.name = this.standAloneSession.slot.getProvider().getName();
    }
    /**
     * Get the keystore for the slot.
     * @param pwp the password for the slot
     * @return the keystore for the provider
     * @throws Exception
     */
    public KeyStore getKeyStore(PasswordProtection pwp) throws Exception {
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                                                                      this.standAloneSession.slot.getProvider(),
                                                                      pwp);
        final KeyStore keyStore = builder.getKeyStore();
        StandAloneSession.m_log.debug("Loading key from slot '"+this.standAloneSession.slot+"' using pin.");
        keyStore.load(null, null);
        return keyStore;
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#getProviderName()
     */
    public String getProviderName() {
        return this.standAloneSession.isNotReloadingP11Keys ? this.name : null;
    }
    /**
     * An object of this class reloads the provider in a separate thread.
     */
    private class Reloader implements Runnable {
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public void run() {
            String errorMessage ="";
            while ( true ) try {
                errorMessage = "";
                {
                    final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyContainer.iterator();
                    while ( i.hasNext() ) {
                        i.next().clear(); // clear all not useable old keys
                    }
                }
                P11ProviderHandler.this.standAloneSession.slot.reset();
                synchronized( this ) {
                    this.wait(10000); // wait 10 seconds to make system recover before trying again. all threads with ongoing operations has to stop
                }
                {
                    final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyContainer.iterator();
                    while ( i.hasNext() ) {
                        PrivateKeyContainer pkf = i.next();
                        errorMessage = pkf.toString();
                        StandAloneSession.m_log.debug("Trying to reload: "+errorMessage);
                        pkf.set(getKeyStore(P11ProviderHandler.this.standAloneSession.getP11Pwd(null)));
                        StandAloneSession.m_log.info("Reloaded: "+errorMessage);
                    }
                }
                P11ProviderHandler.this.standAloneSession.setNextKeyUpdate(new Date().getTime()); // since all keys are now reloaded we should wait an whole interval for next key update
                P11ProviderHandler.this.standAloneSession.isNotReloadingP11Keys = true;
                return;
            } catch ( Throwable t ) {
                StandAloneSession.m_log.debug("Failing to reload p11 keystore. "+errorMessage, t);
            }
        }
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#reload()
     */
    public synchronized void reload() {
        if ( this.standAloneSession.doNotStorePasswordsInMemory ) {
            StandAloneSession.m_log.info("Not possible to recover a lost HSM with no passowrd.");
            return;
        }
        if ( !this.standAloneSession.isNotReloadingP11Keys ) {
            return;
        }
        this.standAloneSession.isNotReloadingP11Keys = false;
        new Thread(new Reloader()).start();
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#addKeyContainer(org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer)
     */
    public void addKeyContainer(PrivateKeyContainer keyContainer) {
        this.sKeyContainer.add(keyContainer);
    }
}