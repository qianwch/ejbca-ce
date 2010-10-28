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

package org.ejbca.ui.web.protocol;

import javax.servlet.http.HttpServlet;

import org.ejbca.core.protocol.ocsp.ICertStore;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CertStoreServletBase extends HttpServlet {

    private final ICertStore certStore;
    /**
     * Sets the object to get certificates from.
     */
    CertStoreServletBase(ICertStore _certStore ) {
        this.certStore = _certStore;
    }
}
