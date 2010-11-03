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

import org.ejbca.core.protocol.ocsp.CertStore;
import org.ejbca.core.protocol.ocsp.CertificateCacheFactory;


/** 
 * Servlet implementing server side of the Certificate Store.
 * For a detailed description see rfc4378.
 * 
 * @web.servlet name = "CertificateStore"
 *              display-name = "CertStoreServlet"
 *              description="Fetches certificates according to rfc4378"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/search.cgi"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreSessionLocal"
 *  type="Session"
 *  link="CertificateStoreSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *
 * @web.resource-ref
 *  name="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *  type="javax.sql.DataSource"
 *  auth="Container"
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public class CertStoreServlet extends CertStoreServletBase {
    public CertStoreServlet() {
        super( CertificateCacheFactory.getInstance(new CertStore()) );
    }
} // CertStoreServlet
