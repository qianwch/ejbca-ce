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

import org.ejbca.core.protocol.certificatestore.CertStoreStandAlone;
import org.ejbca.core.protocol.crlstore.CRLStoreStandAlone;


/** 
 * Servlet implementing server side of the Certificate Store.
 * For a detailed description see rfc4378.
 * 
 * @web.servlet name = "CRLStore"
 *              display-name = "CRLStoreServletStandAlone"
 *              description="Fetches certificates according to rfc4378"
 *              load-on-startup = "1"
 *
 * @web.servlet-mapping url-pattern = "/search.cgi"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @web.ejb-local-ref
 *  name="ejb/OnlyDataCRLSessionLocal"
 *  type="Session"
 *  link="OnlyDataCRLSession"
 *  home="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.crl.IOnlyDataCRLSessionLocal"
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public class CRLStoreServletStandAlone extends CRLStoreServletBase {
	public CRLStoreServletStandAlone() {
		super( new CertStoreStandAlone(), new CRLStoreStandAlone() );
	}
} // CRLStoreServletStandAlone
