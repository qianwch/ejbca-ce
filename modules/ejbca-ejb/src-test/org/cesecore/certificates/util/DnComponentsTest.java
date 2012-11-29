/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;

import java.util.Vector;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 * Tests the DnComponents class.
 * 
 * Based on EJBCA version: DnComponentsTest.java 10947 2010-12-22 09:48:10Z anatom
 * 
 * @version $Id$
 */
public class DnComponentsTest {

    @Test
    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects(true);
        assertEquals(28, s.length);
        int i = 0;
        assertEquals("street", s[i++]);
        assertEquals("pseudonym", s[i++]);
        assertEquals("telephonenumber", s[i++]);
        i++;
        assertEquals("businesscategory", s[i++]);
        assertEquals("postalcode", s[i++]);
        assertEquals("unstructuredaddress", s[i++]);
        assertEquals("unstructuredname", s[i++]);
        i += 3;
        assertEquals("dn", s[i++]);
        assertEquals("uid", s[i++]);
        assertEquals("cn", s[i++]);
        assertEquals("name", s[i++]);
        i += 6;
        assertEquals("t", s[i]);
        i += 6;
        assertEquals("c", s[i]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(28, s1.length);
        assertEquals("street", s1[27]);
        assertEquals("telephonenumber", s1[25]);
        assertEquals("businesscategory", s1[23]);
        assertEquals("postalcode", s1[22]);
        assertEquals("unstructuredaddress", s1[21]);
        assertEquals("unstructuredname", s1[20]);
        assertEquals("uid", s1[15]);
        assertEquals("cn", s1[14]);
        assertEquals("name", s1[13]);
        assertEquals("t", s1[6]);
        assertEquals("c", s1[0]);

        String[] s2 = DnComponents.getDnObjects(true);
        assertEquals(28, s2.length);
        assertEquals("businesscategory", s2[4]);
        assertEquals("postalcode", s2[5]);
        assertEquals("unstructuredaddress", s2[6]);
        assertEquals("unstructuredname", s2[7]);
        assertEquals("uid", s2[12]);
        assertEquals("cn", s2[13]);
        assertEquals("t", s2[21]);
        assertEquals("c", s2[27]);

    }

    @Test
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,SN=12345,NAME=name,C=se");
        final X509Name name = CertTools.stringToBcX509Name(dn);
        Vector oids = name.getOIDs();
        assertEquals(BCStyle.CN, oids.elementAt(0));
        assertEquals(BCStyle.NAME, oids.elementAt(1));
        assertEquals(BCStyle.SERIALNUMBER, oids.elementAt(2));
        assertEquals(BCStyle.C, oids.elementAt(3));
        // The reason it says SERIALNUMBER here instead of SN is that we have not installed the BC provider
        // CryptoProviderTools.installBCProvider();
        assertEquals("CN=oid,Name=name,SERIALNUMBER=12345,C=se", dn);

        String dn1 = CertTools.stringToBCDNString("SURNAME=Json,=fff,CN=oid,SN=12345,NAME=name,C=se");
        final X509Name name1 = CertTools.stringToBcX509Name(dn1);
        Vector oids1 = name1.getOIDs();
        assertEquals(BCStyle.CN, oids1.elementAt(0));
        assertEquals(BCStyle.NAME, oids1.elementAt(1));
        assertEquals(BCStyle.SERIALNUMBER, oids1.elementAt(2));
        assertEquals(BCStyle.SURNAME, oids1.elementAt(3));
        assertEquals(BCStyle.C, oids1.elementAt(4));
        assertEquals("CN=oid,Name=name,SERIALNUMBER=12345,SURNAME=Json,C=se", dn1);
    }

}
