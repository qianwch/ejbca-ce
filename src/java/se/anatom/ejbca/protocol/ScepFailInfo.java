/**
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/se/anatom/ejbca/protocol/ScepFailInfo.java,v 1.1.2.1 2003-08-28 14:48:16 rebrabnoj Exp $
 * $Revision: 1.1.2.1 $
 * $Date: 2003-08-28 14:48:16 $
 *
 */
package se.anatom.ejbca.protocol;

import java.io.Serializable;

/**
 * Encapsulates the possible values for the failinfo part of a SCEP FAILURE response.
 *
 * @author Jon Barber (jon.barber@acm.org)
 */

public class ScepFailInfo implements Serializable {

    /**
     * Unrecognized or unsupported algorithm ident
     */
    public static final ScepFailInfo BAD_ALGORITHM = new ScepFailInfo(0);

    /**
     * Integrity check failed
     */
    public static final ScepFailInfo BAD_MESSAGE_CHECK = new ScepFailInfo(1);

    /**
     * Transaction not permitted or supported
     */
    public static final ScepFailInfo BAD_REQUEST = new ScepFailInfo(2);


    /**
     * Message time field was not sufficiently close to the system time
     */
    public static final ScepFailInfo BAD_TIME = new ScepFailInfo(3);

    /**
     * No certificate could be identified matching the provided criteria
     */
    public static final ScepFailInfo BAD_CERTIFICATE_ID = new ScepFailInfo(4);
    /**
     * The value actually encoded into the response message as the failinfo attribute
     */
    private final int value;

    private ScepFailInfo(int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a failinfo attribute
     * @return  the value to use
     */
    public String getValue() {
        return Integer.toString(value);
    }


    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ScepFailInfo)) return false;

        final ScepFailInfo scepResponseStatus = (ScepFailInfo) o;

        if (value != scepResponseStatus.value) return false;

        return true;
    }

    public int hashCode() {
        return value;
    }
}
