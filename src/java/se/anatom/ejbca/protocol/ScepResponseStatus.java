/**
 * $Header: /home/tomas/Dev/cvs2svn/ejbca-cvsbackup/ejbca/src/java/se/anatom/ejbca/protocol/ScepResponseStatus.java,v 1.1.2.1 2003-08-28 14:48:16 rebrabnoj Exp $
 * $Revision: 1.1.2.1 $
 * $Date: 2003-08-28 14:48:16 $
 *
 */
package se.anatom.ejbca.protocol;

import java.io.Serializable;

/**
 * Encapsulates the possible values for the status of a SCEP response.
 *
 * @author Jon Barber (jon.barber@acm.org)
 */

public class ScepResponseStatus implements Serializable {

    /**
     * Request granted
     */
    public static final ScepResponseStatus SUCCESS = new ScepResponseStatus(0);

    /**
     * Request rejected
     */
    public static final ScepResponseStatus FAILURE = new ScepResponseStatus(2);

    /**
     * Request pending for approval
     */
    public static final ScepResponseStatus PENDING = new ScepResponseStatus(3);

    /**
     * The value actually encoded into the response message as a pkiStatus attribute
     */
    private final int value;

    private ScepResponseStatus(int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a pkiStatus attribute
     * @return  the value to use
     */
    public String getValue() {
        return Integer.toString(value);
    }


    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ScepResponseStatus)) return false;

        final ScepResponseStatus scepResponseStatus = (ScepResponseStatus) o;

        if (value != scepResponseStatus.value) return false;

        return true;
    }

    public int hashCode() {
        return value;
    }
}
