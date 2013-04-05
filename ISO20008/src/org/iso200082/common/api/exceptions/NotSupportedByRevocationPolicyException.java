/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.common.api.exceptions;

import org.iso200082.common.api.revocation.RevocationPolicy;

/**
 * Exception that is thrown when, for example, blacklist revocation is
 * requested from a private key revocation implementation. 
 * See {@link Exception} superclass for ctor information.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see RevocationPolicy
 */
public class NotSupportedByRevocationPolicyException extends Exception
{
  private static final long serialVersionUID = 3320420156982399345L;

  /**
   * See {@link Exception}
   */
  public NotSupportedByRevocationPolicyException()
  {
    super();
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   */
  public NotSupportedByRevocationPolicyException(String message)
  {
    super(message);
  }

  /**
   * See {@link Exception}
   * @param cause The exception cause
   */
  public NotSupportedByRevocationPolicyException(Throwable cause)
  {
    super(cause);
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   * @param cause The exception cause
   */
  public NotSupportedByRevocationPolicyException(String message, Throwable cause)
  {
    super(message, cause);
  }

}
