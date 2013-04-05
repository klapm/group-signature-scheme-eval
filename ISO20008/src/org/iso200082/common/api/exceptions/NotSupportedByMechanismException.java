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


/**
 * Exception that is thrown when an action was requested that is not supported
 * by the mechanism used, e.g. opening in conjunction with a linking-only
 * mechanism.
 * See {@link Exception} superclass for ctor information.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class NotSupportedByMechanismException extends Exception
{

  private static final long serialVersionUID = -2153916358007607968L;

  /**
   * See {@link Exception}
   */
  public NotSupportedByMechanismException()
  {
    super();
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   */
  public NotSupportedByMechanismException(String message)
  {
    super(message);
  }

  /**
   * See {@link Exception}
   * @param cause The exception cause
   */
  public NotSupportedByMechanismException(Throwable cause)
  {
    super(cause);
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   * @param cause The exception cause
   */
  public NotSupportedByMechanismException(String message, Throwable cause)
  {
    super(message, cause);
  }

}
