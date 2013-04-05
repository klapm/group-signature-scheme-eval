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
 * Exception that is thrown on general scheme (library) errors, e.g. when
 * loading a scheme fails.
 * See {@link Exception} superclass for ctor information.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class SchemeException extends Exception
{
  private static final long serialVersionUID = -2754755990911993071L;

  /**
   * See {@link Exception}
   */
  public SchemeException()
  {
    super();
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   */
  public SchemeException(String message)
  {
    super(message);
  }

  /**
   * See {@link Exception}
   * @param cause The exception cause
   */
  public SchemeException(Throwable cause)
  {
    super(cause);
  }

  /**
   * See {@link Exception}
   * @param message The exception message
   * @param cause The exception cause
   */
  public SchemeException(String message, Throwable cause)
  {
    super(message, cause);
  }

}
