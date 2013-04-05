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

package org.iso200082.common;


import java.math.BigInteger;

import org.iso200082.common.ecc.api.Element;


/**
 * Very basic Debug utility to provide for some debugging messages. Debugging
 * can be turned on/off by setting {@link Debug#DEBUG} to true/false.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Debug
{
  /**
   * Sets whether or not debug out is shown
   */
  public static final boolean DEBUG = true;
  
  /* (non-javadoc)
   * Simple categorization of typical anonymous group signature-related
   * processes:
   */
  /** Module label for join processes */
  public static final String JOIN   = "Join";
  
  /** Module label for sign processes */
  public static final String SIGN   = "Sign";

  /** Module label for verify processes */
  public static final String VERIFY = "Verify";

  /** Module label for issuing processes */
  public static final String ISSUE  = "Issue";
  
  /** Module label for setup/creation processes */
  public static final String CREATE = "Create";

  /** Module label for linking processes */
  public static final String LINK   = "Link";

  /** Module label for revocation processes */
  public static final String REVOKE = "Revoke";

  /** Module label for opening processes */
  public static final String OPEN   = "Open";
  
  /**
   * String formatting helper that left-justifies a string according to
   * some given padding-length.
   * 
   * @param str The string to format
   * @param pad The overall padding
   * 
   * @return The left-justified string (of length pad)
   */
  public static final String justifyLeft(String str, int pad)
  {
    return String.format("%1$-" + pad + "s", str);
  }
  
  /**
   * Prints a byte array in hexadecimal notation,
   * see {@link #out(String, byte[])}.
   * 
   * @param in The byte array to print
   */
  public static final void out(byte[] in)
  {
    out(null, in, 16);
  }

  /**
   * Prints a byte array in hexadecimal notation. Prepends a label if non-null.
   * 
   * @param label A label for the byte array
   * @param in The byte array to print
   */
  public static final void out(String label, byte[] in)
  {
    out(label, in, 16);
  }

  /**
   * Prints a byte array. Prepends a label if non-null.
   * 
   * @param label A label for the byte array
   * @param in The byte array to print
   * @param radix The base
   */
  public static final void out(String label, byte[] in, int radix)
  {
    Debug.out(label, new BigInteger(1, in), radix);
  }
  /**
   * Prints a {@link BigInteger} using a given base (radix).
   * 
   * @param number The {@link BigInteger} to print
   * @param radix The base
   */
  public static final void out(BigInteger number, int radix)
  {
    if(DEBUG) System.out.println(number.toString(radix));
  }

  /**
   * Prints a {@link BigInteger} with a prepended label string.
   * 
   * @param label The describing label
   * @param number The number to print
   */
  public static final void out(String label, BigInteger number)
  {
    out(label, number, 16);
  }  

  /**
   * Prints a {@link BigInteger} with a prepended label string, using
   * a given base (radix).
   * 
   * @param label The describing label
   * @param number The number to print
   * @param radix The base
   */
  public static final void out(String label, BigInteger number, int radix)
  {
    if(label == null)
      out(number.toString(radix));
    else
      out(label, number.toString(radix));
  }
  
  /**
   * Prints a given message
   * 
   * @param o The object to print
   */
  public static final void out(Object o)
  {
    if(DEBUG) System.out.println(o.toString());
  }

  /**
   * Convenience function to print intermediate protocol steps.
   * 
   * @param module The affected module, typically one of the module fields 
   * @param step The numeric step as labeled in the standard document
   * @param o The actual message
   */
  public static final void out(String module, int step, Object o)
  {
    if(DEBUG) System.out.println("[" + module + ", Step " + step + "] " + o);
  }
  
  /**
   * Prints a labeled object
   * 
   * @param label the label for the integer (variable name, ...)
   * @param o The object to print
   */
  public static final void out(String label, Object o)
  {
    if(DEBUG) System.out.println(label + ": " + o);
  }
  
  /**
   * Prints a labeled element, calls {@link Element#toString(int)}
   * 
   * @param label A label describing the string
   * @param element The non-jPBC element to print
   * @param radix The base
   */
  public static final void out(String label, Element<?, ?> element, int radix)
  {
    if(DEBUG) System.out.println(label + ": " + element.toString(radix));
  }

}
