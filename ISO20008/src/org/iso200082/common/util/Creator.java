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

package org.iso200082.common.util;

/**
 * Simple builder for primitive implementation elements. Used in
 * {@link RecycleBin}.
 *
 * @param <O> The element to build
 * @param <P> The value type of the element
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Creator<O, P>
{
  /**
   * Creates an object of type O using the values given by 'values'.
   * 
   * @param values The element's components
   * 
   * @return A new (or recycled) element as set by the values
   */
  @SuppressWarnings("unchecked")
  public O create(P... values);
  
  /**
   * Sets the value(s) of 'obj' to those given in 'values'.
   * 
   * @param obj The object to alter
   * @param values The value(s) to set the object to
   * 
   * @return The modified object
   */
  @SuppressWarnings("unchecked")
  public O fromObject(O obj, P... values);
}
