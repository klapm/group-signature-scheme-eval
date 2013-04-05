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
 * Simple array-based pool of reusable objects.
 * 
 * Put adds to the pool until it's full. Get returns from the pool until it's
 * empty. In the latter case, a new object is created.
 *
 * @param <O> The element to recycle
 * @param <P> The primitive type
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class RecycleBin<O, P>
{
  /** The pool array */
  private O[] buffer = null;
  
  /** Current pool position */
  private int cursor = 0;
  
  /** Builder for the elements */
  private Creator<O, P> creator;
  
  /**
   * Ctor, initialized using a given buffer array and creator/builder.
   * It only does the pool management, the actual array is submitted from
   * outside.
   * 
   * @param buffer The pool array
   * @param creator The creator implementation
   */
  public RecycleBin(O[] buffer, Creator<O, P> creator)
  {
    this.buffer  = buffer;
    this.creator = creator;
  }
  
  /**
   * @param values The values to set the newly gotten element to
   * @return The object, preset with the given value(s)
   */
  @SuppressWarnings("unchecked")
  public O get(P... values)
  {
    if(cursor > 0) {
      return creator.fromObject(buffer[cursor--], values);
    }
    
    return creator.create(values);
  }
  
  /**
   * puts a given object into the pool of available ones
   * 
   * @param element The element to recycle
   */
  public void put(O element)
  {
    if(cursor < buffer.length - 1)
      buffer[++cursor] = element;
  }
  
}
