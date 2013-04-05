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

package org.iso200082.mechanisms.m1.parties;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Linker;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;

/**
 * Simple linking party. Tells whether two signatures were created by the same
 * author.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see Linker
 */
public class M1Linker implements Linker
{

  @Override
  public boolean isSameAuthor(Signature s1, Signature s2)
  {
    if(s1 == s2)
      return true;
    
    if(!(s1 instanceof M1Signature) ||
       !(s2 instanceof M1Signature))
      return false;
    
    M1Signature sig1 = (M1Signature) s1;
    M1Signature sig2 = (M1Signature) s2;
    
    return M1Protocol.isSameAuthor(sig1.getT4(), sig2.getT4());
  }

}
