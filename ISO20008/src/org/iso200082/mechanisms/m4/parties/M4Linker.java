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

package org.iso200082.mechanisms.m4.parties;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Linker;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;

/**
 * Party to link two signatures
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use
 * 
 * @see M4Signer
 * @see M4Scheme
 */
public class M4Linker
<
  P
>
implements Linker
{

  @Override
  @SuppressWarnings("unchecked")
  public boolean isSameAuthor(Signature s1, Signature s2)
  {
    if(s1 == s2)
      return true;
    
    if(!(s1 instanceof M4Signature) ||
       !(s2 instanceof M4Signature))
      return false;
    
    M4Signature<P> sig1 = (M4Signature<P>) s1;
    M4Signature<P> sig2 = (M4Signature<P>) s2;
    
    return M4Protocol.isSameAuthor(sig1, sig2);
  }

}
