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

package org.iso200082.mechanisms.m1.revocation;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.parties.M1Verifier;


/**
 * Represents the verifier-local blacklisting revocation scheme as discussed 
 * in 2.6 of the standard. 
 * 
 * @see M1Verifier
 * @see AbstractRevocationPolicy
 * @see RevocationPolicy
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M1LocalBlacklistingPolicy extends AbstractRevocationPolicy
{
  /**
   * Revocation state list, maps from a linking base (as string) to
   * a revoked T_4 element of the signature
   */
  // dirty string hack as byte[] comparisons only compare for the same instance
  private Map<BigInteger, List<BigInteger>> local_revocation_state = null;
  
  /**
   * Ctor, initializes the blacklist
   */
  public M1LocalBlacklistingPolicy()
  {
    local_revocation_state = new HashMap<BigInteger, List<BigInteger>>();
  }

  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.LOCAL_BLACKLIST_REVOCATION;
  }

  @Override
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig)
  {
    if(Util.isAnyNull(bsn, sig) || !(sig instanceof M1Signature))
      return false;
        
    if(!local_revocation_state.containsKey(bsn))
      return false;
    
    return local_revocation_state.get(bsn)
                                 .contains(((M1Signature) sig).getT4());
  }

  @Override
  public boolean requestBlacklistRevocation(BigInteger bsn, Signature sig)
  {
    if(Util.isAnyNull(bsn, sig) || !(sig instanceof M1Signature))
      return false;
    
    M1Signature s = (M1Signature) sig;
    
    // assuming that the policy always grants such requests and revokes.
    if(local_revocation_state.containsKey(bsn))
    {
      if(local_revocation_state.get(bsn).contains(s.getT4()))
        return true; // already in there.
    }
    else
      local_revocation_state.put(bsn, new ArrayList<BigInteger>());
    
    local_revocation_state.get(bsn).add(s.getT4());
    return true;
  }

  @Override
  public RevocationPolicy anewIfLocal()
  {
    return new M1LocalBlacklistingPolicy();
  }

}
