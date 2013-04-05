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

package org.iso200082.mechanisms.m4.revocation;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.parties.M4Verifier;


/**
 * Local blacklisting policy. Keeps a list of blacklisted signers and matches
 * against it on revocation checks.
 * 
 * @see M4Verifier
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4LocalBlacklistingPolicy
<
  P
>
extends AbstractRevocationPolicy
{
  /** maps from BSN to a list of K's for individual signatures */
  protected Map<BigInteger, List<Point<FqElement<P>, Fq<P>>>> revoked_ks;
  
  /**
   * Ctor, initializes the list
   */
  public M4LocalBlacklistingPolicy()
  {
    revoked_ks = new HashMap<BigInteger, List<Point<FqElement<P>, Fq<P>>>>();
  }

  @SuppressWarnings("unchecked")
  @Override
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig)
  {
    if(!(sig instanceof M4Signature))
      return false; // don't you mix these.
    
    if(!revoked_ks.containsKey(bsn))
      return false;
    
    return revoked_ks.get(bsn).contains(((M4Signature<P>) sig).getK()); 
  }

  @SuppressWarnings("unchecked")
  @Override
  public boolean requestBlacklistRevocation(BigInteger bsn, Signature sig)
  {
    if(!(sig instanceof M4Signature))
      return false; // don't you mix these.
    
    if(!revoked_ks.containsKey(bsn))
    {
      List<Point<FqElement<P>, Fq<P>>> bsnlist
        = new ArrayList<Point<FqElement<P>, Fq<P>>>();
      bsnlist.add(((M4Signature<P>) sig).getK());
      revoked_ks.put(bsn, bsnlist);
    } 
    else
    {
      if(!revoked_ks.get(bsn).contains(((M4Signature<P>) sig).getK()))
        revoked_ks.get(bsn).add(((M4Signature<P>) sig).getK());
      
      //otherwise already revoked
    }
    
    return true;
  }

  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.LOCAL_BLACKLIST_REVOCATION;
  }

  @Override
  public RevocationPolicy anewIfLocal()
  {
    return new M4LocalBlacklistingPolicy<P>();
  }

}
