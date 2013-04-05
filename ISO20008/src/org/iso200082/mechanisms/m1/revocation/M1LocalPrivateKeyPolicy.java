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
import java.util.List;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.M1Scheme;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.ds.M1SignatureKey;
import org.iso200082.mechanisms.m1.parties.M1Verifier;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Local private key revocation, maintains state per verifier directly in 
 * this policy object.
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M1Verifier
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M1LocalPrivateKeyPolicy extends AbstractRevocationPolicy
{
  /** Local private key revocation list */
  private List<BigInteger> revocation_list;
  
  /** Scheme instance, required for revocation checking */
  protected M1Scheme scheme = null;
    
  /**
   * Ctor, initializes the revocation list
   */
  public M1LocalPrivateKeyPolicy()
  {
    this.revocation_list = new ArrayList<BigInteger>();
  }
  
  /**
   * Creates a new instance with the given scheme (used on duplication)
   * @param scheme The scheme to set
   */
  public M1LocalPrivateKeyPolicy(M1Scheme scheme)
  {
    this.scheme          = scheme;
    this.revocation_list = new ArrayList<BigInteger>();    
  }  
  
  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.LOCAL_PRIVATEKEY_REVOCATION;
  }
  
  @Override
  public boolean requestPrivateKeyRevocation(SignatureKey key)
  {
    if(!(key instanceof M1SignatureKey))
      return false;
    
    // assuming that the policy always grants such requests and revokes.
    revocation_list.add(((M1SignatureKey) key).getX());
    
    return true;
  }
  
  @Override
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig)
  {
    if(Util.isAnyNull(bsn, sig))
      return true;

    if(!(sig instanceof M1Signature))
      return false;
    
    M1Signature s = (M1Signature) sig;
        
    return 
      M1Protocol.isAuthorRevoked(bsn, s.getT4(), 
                                 revocation_list.toArray(
                                   new BigInteger[revocation_list.size()]), 
                                 scheme.getPublicKey(), scheme.getParameters());
  }
  
  @Override
  public RevocationPolicy anewIfLocal()
  {
    return new M1LocalPrivateKeyPolicy(scheme);
  }
  
  @Override
  public void setScheme(GroupSignatureScheme scheme)
  {
    this.scheme = (M1Scheme) scheme;
  }
  
}
